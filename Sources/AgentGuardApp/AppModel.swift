#if os(macOS)
import AppKit
import Foundation
import GuardCore
import GuardPlatform
import ServiceManagement

@MainActor
final class AppModel: ObservableObject {
    @Published var report: StatusReport?
    @Published var helperReachable = false
    @Published var lastError: String?
    @Published var pending: [String: [PendingItem]] = [:]
    @Published var revision = 0

    let config: AgentGuardConfig

    init() {
        let uid = getuid()
        config = AgentGuardConfig(home: UserAccount.home(uid: uid) ?? NSHomeDirectory(), uid: Int(uid), homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix())
    }

    var templates: [Template] { config.templates }

    var overall: OverallStatus {
        guard let report else { return OverallStatus(level: .problem, reasons: ["无法连接 Helper"]) }
        let objects = report.profiles.map { profile in
            ObjectStatus(profileID: profile.profileID,
                         protection: ProtectionState.derive(mode: profile.mode, observeUntil: nil, revision: profile.revisionState, capabilityPassed: true),
                         revision: profile.revisionState, pendingItems: profile.pendingCount, unmanagedInstances: 0)
        }
        let health = CollectorHealth(problems: report.collectorProblems.isEmpty ? [] : [.interrupted])
        return OverallStatus.evaluate(objects: objects, collector: health, capabilityCheckPassed: true)
    }

    func profile(_ id: String) -> Profile? {
        try? config.store.latest(id)
    }

    // MARK: Helper

    func refresh() {
        Task.detached {
            let status = try? HelperClient().send(.status)
            await MainActor.run {
                if case let .status(report) = status {
                    self.report = report
                    self.helperReachable = true
                } else {
                    self.report = nil
                    self.helperReachable = false
                }
                self.revision += 1
            }
            guard case let .status(report) = status else { return }
            for profile in report.profiles {
                let items = try? HelperClient().send(.pendingItems(profileID: profile.profileID))
                if case let .pendingItems(list) = items {
                    await MainActor.run { self.pending[profile.profileID] = list }
                }
            }
        }
    }

    func installHelper() {
        let service = SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName)
        do {
            try service.register()
        } catch {
            lastError = "安装 Helper 失败：\(error.localizedDescription)"
        }
        if service.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
        refresh()
    }

    // MARK: Changes

    /// Proposes `profile` as the next revision, shows the exact diff, and asks for system
    /// authentication when the change widens permissions.
    func submit(_ profile: Profile) {
        Task.detached {
            do {
                let client = HelperClient()
                let proposal = try client.send(.proposeChange(profile: profile))
                guard case let .pending(info) = proposal else { throw Self.failure(proposal) }
                if info.summary.isEmpty {
                    await MainActor.run { self.lastError = "没有变化" }
                    return
                }
                let confirmed = await MainActor.run { Self.confirm(title: "确认权限变更：\(profile.id)", lines: info.summary) }
                guard confirmed else { return }
                var token: Data?
                if info.requiresAuthorization {
                    token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forChange: info.id),
                                                         prompt: "AgentGuard 将为 \(profile.id) 扩大权限：\n" + info.summary.joined(separator: "\n"))
                }
                let result = try client.send(.approveChange(changeID: info.id, digest: info.digest, authorization: token))
                guard case .applied = result else { throw Self.failure(result) }
                await MainActor.run { self.lastError = nil }
            } catch {
                await MainActor.run { self.lastError = "\(error)" }
            }
            await MainActor.run { self.refresh() }
        }
    }

    func edit(_ id: String, _ change: (inout Profile) -> Void) {
        guard var profile = profile(id) else { return }
        change(&profile)
        profile.revision += 1
        submit(profile)
    }

    func createProfile(id: String, templateIDs: Set<String>) {
        guard ProfileID.isValid(id) else {
            lastError = HelperFailure.message(for: "invalid_profile")
            return
        }
        let refs = templates.filter { templateIDs.contains($0.id) }.map { TemplateRef(id: $0.id, version: $0.version) }
        submit(Profile(id: id, revision: 1, mode: .restrictedLearning, templates: refs, files: [], exec: [], network: NetworkPolicy()))
    }

    func addFolder(to id: String, access: Access) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var isDirectory: ObjCBool = false
        FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
        let sensitive = SensitivePaths(home: config.home).overlapsSensitive(url.path)
        edit(id) { $0.files.append(FileGrant(path: url.path, kind: isDirectory.boolValue ? .directory : .file, access: access, readsSecrets: sensitive)) }
    }

    func accept(_ item: PendingItem, for id: String) {
        edit(id) { profile in
            switch item.suggestion {
            case let .template(templateID):
                if let template = self.templates.first(where: { $0.id == templateID }) {
                    profile.templates.append(TemplateRef(id: template.id, version: template.version))
                }
            case let .file(path, kind, access):
                profile.files.append(FileGrant(path: path, kind: kind, access: access, readsSecrets: item.sensitive))
            case let .exec(path):
                profile.exec.append(ExecGrant(path: path))
            case let .loopbackPort(port):
                profile.network.loopbackTCPConnect.append(port)
            case .outboundTCP:
                profile.network.outboundTCP = .allowed
            case .listen:
                profile.network.listen = .allowed
            }
        }
    }

    func importKnodo() {
        let root = "/Library/KnodoRestricted"
        guard let allowlist = FileManager.default.contents(atPath: root + "/allowlist.json"),
              let policy = try? String(contentsOfFile: root + "/policy.sb", encoding: .utf8)
        else {
            lastError = "找不到 \(root) 下的 allowlist.json 或 policy.sb"
            return
        }
        do {
            var result = try LegacyImporter.importInstallation(profileID: "knodo", allowlistJSON: allowlist, policySBPL: policy)
            result.profile.launch = LaunchSettings(executable: root + "/entry.sh", arguments: [], workingDirectory: nil,
                                                   originalLabel: "com.knodo.restricted-agent", restartOnCleanExit: true)
            if !result.unimportedRules.isEmpty {
                _ = Self.confirm(title: "以下规则无法导入，请手动核对", lines: result.unimportedRules)
            }
            submit(result.profile)
        } catch {
            lastError = "导入失败：\(error)"
        }
    }

    func installLaunchAgent(_ id: String) {
        guard Self.confirm(title: "接管 \(id) 的启动项", lines: ["停止原启动项并备份", "以后由 AgentGuard 启动器在沙箱内启动"]) else { return }
        send(.installLaunchAgent(profileID: id))
    }

    func removeManagement(_ id: String, restoreOriginal: Bool) {
        let lines = restoreOriginal ? ["停止受管实例", "恢复原启动项：之后将无限制运行"] : ["停止受管实例并移除启动项", "不恢复原启动项"]
        guard Self.confirm(title: "移除 \(id) 的管控", lines: lines) else { return }
        Task.detached {
            do {
                let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forRemoval: id), prompt: "AgentGuard 将移除 \(id) 的管控")
                await self.sendAsync(.removeManagement(profileID: id, restoreOriginal: restoreOriginal, authorization: token))
            } catch {
                await MainActor.run { self.lastError = "\(error)" }
            }
        }
    }

    private func send(_ request: HelperRequest) {
        Task.detached { await self.sendAsync(request) }
    }

    nonisolated private func sendAsync(_ request: HelperRequest) async {
        do {
            let response = try HelperClient().send(request)
            if case .failure = response { throw Self.failure(response) }
            await MainActor.run { self.lastError = nil }
        } catch {
            await MainActor.run { self.lastError = "\(error)" }
        }
        await MainActor.run { self.refresh() }
    }

    nonisolated static func failure(_ response: HelperResponse) -> Error {
        if case let .failure(code) = response { return PlatformError.helper(HelperFailure.message(for: code)) }
        return PlatformError.helper("意外的响应")
    }

    static func confirm(title: String, lines: [String]) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = lines.joined(separator: "\n")
        alert.addButton(withTitle: "确认")
        alert.addButton(withTitle: "取消")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }
}
#endif
