#if os(macOS)
import AppKit
import os
import Foundation
import GuardCore
import GuardPlatform
import ServiceManagement

/// 一次等待作答的确认，由窗口内的 sheet 呈现。
struct PendingConfirmation: Identifiable {
    let id = UUID()
    let title: String
    let lines: [String]
    let continuation: CheckedContinuation<Bool, Never>
}

@MainActor
final class AppModel: ObservableObject {
    @Published var report: StatusReport?
    @Published var helperReachable = false
    @Published var lastError: String?
    @Published var pending: [String: [PendingItem]] = [:]
    @Published var revision = 0
    /// Install progress shown in the Helper banner; cleared as soon as the Helper answers.
    @Published var installNotice: String?
    /// 正在重启的配置档。重启要 kill 旧进程再 bootstrap，几百毫秒到几秒不等；
    /// 没有这个状态时界面会一动不动，看上去像没点中。
    @Published var restartingProfiles: Set<String> = []
    /// 待确认的变更。用窗口内的 SwiftUI sheet 呈现：NSAlert 的 sheet 在菜单栏 App 上会挂到
    /// 看不见的窗口上，用户点不动、也关不掉，整个界面看起来就是“只有滚轮活着”。
    @Published var confirmation: PendingConfirmation?
    private var pollTask: Task<Void, Never>?
    /// One registration repair per launch; see `repairStaleRegistrationIfNeeded`.
    private var didAttemptRegistrationRepair = false
    private var registrationRepairTask: Task<Void, Never>?

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
                         revision: profile.revisionState, pendingItems: profile.pendingCount, unmanagedInstances: profile.unmanagedProcesses.count,
                         detachedInstances: profile.detachedInstances.count)
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
                    self.installNotice = nil
                } else {
                    self.report = nil
                    self.helperReachable = false
                    self.repairStaleRegistrationIfNeeded()
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
        // 用户手动触发，别再让自动修复重复登记。
        didAttemptRegistrationRepair = true
        present(register(service), service, openSettings: true)
        pollUntilReachable()
    }

    /// A registered daemon keeps the launch constraint recorded when it was registered, so an
    /// ad-hoc re-signed build leaves a job that launchd can never spawn. Registering again once per
    /// launch is what makes a rebuilt app work without a trip to System Settings.
    private func repairStaleRegistrationIfNeeded() {
        guard !didAttemptRegistrationRepair, registrationRepairTask == nil else { return }
        let service = SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName)
        guard HelperInstallRepair.action(status: Self.installStatus(service.status), reachable: helperReachable) != .none else {
            return
        }
        // 给刚启动的 Helper 一点时间：一次连接失败可能只是启动竞争，那样不该动 BTM。
        registrationRepairTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            registrationRepairTask = nil
            guard !helperReachable else { return }
            didAttemptRegistrationRepair = true
            present(register(service), service, openSettings: false)
            pollUntilReachable()
        }
    }

    /// Registers (or re-registers) the Helper and returns the classification of a refusal. smd
    /// refusing a pending item with EPERM is not a failure: the item is registered and waits for the
    /// user to allow it.
    private func register(_ service: SMAppService) -> HelperRegisterError? {
        switch HelperInstallRepair.action(status: Self.installStatus(service.status), reachable: helperReachable) {
        case .reregister:
            try? service.unregister()
        case .register, .none:
            break
        }
        switch Self.installStatus(service.status) {
        case .enabled, .requiresApproval:
            return nil
        case .notRegistered, .notFound:
            break
        }
        do {
            try service.register()
            return nil
        } catch let error as NSError {
            return HelperRegisterError.classify(domain: error.domain, code: error.code, description: error.localizedDescription)
        }
    }

    private func present(_ registerError: HelperRegisterError?, _ service: SMAppService, openSettings: Bool) {
        // 登记被拒且条目已经在登录项里：这是“被关掉了”，不是签名或 plist 的错误。
        if registerError == .notPermitted, Self.installStatus(service.status) != .requiresApproval {
            installNotice = HelperInstallRepair.appReregistrationGuide
            if openSettings { SMAppService.openSystemSettingsLoginItems() }
            return
        }
        let outcome = HelperInstallOutcome.evaluate(statusAfter: Self.installStatus(service.status), registerError: registerError)
        installNotice = outcome.error ?? outcome.notice
        if outcome.openLoginItems, openSettings { SMAppService.openSystemSettingsLoginItems() }
    }

    private static func installStatus(_ status: SMAppService.Status) -> HelperInstallStatus {
        switch status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        default: return .notRegistered
        }
    }

    /// Approval happens in System Settings, outside the app; keep checking for a while afterwards.
    private func pollUntilReachable() {
        pollTask?.cancel()
        pollTask = Task { @MainActor in
            for _ in 0..<30 {
                refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if helperReachable || Task.isCancelled { break }
            }
        }
    }

    // MARK: Changes

    /// Proposes `profile` as the next revision, shows the exact diff, and asks for system
    /// authentication when the change widens permissions.
    /// `unchangedHint` replaces the bare "没有变化" when the caller knows why an edit may compile to the same policy.
    func submit(_ profile: Profile, unchangedHint: String? = nil) {
        Task.detached {
            let logger = Logger(subsystem: "com.lsclpangpang.agentguard", category: "ui")
            do {
                let client = HelperClient()
                logger.debug("submit: 开始 propose \(profile.id, privacy: .public) rev\(profile.revision) mode=\(String(describing: profile.mode), privacy: .public)")
                let proposal = try client.send(.proposeChange(profile: profile))
                logger.debug("submit: propose 返回 \(String(describing: proposal).prefix(120), privacy: .public)")
                guard case let .pending(info) = proposal else { throw Self.failure(proposal) }
                if info.summary.isEmpty {
                    logger.debug("submit: 差异为空，标记没有变化")
                    await MainActor.run { self.lastError = unchangedHint ?? "没有变化" }
                    return
                }
                let confirmed = await self.askConfirmation("确认权限变更：\(profile.id)", info.summary)
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
                logger.error("submit: 失败 \(String(describing: error), privacy: .public)")
                await MainActor.run { self.lastError = "\(error)" }
            }
            await MainActor.run { self.refresh() }
        }
    }

    func edit(_ id: String, unchangedHint: String? = nil, _ change: (inout Profile) -> Void) {
        guard var profile = profile(id) else { return }
        change(&profile)
        profile.revision += 1
        submit(profile, unchangedHint: unchangedHint)
    }

    /// `program` is what the profile manages; `launch` is set only when it should run as a background item.
    func createProfile(id: String, templateIDs: Set<String>, program: String? = nil, launch: LaunchSettings? = nil) {
        guard ProfileID.isValid(id) else {
            lastError = HelperFailure.message(for: "invalid_profile")
            return
        }
        let refs = templates.filter { templateIDs.contains($0.id) }.map { TemplateRef(id: $0.id, version: $0.version) }
        submit(Profile(id: id, revision: 1, mode: .restrictedLearning, templates: refs, files: [], exec: [], network: NetworkPolicy(),
                       launch: launch, programs: program.map { [$0] } ?? []))
    }

    /// Asks for an executable; nil when the user cancels.
    func chooseExecutable() -> String? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = true
        panel.message = "选择要管控的可执行文件。按 ⌘⇧G 可以输入路径，例如 /opt/homebrew/bin/claude"
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: url.path)
        else {
            lastError = "\(url.path) 不是可执行文件。App 请选它包里 Contents/MacOS 下的程序。"
            return nil
        }
        return url.path
    }

    func addProgram(to id: String) {
        guard let path = chooseExecutable() else { return }
        edit(id) { profile in
            if !profile.programs.contains(path) { profile.programs.append(path) }
        }
    }

    func removeProgram(_ path: String, from id: String) {
        edit(id) { profile in profile.programs.removeAll { $0 == path } }
    }

    func deleteProfile(_ id: String, restoreOriginal: Bool = false) {
        var lines = ["删除配置档 \(id) 及其全部权限设置；已批准的历史修订会归档保留", "之后 guard run \(id) 将无法启动"]
        // 在进 detached 任务之前先取好：profile(_:) 是 MainActor 隔离的，detached 里不能直接调。
        let originalLabel = profile(id)?.launch?.originalLabel
        if let launch = profile(id)?.launch {
            lines.append("移除 AgentGuard 为它安装的启动项")
            if let original = launch.originalLabel {
                lines.append(restoreOriginal ? "恢复原启动项 \(original)：之后将无限制运行" : "不恢复原启动项 \(original)")
            }
        }
        Task {
            guard await askConfirmation("删除配置档 \(id)", lines) else { return }
            Task.detached {
                do {
                    let restores = restoreOriginal && originalLabel != nil
                    let prompt = "AgentGuard 将删除配置档 \(id)" + (restores ? "，并恢复原启动项（之后将无限制运行）" : "")
                    let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forDeletion: id, restoreOriginal: restores), prompt: prompt)
                    await self.sendAsync(.deleteProfile(profileID: id, restoreOriginal: restoreOriginal, authorization: token))
                } catch {
                    await MainActor.run { self.lastError = "\(error)" }
                }
            }
        }
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
            // entry.sh is a script, so the process to watch for is the daemon it starts.
            let daemon = root + "/release/knodo-agentd"
            if FileManager.default.isExecutableFile(atPath: daemon) { result.profile.programs = [daemon] }
            Task {
                if !result.unimportedRules.isEmpty {
                    _ = await askConfirmation("以下规则无法导入，请手动核对", result.unimportedRules)
                }
                submit(result.profile)
            }
        } catch {
            lastError = "导入失败：\(error)"
        }
    }

    /// 改完规则后旧进程还在按老沙箱跑，重启后新修订才算生效。
    func restartManaged(_ id: String) {
        Task {
            guard await askConfirmation("重启 \(id) 的受管实例", ["结束当前实例的进程", "按已保存的修订重新启动"]) else { return }
            restartingProfiles.insert(id)
            defer { restartingProfiles.remove(id) }
            await sendAsync(.restartManagedInstance(profileID: id))
            // 实例注册来自启动器连上 Helper，通常几百毫秒；最多等 12 秒再放弃提示。
            for _ in 0..<24 {
                if report?.profiles.first(where: { $0.profileID == id })?.runningInstances.isEmpty == false { break }
                try? await Task.sleep(nanoseconds: 500_000_000)
                refresh()
            }
        }
    }

    func installLaunchAgent(_ id: String) {
        Task {
            guard await askConfirmation("接管 \(id) 的启动项", ["停止原启动项并备份", "以后由 AgentGuard 启动器在沙箱内启动"]) else { return }
            send(.installLaunchAgent(profileID: id))
        }
    }

    func removeManagement(_ id: String, restoreOriginal: Bool) {
        let lines = restoreOriginal ? ["停止受管实例", "恢复原启动项：之后将无限制运行"] : ["停止受管实例并移除启动项", "不恢复原启动项"]
        Task {
            guard await askConfirmation("移除 \(id) 的管控", lines) else { return }
            removeManagementConfirmed(id, restoreOriginal: restoreOriginal)
        }
    }

    private func removeManagementConfirmed(_ id: String, restoreOriginal: Bool) {
        Task.detached {
            do {
                let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forRemoval: id), prompt: "AgentGuard 将移除 \(id) 的管控")
                await self.sendAsync(.removeManagement(profileID: id, restoreOriginal: restoreOriginal, authorization: token))
            } catch {
                await MainActor.run { self.lastError = "\(error)" }
            }
        }
    }

    func acknowledgeCollectorProblems() {
        send(.acknowledgeCollectorProblems)
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

    /// 弹出一个窗口内的确认 sheet，并等到用户作答。
    func askConfirmation(_ title: String, _ lines: [String]) async -> Bool {
        if let existing = confirmation {
            // 同一时刻只允许一个确认；已有的直接当作取消，避免请求悬挂。
            existing.continuation.resume(returning: false)
            confirmation = nil
        }
        Logger(subsystem: "com.lsclpangpang.agentguard", category: "ui").debug("显示确认 sheet：\(title, privacy: .public)")
        return await withCheckedContinuation { continuation in
            confirmation = PendingConfirmation(title: title, lines: lines, continuation: continuation)
        }
    }

    func answerConfirmation(_ approved: Bool) {
        guard let pending = confirmation else { return }
        confirmation = nil
        pending.continuation.resume(returning: approved)
    }
}
#endif
