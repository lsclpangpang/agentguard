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
    /// Install progress shown in the Helper banner; cleared as soon as the Helper answers.
    @Published var installNotice: String?
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
                         revision: profile.revisionState, pendingItems: profile.pendingCount, unmanagedInstances: 0,
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
                let confirmed = await Self.confirm(title: "确认权限变更：\(profile.id)", lines: info.summary)
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
            Task {
                if !result.unimportedRules.isEmpty {
                    _ = await Self.confirm(title: "以下规则无法导入，请手动核对", lines: result.unimportedRules)
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
            guard await Self.confirm(title: "重启 \(id) 的受管实例",
                                     lines: ["结束当前实例的进程", "按已保存的修订重新启动"]) else { return }
            send(.restartManagedInstance(profileID: id))
        }
    }

    func installLaunchAgent(_ id: String) {
        Task {
            guard await Self.confirm(title: "接管 \(id) 的启动项", lines: ["停止原启动项并备份", "以后由 AgentGuard 启动器在沙箱内启动"]) else { return }
            send(.installLaunchAgent(profileID: id))
        }
    }

    func removeManagement(_ id: String, restoreOriginal: Bool) {
        let lines = restoreOriginal ? ["停止受管实例", "恢复原启动项：之后将无限制运行"] : ["停止受管实例并移除启动项", "不恢复原启动项"]
        Task {
            guard await Self.confirm(title: "移除 \(id) 的管控", lines: lines) else { return }
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

    /// Confirms a change before it is applied. A Knodo import or a broad rule set produces hundreds
    /// of diff lines, so anything longer than a few lines goes into a fixed-size scrollable box
    /// instead of growing the alert until it covers the screen.
    /// It is a sheet on the main window: an app-modal alert floats free of the
    /// window, can end up behind it, and blocks scrolling and clicks in every window until answered.
    static func confirm(title: String, lines: [String]) async -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.addButton(withTitle: "确认")
        alert.addButton(withTitle: "取消")
        let text = lines.joined(separator: "\n")
        if text.count <= 480, lines.count <= 8 {
            alert.informativeText = text
        } else {
            alert.informativeText = "共 \(lines.count) 行变更，滚动查看全部内容。"
            alert.accessoryView = DiffTextView(text: text)
        }
        NSApp.activate(ignoringOtherApps: true)
        if let window = mainWindow {
            window.makeKeyAndOrderFront(nil)
            return await alert.beginSheetModal(for: window) == .alertFirstButtonReturn
        }
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// The SwiftUI `Window(id: "main")`; its NSWindow identifier starts with the scene id.
    private static var mainWindow: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.identifier?.rawValue.hasPrefix("main") == true }
    }
}

/// Read-only, word-wrapping, fixed-size text box for long change summaries.
private final class DiffTextView: NSScrollView {
    init(text: String) {
        let size = NSSize(width: 620, height: 360)
        super.init(frame: NSRect(origin: .zero, size: size))
        hasVerticalScroller = true
        hasHorizontalScroller = false
        autohidesScrollers = true
        borderType = .bezelBorder

        let textView = NSTextView(frame: NSRect(origin: .zero, size: size))
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = false
        textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.textContainerInset = NSSize(width: 6, height: 6)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.textContainer?.containerSize = NSSize(width: size.width, height: .greatestFiniteMagnitude)
        textView.string = text
        documentView = textView
        textView.scrollToBeginningOfDocument(nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("DiffTextView 只支持代码创建") }
}
#endif
