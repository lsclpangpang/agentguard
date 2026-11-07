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
    @Published var lastWarning: String?
    /// Confirmed results of the last action, e.g. which processes a stop ended.
    @Published var lastNotice: String?
    /// Recent activity per profile, loaded when its activity tab is shown.
    @Published var activity: [String: ActivityLog] = [:]
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
    /// When the Helper last answered a status request. Older than `StatusFreshness.maxAge`, the
    /// report on screen may no longer describe the running programs.
    @Published var statusConfirmedAt: Date?
    /// Ticks on its own so "状态待确认" appears even while a status request hangs.
    @Published private(set) var clock = Date()
    private var pollTask: Task<Void, Never>?
    private var autoRefreshTask: Task<Void, Never>?
    private var clockTask: Task<Void, Never>?
    /// One registration repair per launch; see `repairStaleRegistrationIfNeeded`.
    private var didAttemptRegistrationRepair = false
    private var registrationRepairTask: Task<Void, Never>?
    private var manualInstallTask: Task<Void, Never>?
    var helperMaintenance = HelperMaintenance(enabled: !UserDefaults.standard.bool(forKey: "helperRemovedByUser"))
    @Published var uninstalling = false

    /// Stop both scheduled work and the effects of requests already in flight.
    func suspendHelperMaintenance() {
        helperMaintenance.suspend()
        UserDefaults.standard.set(true, forKey: "helperRemovedByUser")
        didAttemptRegistrationRepair = true
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
        clockTask?.cancel()
        clockTask = nil
        pollTask?.cancel()
        pollTask = nil
        registrationRepairTask?.cancel()
        registrationRepairTask = nil
        manualInstallTask?.cancel()
        manualInstallTask = nil
    }

    let config: AgentGuardConfig

    init() {
        let uid = getuid()
        config = AgentGuardConfig(home: UserAccount.home(uid: uid) ?? NSHomeDirectory(), uid: Int(uid), homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix())
    }

    var templates: [Template] { config.templates }

    var overall: OverallStatus {
        guard helperMaintenance.enabled else {
            return OverallStatus(level: .attention, reasons: [uninstalling ? "正在卸载后台组件" : "后台维护已暂停；需要恢复使用时请在设置中点“检查并修复”"])
        }
        // 失败时会保留上次的 report（避免详情页被拆掉重建），所以可达性要单独判断，
        // 否则菜单栏会一直显示上次的“均已生效”。
        guard helperReachable, let report else { return OverallStatus(level: .problem, reasons: ["无法连接 Helper"]) }
        let objects = report.profiles.map { profile in
            ObjectStatus(profileID: profile.profileID,
                         protection: ProtectionState.derive(mode: profile.mode, observeUntil: nil, revision: profile.revisionState),
                         revision: profile.revisionState, pendingItems: profile.pendingCount, unmanagedInstances: profile.unmanagedProcesses.count,
                         detachedInstances: profile.detachedInstances.count, untrackedInstances: profile.untrackedInstances.count)
        }
        let health = CollectorHealth(problems: report.collectorProblems.isEmpty ? [] : [.interrupted])
        let status = OverallStatus.evaluate(objects: objects, collector: health, freshness: freshness)
        guard helperOutdated else { return status }
        return OverallStatus(level: max(status.level, .attention), reasons: ["后台服务版本较旧，需要更新：在设置中点“检查并修复”"] + status.reasons)
    }

    /// The Helper answered but speaks an older protocol: the App was updated, the Helper was not.
    var helperOutdated: Bool {
        guard helperReachable, let report else { return false }
        return report.helperProtocol < HelperProtocol.version
    }

    var freshness: StatusFreshness { StatusFreshness.evaluate(confirmedAt: statusConfirmedAt, now: Date()) }

    func profile(_ id: String) -> Profile? {
        try? config.store.latest(id)
    }

    // MARK: Helper

    func refresh() {
        guard helperMaintenance.enabled else { return }
        startAutoRefresh()
        Task { _ = await refreshReport() }
    }

    /// Running programs change on their own, so the status is asked for again every few seconds
    /// rather than only after the user acts. Pending items are left to explicit refreshes.
    private func startAutoRefresh() {
        guard helperMaintenance.enabled, autoRefreshTask == nil else { return }
        autoRefreshTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled, let self, self.helperMaintenance.enabled else { return }
                _ = await self.refreshReport(timeout: 10, includePending: false)
            }
        }
        clockTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled, let self, self.helperMaintenance.enabled else { return }
                self.clock = Date()
            }
        }
    }

    /// Returns this request's snapshot, rather than the previous report cached by the UI.
    func refreshReport(timeout: TimeInterval = 60, includePending: Bool = true) async -> StatusReport? {
        let generation = helperMaintenance.generation
        guard helperMaintenance.accepts(generation), !Task.isCancelled else { return nil }
        let status = await Task.detached {
            try? HelperClient().send(.status, timeout: timeout)
        }.value
        guard helperMaintenance.accepts(generation), !Task.isCancelled else { return nil }
        if case let .status(report) = status {
            self.report = report
            helperReachable = true
            statusConfirmedAt = Date()
            if report.helperProtocol >= HelperProtocol.version { installNotice = nil }
        } else {
            // Preserve the last report during a failed query so the selected detail is not rebuilt.
            helperReachable = false
            repairStaleRegistrationIfNeeded()
        }
        revision += 1
        guard case let .status(report) = status else { return nil }
        guard includePending else { return report }
        // Pending-item retrieval must not delay a caller waiting for the actual status snapshot.
        Task.detached {
            for profile in report.profiles {
                guard await MainActor.run(body: { self.helperMaintenance.accepts(generation) }) else { return }
                let items = try? HelperClient().send(.pendingItems(profileID: profile.profileID))
                if case let .pendingItems(list) = items {
                    await MainActor.run {
                        if self.helperMaintenance.accepts(generation) { self.pending[profile.profileID] = list }
                    }
                }
            }
        }
        return report
    }

    func installHelper() {
        guard !uninstalling else { return }
        suspendHelperMaintenance()
        helperMaintenance.resume()
        UserDefaults.standard.set(false, forKey: "helperRemovedByUser")
        didAttemptRegistrationRepair = true
        let generation = helperMaintenance.generation
        manualInstallTask = Task { @MainActor in
            // Use a fresh response: a reachable Helper can still be an older installed binary.
            _ = await refreshReport(timeout: 5, includePending: false)
            guard !Task.isCancelled, helperMaintenance.accepts(generation) else { return }
            let service = SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName)
            let outdated = helperOutdated
            let error = await register(service, outdated: outdated)
            guard !Task.isCancelled, helperMaintenance.accepts(generation) else { return }
            present(error, service, openSettings: true)
            if outdated && error == nil && service.status == .enabled {
                helperReachable = false
                statusConfirmedAt = nil
                installNotice = "正在更新后台服务，等待新版本确认…"
            }
            manualInstallTask = nil
            pollUntilReachable()
        }
    }

    /// A registered daemon keeps the launch constraint recorded when it was registered, so an
    /// ad-hoc re-signed build leaves a job that launchd can never spawn. Registering again once per
    /// launch is what makes a rebuilt app work without a trip to System Settings.
    private func repairStaleRegistrationIfNeeded() {
        guard helperMaintenance.enabled, !didAttemptRegistrationRepair, registrationRepairTask == nil else { return }
        let service = SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName)
        guard HelperInstallRepair.action(status: Self.installStatus(service.status), reachable: helperReachable) != .none else {
            return
        }
        // 给刚启动的 Helper 一点时间：一次连接失败可能只是启动竞争，那样不该动 BTM。
        let generation = helperMaintenance.generation
        registrationRepairTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard !Task.isCancelled, helperMaintenance.accepts(generation) else { return }
            registrationRepairTask = nil
            guard !helperReachable else { return }
            didAttemptRegistrationRepair = true
            let error = await register(service)
            guard !Task.isCancelled, helperMaintenance.accepts(generation) else { return }
            present(error, service, openSettings: false)
            pollUntilReachable()
        }
    }

    /// Registers (or re-registers) the Helper and returns the classification of a refusal. smd
    /// refusing a pending item with EPERM is not a failure: the item is registered and waits for the
    /// user to allow it.
    private func register(_ service: SMAppService, outdated: Bool = false) async -> HelperRegisterError? {
        guard helperMaintenance.enabled else { return nil }
        let generation = helperMaintenance.generation
        switch HelperInstallRepair.action(status: Self.installStatus(service.status), reachable: helperReachable, outdated: outdated) {
        case .reregister:
            // The asynchronous variant completes only after the previous process is killed;
            // the synchronous unregister returns too early to safely re-register an update.
            do { try await service.unregister() }
            catch { return .other("移除旧后台服务失败：\(error.localizedDescription)") }
        case .register, .none:
            break
        }
        guard !Task.isCancelled, helperMaintenance.accepts(generation) else { return nil }
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
        if case let .other(message) = registerError {
            lastError = "后台服务修复失败：\(message)"
        }
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
                guard !Task.isCancelled, helperMaintenance.enabled else { return }
                _ = await refreshReport(timeout: 2, includePending: false)
                guard !Task.isCancelled, helperMaintenance.enabled else { return }
                if helperReachable && !helperOutdated { startAutoRefresh(); return }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            guard !Task.isCancelled, helperMaintenance.enabled else { return }
            installNotice = helperOutdated ? "后台服务仍是旧版本，更新尚未确认。请检查后台项目的系统授权后重试。"
                                          : "尚未连接到后台服务，请检查后台项目的系统授权。"
            startAutoRefresh()
        }
    }

    // MARK: Changes

    /// How one proposed change ended; callers that keep a form open use it to decide whether to close.
    enum SubmitOutcome: Equatable {
        case applied(revision: Int)
        case unchanged
        case cancelled
        case failed(String)
    }

    /// Proposes `profile` as the next revision, shows the exact diff, and asks for system
    /// authentication when the change widens permissions.
    /// `unchangedHint` replaces the bare "没有变化" when the caller knows why an edit may compile to the same policy.
    /// `warnings` are shown above the change itself, e.g. access that legacy rules will keep granting.
    func submit(_ profile: Profile, unchangedHint: String? = nil, warnings: [String] = []) {
        Task { _ = await submitAsync(profile, unchangedHint: unchangedHint, warnings: warnings) }
    }

    @discardableResult
    func submitAsync(_ profile: Profile, unchangedHint: String? = nil, warnings: [String] = []) async -> SubmitOutcome {
        let config = self.config
        let logger = Logger(subsystem: "com.lsclpangpang.agentguard", category: "ui")
        let proposal = await Task.detached { () -> Result<HelperResponse, Error> in
            Result { try HelperClient().send(.proposeChange(profile: profile)) }
        }.value
        let info: PendingChangeInfo
        switch proposal {
        case let .success(.pending(pending)):
            info = pending
        case let .success(response):
            return finish(.failed("\(Self.failure(response, diagnosis: Self.compileDiagnosis(for: profile, config: config)))"))
        case let .failure(error):
            return finish(.failed("\(error)"))
        }
        if info.summary.isEmpty {
            logger.debug("submit: 差异为空，标记没有变化")
            lastError = unchangedHint ?? "没有变化"
            return .unchanged
        }
        let legacyWarnings = self.profile(profile.id).map {
            LegacyRuleAnalysis.revocationWarnings(from: $0, to: profile, environment: config.environment)
        } ?? []
        guard await askConfirmation("确认权限变更：\(profile.id)", warnings + legacyWarnings + info.summary) else { return .cancelled }
        let result = await Task.detached { () -> Result<HelperResponse, Error> in
            Result {
                var token: Data?
                if info.requiresAuthorization {
                    token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forChange: info.id),
                                                         prompt: "AgentGuard 将为 \(profile.id) 扩大权限：\n" + info.summary.joined(separator: "\n"))
                }
                return try HelperClient().send(.approveChange(changeID: info.id, digest: info.digest, authorization: token))
            }
        }.value
        switch result {
        case let .success(.applied(revision)):
            lastError = nil
            refresh()
            return .applied(revision: revision)
        case let .success(response):
            return finish(.failed("\(Self.failure(response, diagnosis: Self.compileDiagnosis(for: profile, config: config)))"))
        case let .failure(error):
            return finish(.failed("\(error)"))
        }
    }

    private func finish(_ outcome: SubmitOutcome) -> SubmitOutcome {
        if case let .failed(message) = outcome {
            Logger(subsystem: "com.lsclpangpang.agentguard", category: "ui").error("submit: 失败 \(message, privacy: .public)")
            lastError = message
        }
        refresh()
        return outcome
    }

    func edit(_ id: String, unchangedHint: String? = nil, warnings: [String] = [], _ change: (inout Profile) -> Void) {
        guard var profile = profile(id) else { return }
        change(&profile)
        profile.revision += 1
        submit(profile, unchangedHint: unchangedHint, warnings: warnings)
    }

    /// A newly added parent directory makes narrower child grants redundant. Normalize at the
    /// user-edit boundary; callers that bypass this path and templates still go through the
    /// compiler's stricter nested read-only validation.
    func normalizedFileGrants(_ grants: [FileGrant]) -> [FileGrant] {
        (try? FileGrantMerger.normalize(grants, resolver: config.environment.resolver,
                                        caseInsensitive: config.environment.caseInsensitive)) ?? grants
    }

    /// Creates a profile and waits for the outcome, so the form that asked can stay open on failure.
    func createProfile(_ profile: Profile) async -> SubmitOutcome {
        guard ProfileID.isValid(profile.id) else {
            lastError = HelperFailure.message(for: "invalid_profile")
            return .failed(HelperFailure.message(for: "invalid_profile"))
        }
        return await submitAsync(profile)
    }

    /// Shows the file panel without checking the result; nil when the user cancels.
    func pickFile() async -> String? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = true
        panel.message = "选择要管控的可执行文件。按 ⌘⇧G 可以输入路径，例如 /opt/homebrew/bin/claude"
        guard let url = await Self.run(panel) else { return nil }
        return url.path
    }

    /// Presents a sheet when the host is available, otherwise an asynchronous standalone panel.
    /// Avoids a nested application-modal session while SwiftUI is presenting its own sheets.
    @MainActor static func run(_ panel: NSOpenPanel) async -> URL? {
        let host = NSApp.keyWindow
        if let host, host.sheetParent == nil, host.attachedSheet == nil {
            return await withCheckedContinuation { (continuation: CheckedContinuation<URL?, Never>) in
                panel.beginSheetModal(for: host) { response in
                    continuation.resume(returning: response == .OK ? panel.url : nil)
                }
            }
        }
        return await withCheckedContinuation { (continuation: CheckedContinuation<URL?, Never>) in
            panel.begin { response in
                continuation.resume(returning: response == .OK ? panel.url : nil)
            }
        }
    }

    /// Checks a program path and returns the real path to store, or the message to show.
    func validateProgram(_ path: String) -> Result<String, ProgramPathError> {
        ProgramPath.validate(path, home: config.home, probe: LocalProgramFileProbe())
    }

    /// Asks for an executable; nil when the user cancels or picks something that can't be managed.
    func chooseExecutable() async -> String? {
        guard let path = await pickFile() else { return nil }
        switch validateProgram(path) {
        case let .success(real): return real
        case let .failure(error):
            lastError = "\(path)：" + ProgramPath.message(for: error)
            return nil
        }
    }

    func removeProgram(_ path: String, from id: String) {
        edit(id) { profile in profile.programs.removeAll { $0 == path } }
    }

    func deleteProfile(_ id: String, restoreOriginal: Bool = false) {
        var lines = ["删除 \(id) 的全部权限设置；已批准的历史修订会归档保留", "之后 guard run \(id) 将无法启动"]
        // 在进 detached 任务之前先取好：profile(_:) 是 MainActor 隔离的，detached 里不能直接调。
        let originalLabel = profile(id)?.launch?.originalLabel
        if let launch = profile(id)?.launch {
            lines.append("移除 AgentGuard 为它安装的启动项")
            if let original = launch.originalLabel {
                lines.append(restoreOriginal ? "恢复原启动项 \(original)：之后将无限制运行" : "不恢复原启动项 \(original)")
            }
        }
        let running = status(for: id)?.runningInstances ?? []
        if !running.isEmpty { lines.insert("先停止正在运行的 \(running.count) 个副本（#\(running.map(String.init).joined(separator: "、#"))）", at: 0) }
        Task {
            guard await askConfirmation("移除 \(id) 的保护", lines) else { return }
            let restores = restoreOriginal && originalLabel != nil
            // Authorize first: cancelling the prompt must leave the program as it was, not stopped.
            let token = await Task.detached { () -> Result<Data?, Error> in
                Result {
                    let prompt = "AgentGuard 将删除配置档 \(id)" + (restores ? "，并恢复原启动项（之后将无限制运行）" : "")
                    return try UserAuthorization.obtain(scope: HelperService.authorizationScope(forDeletion: id, restoreOriginal: restores), prompt: prompt)
                }
            }.value
            guard case let .success(authorization) = token else {
                if case let .failure(error) = token { lastError = "\(error)" }
                return
            }
            if !running.isEmpty {
                guard await sendAsync(.stopManaged(profileID: id), refreshAfter: false) else { return }
                // Exits are settled within a moment; wait for the report to show it rather than racing it.
                let deadline = Date().addingTimeInterval(6)
                while Date() < deadline {
                    if let report = await refreshReport(includePending: false),
                       report.profiles.first(where: { $0.profileID == id })?.runningInstances.isEmpty ?? true { break }
                    try? await Task.sleep(nanoseconds: 500_000_000)
                }
                if !(status(for: id)?.runningInstances.isEmpty ?? true) {
                    lastError = "还有运行中的副本没有确认停止，没有删除。请稍后重试或手动结束它们。"
                    return
                }
            }
            await sendAsync(.deleteProfile(profileID: id, restoreOriginal: restoreOriginal, authorization: authorization))
        }
    }

    func addFolder(to id: String, access: Access) {
        Task {
            let panel = NSOpenPanel()
            panel.canChooseDirectories = true
            panel.canChooseFiles = true
            panel.allowsMultipleSelection = false
            panel.message = "选择要放行的目录或文件。按 ⌘⇧G 可以输入路径。"
            guard let url = await Self.run(panel) else { return }
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            let sensitive = SensitivePaths(home: config.home).overlapsSensitive(url.path)
            let grant = FileGrant(path: url.path, kind: isDirectory.boolValue ? .directory : .file,
                                  access: access, readsSecrets: sensitive)
            edit(id) { profile in profile.files = normalizedFileGrants(profile.files + [grant]) }
        }
    }

    func accept(_ item: PendingItem, for id: String) {
        edit(id) { profile in
            switch item.suggestion {
            case let .template(templateID):
                if let template = self.templates.first(where: { $0.id == templateID }) {
                    profile.templates.append(TemplateRef(id: template.id, version: template.version))
                }
            case let .file(path, kind, access):
                profile.files = normalizedFileGrants(profile.files + [FileGrant(path: path, kind: kind, access: access,
                                                                                readsSecrets: item.sensitive)])
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
            let preview = MigrationPreview.lines(for: result, templates: templates, environment: config.environment)
            Task {
                // Cancelling here stops the import; nothing has been changed yet.
                guard await askConfirmation("迁移现有 Knodo 沙箱", preview) else { return }
                submit(result.profile)
            }
        } catch {
            lastError = "导入失败：\(error)"
        }
    }

    /// 改完规则后旧进程还在按老沙箱跑，重启后新修订才算生效。
    func restartManaged(_ id: String) {
        launchManaged(id, restart: true)
    }

    private func launchManaged(_ id: String, restart: Bool) {
        Task {
            guard let launch = profile(id)?.launch else { return }
            var lines = ["按已保存的权限启动：" + LaunchArguments.format([launch.executable] + launch.arguments),
                         runAtLogin(id) ?? launch.runAtLogin ? "启用登录自启，后续登录也通过 AgentGuard 启动" : "仅在本次登录中启动，不添加登录自启"]
            if !(status(for: id)?.runningInstances.isEmpty ?? true) {
                lines.insert("结束 \(id) 当前运行的副本，正在进行的任务会被中断；重启后旧权限才会收回", at: 0)
            }
            if let original = launch.originalLabel, status(for: id)?.launchAgent?.canRestoreOriginal != true {
                lines.append("备份并替换原自启任务：\(original)")
            }
            guard await askConfirmation("\(restart ? "重启并应用" : "启动") \(id)", lines) else { return }
            restartingProfiles.insert(id)
            defer { restartingProfiles.remove(id) }
            guard await sendAsync(restart ? .restartManagedInstance(profileID: id) : .installLaunchAgent(profileID: id), refreshAfter: false) else {
                _ = await refreshReport()
                return
            }
            // 实例注册来自启动器连上 Helper，通常几百毫秒；最多等 12 秒再放弃提示。
            let deadline = Date().addingTimeInterval(12)
            while !Task.isCancelled {
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0, let snapshot = await refreshReport(timeout: remaining) else { break }
                let current = snapshot.profiles.first(where: { $0.profileID == id })
                if current?.revisionState == .applied(running: true) {
                    lastNotice = [lastNotice, restart ? "\(id) 已重启，当前修订已加载，已确认旧运行副本退出。可以重新尝试之前失败的操作。" : "\(id) 已启动，当前修订已加载。"]
                        .compactMap { $0 }.joined(separator: "\n")
                    break
                }
                if let current, !current.runningInstances.isEmpty,
                   current.revisionState == .verificationFailed || !current.verificationPending.isEmpty {
                    lastNotice = [lastNotice, "\(id) 已\(restart ? "重启" : "启动")，权限核验结果见下方。"]
                        .compactMap { $0 }.joined(separator: "\n")
                    break
                }
                do { try await Task.sleep(nanoseconds: 500_000_000) } catch { break }
            }
        }
    }

    func installLaunchAgent(_ id: String) {
        launchManaged(id, restart: false)
    }

    func removeManagement(_ id: String, restoreOriginal: Bool) {
        let lines = restoreOriginal ? ["停止此配置的受管程序，并取消 AgentGuard 的自启安排", "恢复备份的原启动方式，之后不再通过 AgentGuard 加载这份权限配置"] : ["停止此配置的受管程序，并取消登录自启", "保留权限和启动设置，以后可再次点“启动程序”", "保留原启动方式的备份，本次不恢复它"]
        Task {
            guard await askConfirmation(restoreOriginal ? "恢复 \(id) 的原启动方式" : "停止 \(id) 并取消自启", lines) else { return }
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

    @discardableResult
    nonisolated func sendAsync(_ request: HelperRequest, refreshAfter: Bool = true) async -> Bool {
        var succeeded = false
        do {
            let response = try HelperClient().send(request)
            if case .failure = response { throw Self.failure(response) }
            await MainActor.run {
                self.lastError = nil
                switch response {
                case let .completed(warnings):
                    self.lastWarning = warnings.joined(separator: "\n")
                    self.lastNotice = nil
                case let .report(report):
                    self.lastWarning = report.problems.isEmpty ? nil : report.problems.joined(separator: "\n")
                    self.lastNotice = report.notes.isEmpty ? nil : report.notes.joined(separator: "\n")
                default:
                    self.lastWarning = nil
                    self.lastNotice = nil
                }
            }
            succeeded = true
        } catch {
            await MainActor.run { self.lastError = "\(error)" }
        }
        if refreshAfter { await MainActor.run { self.refresh() } }
        return succeeded
    }

    nonisolated static func failure(_ response: HelperResponse, diagnosis: String? = nil) -> Error {
        if case let .failure(code) = response {
            if code == "compile_error", let diagnosis { return PlatformError.helper(diagnosis) }
            return PlatformError.helper(HelperFailure.message(for: code))
        }
        return PlatformError.helper("意外的响应")
    }

    /// Recovers the concrete reason for a refusal that the Helper can only report as `compile_error`.
    ///
    /// Every `CompileError` collapses to that one code before it leaves the Helper, so the grant
    /// path and the protected directory it collided with are lost. Recompiling the same revision
    /// here puts them back. No diagnosis is offered when this compile succeeds: that means the App
    /// and the Helper see the filesystem differently (the Helper runs as root), and a wrong reason
    /// would be worse than the generic one.
    nonisolated static func compileDiagnosis(for profile: Profile, config: AgentGuardConfig) -> String? {
        do {
            _ = try PolicyCompiler(environment: config.environment)
                .compile(profile, catalog: TemplateCatalog(config.templates))
            return nil
        } catch let error as CompileError {
            return "没有保存：\(error.message)"
        } catch {
            return nil
        }
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
