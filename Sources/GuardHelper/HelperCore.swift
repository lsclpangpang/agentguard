#if os(macOS)
import Foundation
import GuardCore
import GuardPlatform
import os

/// Owns the HelperService and performs the privileged side effects its decisions call for.
/// Mutable service state runs on `queue`; slow startup-state inspection has its own worker.
final class HelperCore {
    let queue = DispatchQueue(label: "com.lsclpangpang.agentguard.helper")
    private var identities: [CallerRole: CodeIdentity]
    private let paths = AgentGuardConfig(home: "/var/empty", uid: -1, homebrewPrefix: "/opt/homebrew")
    private var owner: OwnerRecord?
    private var config: AgentGuardConfig?
    private var service: HelperService?
    private let collector = Collector()
    private let accessLogBudget = EventQueueBudget()
    private let helperSessionID = UUID().uuidString.lowercased()
    private var accessLogStore: AccessLogStore?
    private var accessLogRequestsInFlight = 0
    private var accessLogHealthPollInFlight = false
    private var accessLogDiagnostic = ""
    private var accessLogDiagnosticAt: Date?
    private var shuttingDown = false
    private let bundleMacOSDirectory: String
    private let helperRuntimeCodeHash: String?
    private var collectorInstallation: CollectorInstallationStatus?
    private var started = false
    private var processBirths: [ProcessKey: UInt64] = [:]
    private var launchStatusMonitor: LaunchStatusMonitor?
    private var operationWarnings: [String] = []
    /// What the current request's stop achieved; reported instead of a bare success.
    private var operationStop: StopOutcome?

    init(bundleMacOSDirectory: String, runtimeCodeHash: String? = nil) {
        self.bundleMacOSDirectory = bundleMacOSDirectory
        self.helperRuntimeCodeHash = runtimeCodeHash
        self.identities = Self.readIdentities(bundleMacOSDirectory: bundleMacOSDirectory)
        if let data = FileManager.default.contents(atPath: paths.ownerPath), let record = try? OwnerRecord.decode(data) {
            adopt(record)
        }
    }

    /// Reads the cdhash of every binary we are willing to trust. Called at startup and again
    /// whenever the bundle changed on disk: an installed app gets re-signed on every rebuild, and
    /// the running daemon must not need a restart to accept it.
    static func readIdentities(bundleMacOSDirectory: String) -> [CallerRole: CodeIdentity] {
        var identities: [CallerRole: CodeIdentity] = [:]
        for (role, name) in [(CallerRole.app, "AgentGuard"), (.cli, "guard"), (.launcher, "agentguard-launcher")] {
            if let hash = try? CodeSigning.cdhash(atPath: bundleMacOSDirectory + "/" + name) {
                identities[role] = CodeIdentity(signingIdentifier: AgentGuardConfig.signingIdentifier(role), teamIdentifier: nil, cdhashes: [hash])
            }
        }
        return identities
    }

    /// Re-pins the bundled binaries whenever a connection arrives. Must run on `queue`:
    /// requests read `identities` and the service's trust policy there.
    ///
    /// 每次都同步给 HelperService，而不是只在 cdhash 变化时同步：这个 daemon 会连续运行几天，
    /// 期间 App 可能被重编十几次；只要有一轮信任表没跟上，合法调用者就会被判成 not_trusted
    /// （现象是界面一切正常、只有改权限时静默失败）。`true` 表示 cdhash 确实变了。
    @discardableResult
    func refreshIdentitiesIfChanged() -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        let fresh = CallerTrustPolicy.refreshed(identities, with: Self.readIdentities(bundleMacOSDirectory: bundleMacOSDirectory))
        let changed = fresh != identities
        identities = fresh
        service?.updateIdentities(fresh)
        return changed
    }

    /// Only connections from our own bundle's binaries get past XPC.
    var codeSigningRequirement: String? {
        let hashes = identities.values.flatMap(\.cdhashes).sorted()
        return hashes.isEmpty ? nil : hashes.map { "cdhash H\"\($0)\"" }.joined(separator: " or ")
    }

    func start() {
        started = true
        // The collector daemon owns Full Disk Access; it is installed outside the app bundle so an
        // app rebuild (and the re-signing that follows) never invalidates that grant.
        let installation: CollectorInstallationStatus
        switch CollectorInstaller.ensureInstalled(bundleMacOSDirectory: bundleMacOSDirectory) {
        case .installed: installation = .installedBundled
        case .alreadyPresent: installation = .keptExisting
        case .wouldReplaceOutdated: installation = .keptOutdated
        case let .failed(reason):
            installation = .failed(reason: reason)
            FileHandle.standardError.write(Data("采集器安装失败：\(reason)\n".utf8))
        }
        queue.sync {
            collectorInstallation = installation
            service?.updateCollectorInstallation(installation)
        }
        collector.configureDelivery(on: queue, budget: accessLogBudget) { [weak self] batch in
            guard let self else { return }
            for input in batch {
                switch input {
                case let .es(line):
                    if let resolution = self.service?.resolveObservedProcess(line.process, startTime: line.processStartTime) {
                        if let previous = resolution.previousKey {
                            self.processBirths.removeValue(forKey: previous)
                            // Resolution requires this exact birth. Install it before exec's
                            // inheritance lookup, so even the first event can transition safely.
                            if let birth = line.processStartTime { self.processBirths[line.process] = birth }
                        }
                        var births: [(ProcessKey, UInt64?)] = [(line.process, line.processStartTime)]
                        if case let .fork(child) = line.kind {
                            if let related = self.service?.resolveObservedProcess(child,
                                startTime: line.relatedProcessStartTime, expectedInstance: resolution.instance),
                               let previous = related.previousKey {
                                self.processBirths.removeValue(forKey: previous)
                                if let birth = line.relatedProcessStartTime { self.processBirths[child] = birth }
                            }
                            births.append((child, line.relatedProcessStartTime))
                        }
                        if case let .exec(target, _) = line.kind {
                            let inherited = target.pid == line.process.pid ? self.processBirths[line.process] : nil
                            births.append((target, line.relatedProcessStartTime ?? inherited))
                        }
                        for (key, birth) in births where self.processBirths[key] == nil {
                            if let birth { self.processBirths[key] = birth }
                        }
                    }
                    self.service?.observe(line: line)
                    if case .exit = line.kind { self.processBirths.removeValue(forKey: line.process) }
                case let .denial(denial):
                    self.service?.observe(denial: denial)
                case let .gap(gap):
                    if gap.attributionIncomplete { self.service?.ingest(.gap) }
                    self.service?.recordAccessLogGap(
                        reason: gap.reasons.map(\.rawValue).sorted().joined(separator: ", "),
                        droppedCount: gap.possibleUnknownLoss ? nil : gap.droppedCount, at: gap.lastAt,
                        firstSequence: gap.firstSourceSequence, lastSequence: gap.lastSourceSequence,
                        from: gap.firstAt, through: gap.lastAt
                    )
                }
            }
            self.service?.updateAccessLogCoverage(fileEventsSubscribed: self.collector.coverageStatus().fileEventsSubscribed)
        }
        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            guard let self else { return }
            let health = self.collector.health()
            self.queue.async {
                self.service?.updateCollectorHealth(health)
                self.service?.updateAccessLogCoverage(fileEventsSubscribed: health.coverage.fileEventsSubscribed)
                self.refreshAccessLogDiagnostics()
                self.service?.updateRunningProcesses(ProcessFacts.allProcesses())
                self.reconcileInstances()
            }
        }
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.queue.async {
                self?.refreshLaunchStatus()
                self?.service?.verifyInstances()
            }
        }
        refreshCollector()
    }

    /// Trust and attribution are frozen on the state queue; bounded log reads run outside it.
    func handle(_ data: Data, identity: CallerIdentity, process: ProcessKey, reply: @escaping (Data) -> Void) {
        queue.async {
            guard !self.shuttingDown else {
                reply((try? HelperWire.encode(HelperResponse.failure(code: "helper_shutting_down"))) ?? Data())
                return
            }
            if let request = try? HelperWire.decodeRequest(data) {
                self.claimOwnershipIfNeeded(identity)
                switch request {
                case .accessLogStatus, .queryAccessLog, .exportAccessLogPage, .clearAccessLog:
                    // Admit before preparation: clear preparation fixes its cutoff immediately.
                    guard self.accessLogRequestsInFlight < 4 else {
                        reply((try? HelperWire.encode(HelperResponse.failure(code: "access_log_busy"))) ?? Data())
                        return
                    }
                default: break
                }
                if let work = self.service?.prepareAccessLogRequest(request, caller: identity, process: process) {
                    self.accessLogRequestsInFlight += 1
                    Task {
                        let response = await work()
                        self.queue.async {
                            self.accessLogRequestsInFlight -= 1
                            if case let .accessLogCleared(profileID, result) = response {
                                self.service?.completeAccessLogClear(profileID: profileID, result: result)
                            }
                            reply((try? HelperWire.encode(response)) ?? Data())
                        }
                    }
                    return
                }
            }
            reply(self.handle(data, identity: identity, process: process))
        }
    }

    /// A normal Helper stop seals and synchronizes its own logs; managed processes are untouched.
    func shutdown(completion: @escaping () -> Void) {
        queue.async {
            guard !self.shuttingDown else { return }
            self.shuttingDown = true
            self.collector.flushPendingForAccessLogClear()
            let store = self.accessLogStore
            Task {
                await store?.close()
                completion()
            }
        }
    }

    func handle(_ data: Data, identity: CallerIdentity, process: ProcessKey) -> Data {
        let response: HelperResponse
        if let request = try? HelperWire.decodeRequest(data) {
            claimOwnershipIfNeeded(identity)
            operationWarnings = []
            operationStop = nil
            defer {
                switch request {
                case .approveChange, .applyTightening, .installLaunchAgent, .restartManagedInstance, .removeManagement, .deleteProfile,
                     .stopManaged, .applyLoginSetting, .setRunAtLogin, .disableLaunchItem, .restoreLaunchItem, .uninstall:
                    refreshLaunchStatus(invalidate: true)
                default: break
                }
            }
            if let service {
                response = apply(service.handle(request, caller: identity, process: process), for: request)
                if case .setAccessLogEnabled = request { refreshCollector() }
                if case let .registerInstance(profileID, revision) = request,
                   case let .registered(instance, _) = response {
                    recordInstance(profileID: profileID, instance: instance, revision: revision, root: process)
                }
            } else {
                response = .failure(code: "not_trusted")
            }
        } else {
            response = .failure(code: "bad_request")
        }
        return (try? HelperWire.encode(response)) ?? Data()
    }

    // MARK: Ownership

    /// A failed disk cannot save its own error record. Keep a bounded, rate-limited system
    /// diagnostic as well; one outstanding poll prevents slow storage from growing a task queue.
    private func refreshAccessLogDiagnostics() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !shuttingDown, !accessLogHealthPollInFlight, let store = accessLogStore else { return }
        accessLogHealthPollInFlight = true
        Task {
            let status = await store.status()
            self.queue.async {
                self.accessLogHealthPollInFlight = false
                let message = String(status.errors.prefix(4).joined(separator: "; ").prefix(2048))
                guard !message.isEmpty else {
                    self.accessLogDiagnostic = ""
                    return
                }
                let now = Date()
                let interval: TimeInterval = message == self.accessLogDiagnostic ? 300 : 60
                guard self.accessLogDiagnosticAt.map({ now.timeIntervalSince($0) >= interval }) ?? true else { return }
                self.accessLogDiagnostic = message
                self.accessLogDiagnosticAt = now
                Logger(subsystem: "com.lsclpangpang.agentguard", category: "access-log")
                    .error("访问日志保存异常：\(message, privacy: .public)")
            }
        }
    }

    private func claimOwnershipIfNeeded(_ identity: CallerIdentity) {
        guard owner == nil, let app = identities[.app], identity.signingIdentifier == app.signingIdentifier,
              let hash = identity.cdhash?.lowercased(), app.cdhashes.contains(hash),
              let home = UserAccount.home(uid: uid_t(identity.uid))
        else { return }
        let record = OwnerRecord(uid: identity.uid, home: home)
        try? FileManager.default.createDirectory(atPath: paths.configRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        try? record.encode().write(to: URL(fileURLWithPath: paths.ownerPath), options: .atomic)
        adopt(record)
    }

    private func adopt(_ record: OwnerRecord) {
        owner = record
        let config = AgentGuardConfig(home: record.home, uid: record.uid, homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix())
        // 启动项的日志要在属主名下：launchd 用用户身份打开 StandardOutPath。
        let ownerLogDirectory = record.home + "/Library/Logs/AgentGuard"
        try? FileManager.default.createDirectory(atPath: ownerLogDirectory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755, .ownerAccountID: record.uid], ofItemAtPath: ownerLogDirectory)
        for directory in [config.configRoot, config.stateRoot, config.releasesRoot, config.logDirectory, config.configRoot + "/backups"] {
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        }
        self.config = config
        var accessLogInitializationError: String?
        if accessLogStore == nil {
            do {
                accessLogStore = AccessLogStore(
                    fileSystem: try ProtectedAccessLogFileSystem(root: config.configRoot + "/access-logs", ownerUID: 0),
                    scheduler: DispatchAccessLogScheduler(), clock: Date.init,
                    makeID: { UUID().uuidString.lowercased() }, writerID: helperSessionID,
                    budget: accessLogBudget, policy: .default
                )
            } catch {
                accessLogInitializationError = "访问日志目录暂时不可用：\(error.localizedDescription)"
                Logger(subsystem: "com.lsclpangpang.agentguard", category: "access-log")
                    .error("访问日志初始化失败：\(String(describing: error), privacy: .public)")
            }
        }
        let files = launchFiles(config: config, owner: record), domain = "gui/\(record.uid)"
        launchStatusMonitor = LaunchStatusMonitor { requests in
            LaunchItemController(files: files, domain: domain, fileOwner: 0).statuses(requests)
        }
        service = HelperService(
            store: config.store, environment: config.environment, catalog: TemplateCatalog(config.templates),
            trust: CallerTrustPolicy(allowedUID: record.uid, identities: identities),
            verifier: SystemAuthorizationVerifier(), settings: config.helperSettings,
            clock: Date.init, makeID: { UUID().uuidString.lowercased() },
            launcherGeneration: (try? CodeSigning.cdhash(atPath: config.helperSettings.launcherPath)).map { String($0.prefix(8)) } ?? "",
            managedLogDirectory: record.home + "/Library/Logs/AgentGuard",
            probe: SystemSandboxProbe(),
            activity: ActivityStore(root: config.configRoot, files: LocalFileStore()),
            accessLog: accessLogStore, accessLogInitializationError: accessLogInitializationError,
            helperSessionID: helperSessionID,
            helperRuntimeCodeHash: helperRuntimeCodeHash, collectorInstallation: collectorInstallation,
            checkedProcessBirth: { [weak self] process in
                // The bookkeeping can originate in collector events; require an independent OS
                // query of this exact process key each time it is used to confirm a checked PID.
                guard let expected = self?.processBirths[process],
                      let actual = ProcessFacts.startTime(pid: process.pid), expected == actual else { return nil }
                return actual
            }
        )
        service?.onAcknowledgeCollectorProblems = { [weak self] in
            guard let self else { return }
            self.collector.acknowledge()
            self.service?.updateCollectorHealth(self.collector.health())
        }
        service?.onAccessLogClearBoundary = { [weak self] in
            self?.collector.flushPendingForAccessLogClear()
        }
        service?.performProfileDeletion = { [weak self] id, originalLabel, archive in
            guard let self else { throw LaunchItemError.operationFailed }
            let plan = self.validatedTargets(id)
            let hasLaunch = (try config.store.latest(id))?.launch != nil
            let warnings = try self.launchController(config: config, owner: record).remove(profileID: id, restoreOriginal: originalLabel,
                                                                                          hasLaunchSettings: hasLaunch, deleting: true,
                                                                                          stop: { self.stop(plan, profileID: id) }, commit: archive)
            self.operationWarnings += warnings
        }
        if started { refreshCollector() }
        reconcileInstances()
        refreshLaunchStatus(invalidate: true)
    }

    /// 实例追踪表在内存里，Helper 一重启就空了，界面会把正在跑的受管对象误报成“已停止”。
    /// 注册时把 root 进程的 pid + 启动时刻落盘，重启后按这两项核对再装回追踪表。
    /// 记录放在配置目录下：每个配置档的状态目录在它自己的沙箱里可写，放在那里的记录可以被受管程序伪造。
    /// 以前写在状态目录里的 instance.json 不再读取。
    private var instanceRecords: InstanceRecordStore? {
        config.map { InstanceRecordStore(root: $0.configRoot, files: LocalFileStore()) }
    }

    private func recordInstance(profileID: String, instance: Int, revision: Int, root: ProcessKey) {
        guard let records = instanceRecords, let startTime = ProcessFacts.startTime(pid: root.pid) else { return }
        service?.updateInstanceIdentity(instance: instance, bootSessionID: ProcessFacts.bootSessionID, rootStartTime: startTime)
        let snapshot = service?.instances(ofProfile: profileID).first { $0.id == instance }
        processBirths[root] = startTime
        try? records.save(InstanceRecord(instance: instance, profileID: profileID, revision: revision, pid: root.pid, startTime: startTime,
                                         supervisedByLaunchd: snapshot?.supervisedByLaunchd ?? false, bootSessionID: ProcessFacts.bootSessionID,
                                         runUUID: snapshot?.runUUID, instanceOrigin: snapshot?.instanceOrigin))
    }

    func reconcileInstances() {
        guard let config, let service, let records = instanceRecords else { return }
        // 恢复出来的进程用的是“pid + 启动时刻”，和 ES 事件里的 version 对不上，
        // 所以退出的判定也在这里做：进程真没了就把它从追踪表里摘掉。
        for profileID in ((try? config.store.profileIDs()) ?? []) {
            for instance in service.instances(ofProfile: profileID) {
                for process in instance.liveProcesses {
                    let current = ProcessFacts.startTime(pid: process.pid)
                    if kill(process.pid, 0) != 0 {
                        service.ingest(.exit(process))
                        processBirths.removeValue(forKey: process)
                    } else if let expected = processBirths[process], let current {
                        if current != expected {
                            service.ingest(.gap)
                            service.ingest(.exit(process))
                            processBirths.removeValue(forKey: process)
                        }
                    } else {
                        // An unavailable identity is not evidence that the process exited.
                        service.ingest(.gap)
                    }
                }
            }
        }
        for var record in ((try? records.all()) ?? []) {
            // Only a reboot, or a completely observed exit of the whole tree, proves that no
            // descendants survive. A dead root alone cannot clear a restored instance's uncertainty.
            if record.isFromEarlierBoot(current: ProcessFacts.bootSessionID) {
                try? records.remove(profileID: record.profileID, instance: record.instance)
                continue
            }
            if record.bootSessionID == nil, let boot = ProcessFacts.bootSessionID {
                record.bootSessionID = boot
                try? records.save(record)
            }
            if let snapshot = service.instances(ofProfile: record.profileID).first(where: { $0.id == record.instance }) {
                if !snapshot.isRunning && !snapshot.trackingIncomplete {
                    try? records.remove(profileID: record.profileID, instance: record.instance)
                }
                continue
            }
            let root = ProcessKey(pid: record.pid, version: UInt32(truncatingIfNeeded: record.startTime))
            service.restoreInstance(id: record.instance, profileID: record.profileID, revision: record.revision, root: root,
                                    supervisedByLaunchd: record.supervisedByLaunchd, runUUID: record.runUUID,
                                    instanceOrigin: record.instanceOrigin, bootSessionID: record.bootSessionID,
                                    rootStartTime: record.startTime)
            if let snapshot = service.instances(ofProfile: record.profileID).first(where: { $0.id == record.instance }),
               record.runUUID != snapshot.runUUID || record.instanceOrigin != snapshot.instanceOrigin {
                record.runUUID = snapshot.runUUID
                record.instanceOrigin = snapshot.instanceOrigin
                try? records.save(record)
            }
            if ProcessFacts.startTime(pid: record.pid) == record.startTime {
                processBirths[root] = record.startTime
            } else {
                service.ingest(.exit(root))
            }
        }
        // A restored instance's forks were never observed; find the ones still running by parent PID
        // so a stop reaches them. Daemons that were reparented stay unknown, which the status says.
        for (key, birth) in service.adoptDescendants(of: ProcessFacts.allProcesses(), knownBirths: processBirths, birth: ProcessFacts.startTime) {
            processBirths[key] = birth
        }
    }

    // MARK: Side effects

    private func apply(_ response: HelperResponse, for request: HelperRequest) -> HelperResponse {
        guard let config, let owner else { return response }
        switch response {
        case var .status(report):
            for index in report.profiles.indices {
                let id = report.profiles[index].profileID
                report.profiles[index].launchAgent = launchStatusMonitor?.status(for: id)
            }
            return .status(report)
        case .registered:
            if case let .registerInstance(profileID, _) = request { prepareStateDirectory(profileID, config: config, owner: owner) }
        case .applied:
            refreshCollector()
        case let .launchAgent(label, originalLabel, plist):
            guard case let .installLaunchAgent(profileID) = request else { return response }
            do { try installLaunchAgent(label: label, profileID: profileID, originalLabel: originalLabel, plist: plist, config: config, owner: owner) }
            catch { return .failure(code: "startup_error:" + String(describing: error)) }
        case let .restartManaged(label, originalLabel, plist, pids):
            guard case let .restartManagedInstance(profileID) = request else { return response }
            _ = pids // Identity-checked targets are obtained before unloading the jobs below.
            do { try installLaunchAgent(label: label, profileID: profileID, originalLabel: originalLabel, plist: plist, config: config, owner: owner, restart: true) }
            catch { return .failure(code: "startup_error:" + String(describing: error)) }
        case let .deleted(profileID, _):
            // Known startup-file changes completed transactionally before archiving. Any skipped
            // cleanup is reported in operationWarnings rather than blocking unrelated deletion.
            // Archived, not removed: it may hold the agent's working files. A recreated profile with
            // the same name must not see the old contents (or the old instance record).
            try? instanceRecords?.removeAll(profileID: profileID)
            let state = config.stateRoot + "/" + profileID
            if FileManager.default.fileExists(atPath: state) {
                let archive = config.stateRoot + "/.deleted/" + profileID + "-" + UUID().uuidString.lowercased()
                try? FileManager.default.createDirectory(atPath: config.stateRoot + "/.deleted", withIntermediateDirectories: true,
                                                         attributes: [.posixPermissions: 0o700])
                try? FileManager.default.moveItem(atPath: state, toPath: archive)
            }
            refreshCollector()
        case let .removal(label, restoreOriginalLabel):
            guard case let .removeManagement(profileID, _, _) = request else { return response }
            do {
                try removeLaunchAgent(label: label, profileID: profileID, restore: restoreOriginalLabel, config: config, owner: owner)
            } catch {
                return .failure(code: "startup_error:" + String(describing: error))
            }
        case let .stopManaged(profileID):
            let plan = validatedTargets(profileID)
            do {
                operationWarnings += try launchController(config: config, owner: owner).stop(profileID: profileID) { self.stop(plan, profileID: profileID) }
                service?.recordHistory(profileID, .stopped, "停止本次运行", operationStop?.unconfirmed ?? [])
            } catch {
                return .failure(code: "startup_error:" + String(describing: error))
            }
        case let .relocateLaunchAgent(profileID, runAtLogin):
            do {
                let moved = try launchController(config: config, owner: owner).relocate(profileID: profileID, runAtLogin: runAtLogin)
                if !moved { operationWarnings.append(runAtLogin ? "还没有启用受控启动，登录自启会在下次启动程序时生效" : "没有需要调整的登录启动项") }
            } catch {
                return .failure(code: "startup_error:" + String(describing: error))
            }
        case let .disableLaunchItem(profileID, label, path):
            do {
                try launchController(config: config, owner: owner).disable(label: label, path: path, profileID: profileID)
                service?.recordHistory(profileID, .decision, "停用其他启动入口 \(label)", [path])
            }
            catch { return .failure(code: "startup_error:" + String(describing: error)) }
        case let .restoreLaunchItem(label):
            do { try launchController(config: config, owner: owner).restoreDisabled(label: label) }
            catch { return .failure(code: "startup_error:" + String(describing: error)) }
        case let .uninstall(targets):
            uninstall(targets, restoreDisabled: { if case let .uninstall(restore, _) = request { return restore } else { return false } }(),
                      config: config, owner: owner)
        default:
            break
        }
        if let stop = operationStop {
            switch request {
            case .installLaunchAgent, .restartManagedInstance:
                // Starting a program with no old process is not a "nothing to stop" action.
                return .report(OperationReport(stop: stop == StopOutcome() ? nil : stop, warnings: operationWarnings))
            default:
                return .report(OperationReport(stop: stop, warnings: operationWarnings))
            }
        }
        return operationWarnings.isEmpty ? response : .completed(warnings: operationWarnings)
    }

    /// Removes every profile's launch items and stops its programs, then the collector. Each profile
    /// is handled on its own, so one failure does not leave the rest half removed; what failed is reported.
    private func uninstall(_ targets: [UninstallTarget], restoreDisabled: Bool, config: AgentGuardConfig, owner: OwnerRecord) {
        let controller = launchController(config: config, owner: owner)
        for target in targets {
            let plan = validatedTargets(target.profileID)
            var stopped = false
            do {
                operationWarnings += try controller.remove(profileID: target.profileID, restoreOriginal: target.restoreOriginalLabel,
                                                           hasLaunchSettings: target.hasLaunchSettings) {
                    self.stop(plan, profileID: target.profileID)
                    stopped = true
                }
            } catch {
                operationWarnings.append("\(target.profileID)：未能移除启动项（\(error)），请在重新安装后处理")
                // The programs are stopped anyway: nothing would manage them once the Helper is gone.
                if !stopped { stop(plan, profileID: target.profileID) }
            }
        }
        if restoreDisabled {
            for item in controller.disabledItems() {
                do { try controller.restoreDisabled(label: item.label) }
                catch { operationWarnings.append("未能恢复被停用的启动项 \(item.label)（\(error)），备份保留在 \(controller.disabledDirectory)") }
            }
        } else if !controller.disabledItems().isEmpty {
            operationWarnings.append("被停用的其他启动项没有恢复，备份保留在 \(controller.disabledDirectory)")
        }
        operationWarnings += CollectorInstaller.uninstall()
        if operationStop == nil { operationStop = StopOutcome() }
    }

    private func prepareStateDirectory(_ profileID: String, config: AgentGuardConfig, owner: OwnerRecord) {
        let base = config.stateRoot + "/" + profileID
        for directory in [base, base + "/tmp"] {
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try? FileManager.default.setAttributes([.posixPermissions: 0o700, .ownerAccountID: owner.uid], ofItemAtPath: directory)
        }
    }

    private func launchFiles(config: AgentGuardConfig, owner: OwnerRecord) -> LaunchItemFiles {
        LaunchItemFiles(home: owner.home, configRoot: config.configRoot, launcherPath: config.launcherPath,
                        labelPrefix: AgentGuardConfig.labelPrefix)
    }

    private func launchController(config: AgentGuardConfig, owner: OwnerRecord) -> LaunchItemController {
        LaunchItemController(files: launchFiles(config: config, owner: owner), domain: "gui/\(owner.uid)", fileOwner: 0)
    }

    private func refreshLaunchStatus(invalidate: Bool = false) {
        guard let config, let monitor = launchStatusMonitor else { return }
        let requests = ((try? config.store.profileIDs()) ?? []).compactMap { id -> LaunchStatusRequest? in
            guard let profile = try? config.store.latest(id) else { return nil }
            return LaunchStatusRequest(id: id, launch: profile.launch)
        }
        monitor.refresh(requests, invalidate: invalidate)
    }

    /// Stops the identity-checked targets and records what actually exited, merged into this
    /// request's outcome (an uninstall stops several profiles).
    private func stop(_ plan: ProcessStopPlan, profileID: String) {
        let untrackedBefore = service?.instances(ofProfile: profileID).filter(\.trackingIncomplete).map(\.id) ?? []
        let targets = plan.targets
        func stillSame(_ pid: Int32) -> Bool { ProcessFacts.startTime(pid: pid) == targets[pid] }
        for pid in targets.keys where stillSame(pid) { kill(pid, SIGTERM) }
        var deadline = Date().addingTimeInterval(3)
        while Date() < deadline, targets.keys.contains(where: stillSame) { usleep(100_000) }
        let lingering = targets.keys.filter(stillSame)
        for pid in lingering { kill(pid, SIGKILL) }
        deadline = Date().addingTimeInterval(1)
        while Date() < deadline, lingering.contains(where: stillSame) { usleep(50_000) }
        let survivors = lingering.filter(stillSame)
        // Restored processes are keyed by birth time, so the collector's exit events never match
        // them; settle the tracker now, or the stopped instance still looks running (and untracked).
        reconcileInstances()
        var outcome = operationStop ?? StopOutcome()
        outcome.stopped += targets.keys.filter { !lingering.contains($0) }
        outcome.forced += lingering.filter { !survivors.contains($0) }
        outcome.survivors += survivors
        outcome.skipped += plan.skipped
        let untrackedAfter = service?.instances(ofProfile: profileID).filter(\.trackingIncomplete).map(\.id) ?? []
        outcome.untrackedInstances = Array(Set(outcome.untrackedInstances + untrackedBefore + untrackedAfter)).sorted()
        operationStop = outcome
    }

    private func validatedTargets(_ id: String) -> ProcessStopPlan {
        ProcessStopPlan(processes: service?.instances(ofProfile: id).flatMap({ $0.liveProcesses }) ?? [],
                        births: processBirths, currentBirth: ProcessFacts.startTime)
    }

    private func installLaunchAgent(label: String, profileID: String, originalLabel: String?, plist: Data,
                                    config: AgentGuardConfig, owner: OwnerRecord, restart: Bool = false) throws {
        guard let latest = try config.store.latest(profileID),
              let launch = LoginSettingStore(root: config.configRoot, files: LocalFileStore()).applied(to: latest).launch
        else { throw LaunchItemError.operationFailed }
        let plan = validatedTargets(profileID)
        let warnings = try launchController(config: config, owner: owner).install(profileID: profileID, launch: launch, label: label, plist: plist, restart: restart) {
            self.stop(plan, profileID: profileID)
        }
        operationWarnings += warnings
    }

    private func removeLaunchAgent(label: String, profileID: String, restore originalLabel: String?, config: AgentGuardConfig, owner: OwnerRecord) throws {
        let plan = validatedTargets(profileID)
        let warnings = try launchController(config: config, owner: owner).remove(profileID: profileID, restoreOriginal: originalLabel, stop: {
            self.stop(plan, profileID: profileID)
        })
        operationWarnings += warnings
    }

    /// File collection is independent of protection mode when access logging is enabled.
    private func refreshCollector() {
        guard let config else {
            os_log("refreshCollector: 还没有 owner/config，跳过", log: .default, type: .error)
            return
        }
        let fileEvents = ((try? config.store.profileIDs()) ?? []).contains { id in
            (try? config.store.latest(id))?.mode != .enforce || service?.accessLogEnabled(id) == true
        }
        let flag = AgentGuardConfig.collectorFileEventsFlagPath
        if fileEvents {
            if !FileManager.default.fileExists(atPath: flag) {
                FileManager.default.createFile(atPath: flag, contents: Data())
            }
        } else {
            try? FileManager.default.removeItem(atPath: flag)
        }
        collector.start(fileEvents: fileEvents)
    }
}

enum Launchctl {
    @discardableResult
    static func run(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus
        } catch {
            return -1
        }
    }
}
#endif
