#if os(macOS)
import Foundation
import GuardCore
import GuardPlatform
import os

/// Owns the HelperService and performs the privileged side effects its decisions call for.
/// Everything runs on `queue`.
final class HelperCore {
    let queue = DispatchQueue(label: "com.lsclpangpang.agentguard.helper")
    private var identities: [CallerRole: CodeIdentity]
    private let paths = AgentGuardConfig(home: "/var/empty", uid: -1, homebrewPrefix: "/opt/homebrew")
    private var owner: OwnerRecord?
    private var config: AgentGuardConfig?
    private var service: HelperService?
    private let collector = Collector()
    private let bundleMacOSDirectory: String
    private var started = false

    init(bundleMacOSDirectory: String) {
        self.bundleMacOSDirectory = bundleMacOSDirectory
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

    /// Re-pins the bundled binaries whenever a connection arrives.
    ///
    /// 每次都同步给 HelperService，而不是只在 cdhash 变化时同步：这个 daemon 会连续运行几天，
    /// 期间 App 可能被重编十几次；只要有一轮信任表没跟上，合法调用者就会被判成 not_trusted
    /// （现象是界面一切正常、只有改权限时静默失败）。`true` 表示 cdhash 确实变了。
    @discardableResult
    func refreshIdentitiesIfChanged() -> Bool {
        let fresh = Self.readIdentities(bundleMacOSDirectory: bundleMacOSDirectory)
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
        if case let .failed(reason) = CollectorInstaller.ensureInstalled(bundleMacOSDirectory: bundleMacOSDirectory) {
            FileHandle.standardError.write(Data("采集器安装失败：\(reason)\n".utf8))
        }
        collector.onLine = { [weak self] line in self?.queue.async { self?.service?.observe(line: line) } }
        collector.onDenial = { [weak self] denial in self?.queue.async { self?.service?.observe(denial: denial) } }
        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            guard let self else { return }
            let health = self.collector.health()
            self.queue.async {
                self.service?.updateCollectorHealth(health)
                self.service?.updateRunningProcesses(ProcessFacts.allProcesses())
                self.reconcileInstances()
            }
        }
        refreshCollector()
    }

    func handle(_ data: Data, identity: CallerIdentity, process: ProcessKey) -> Data {
        let response: HelperResponse
        if let request = try? HelperWire.decodeRequest(data) {
            claimOwnershipIfNeeded(identity)
            if let service {
                response = apply(service.handle(request, caller: identity, process: process), for: request)
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
        service = HelperService(
            store: config.store, environment: config.environment, catalog: TemplateCatalog(config.templates),
            trust: CallerTrustPolicy(allowedUID: record.uid, identities: identities),
            verifier: SystemAuthorizationVerifier(), settings: config.helperSettings,
            clock: Date.init, makeID: { UUID().uuidString.lowercased() },
            launcherGeneration: (try? CodeSigning.cdhash(atPath: config.helperSettings.launcherPath)).map { String($0.prefix(8)) } ?? "",
            managedLogDirectory: record.home + "/Library/Logs/AgentGuard"
        )
        service?.onAcknowledgeCollectorProblems = { [weak self] in
            guard let self else { return }
            self.collector.acknowledge()
            self.service?.updateCollectorHealth(self.collector.health())
        }
        if started { refreshCollector() }
        reconcileInstances()
    }

    /// 实例追踪表在内存里，Helper 一重启就空了，界面会把正在跑的受管对象误报成“已停止”。
    /// 注册时把 root 进程的 pid + 启动时刻落盘，重启后按这两项核对再装回追踪表。
    private struct InstanceRecord: Codable {
        var instance: Int
        var revision: Int
        var pid: Int32
        var startTime: UInt64
        /// 由启动器注册的实例受 launchd 看护；恢复时要把这个事实一起带回来，
        /// 否则重启 Helper 之后 detached 判定会静默消失。
        var supervisedByLaunchd: Bool

        /// 合成的 Decodable 不认属性默认值，老记录缺这个 key 会直接解码失败、恢复整个失效。
        init(instance: Int, revision: Int, pid: Int32, startTime: UInt64, supervisedByLaunchd: Bool) {
            self.instance = instance
            self.revision = revision
            self.pid = pid
            self.startTime = startTime
            self.supervisedByLaunchd = supervisedByLaunchd
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            instance = try c.decode(Int.self, forKey: .instance)
            revision = try c.decode(Int.self, forKey: .revision)
            pid = try c.decode(Int32.self, forKey: .pid)
            startTime = try c.decode(UInt64.self, forKey: .startTime)
            supervisedByLaunchd = try c.decodeIfPresent(Bool.self, forKey: .supervisedByLaunchd) ?? false
        }
    }

    private func instanceRecordPath(_ profileID: String) -> String? {
        config.map { $0.stateRoot + "/" + profileID + "/instance.json" }
    }

    private func recordInstance(profileID: String, instance: Int, revision: Int, root: ProcessKey) {
        guard let path = instanceRecordPath(profileID),
              let startTime = ProcessFacts.startTime(pid: root.pid) else { return }
        let snapshot = service?.instances(ofProfile: profileID).first { $0.id == instance }
        let record = InstanceRecord(instance: instance, revision: revision, pid: root.pid, startTime: startTime,
                                    supervisedByLaunchd: snapshot?.supervisedByLaunchd ?? false)
        try? JSONEncoder().encode(record).write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    func reconcileInstances() {
        guard let config, let service else { return }
        for profileID in ((try? config.store.profileIDs()) ?? []) {
            guard let path = instanceRecordPath(profileID),
                  let data = FileManager.default.contents(atPath: path),
                  let record = try? JSONDecoder().decode(InstanceRecord.self, from: data)
            else { continue }
            // 进程没了、或者 pid 被复用（启动时刻对不上）就当作已退出，别把陌生进程算进来。
            guard kill(record.pid, 0) == 0,
                  ProcessFacts.startTime(pid: record.pid) == record.startTime
            else { continue }
            // 恢复出来的进程用的是“pid + 启动时刻”，和 ES 事件里的 version 对不上，
            // 所以退出的判定也在这里做：进程真没了就把它从追踪表里摘掉。
            for instance in service.instances(ofProfile: profileID) {
                for process in instance.liveProcesses where kill(process.pid, 0) != 0 {
                    service.ingest(.exit(process))
                }
            }
            if service.instances(ofProfile: profileID).contains(where: { $0.isRunning }) { continue }
            service.restoreInstance(id: record.instance, profileID: profileID, revision: record.revision,
                                    root: ProcessKey(pid: record.pid, version: UInt32(truncatingIfNeeded: record.startTime)),
                                    supervisedByLaunchd: record.supervisedByLaunchd)
        }
    }

    // MARK: Side effects

    private func apply(_ response: HelperResponse, for request: HelperRequest) -> HelperResponse {
        guard let config, let owner else { return response }
        switch response {
        case .registered:
            if case let .registerInstance(profileID, _) = request { prepareStateDirectory(profileID, config: config, owner: owner) }
        case .applied:
            refreshCollector()
        case let .launchAgent(label, originalLabel, plist):
            guard case let .installLaunchAgent(profileID) = request else { return response }
            if !installLaunchAgent(label: label, profileID: profileID, originalLabel: originalLabel, plist: plist, config: config, owner: owner) {
                return .failure(code: "launchctl_failed")
            }
        case let .restartManaged(label, originalLabel, plist, pids):
            guard case let .restartManagedInstance(profileID) = request else { return response }
            // 沙箱规则是进程启动时装载的，旧进程不退，新修订就只是“存了但没生效”。
            for pid in pids { kill(pid, SIGTERM) }
            if !pids.isEmpty {
                let deadline = Date().addingTimeInterval(3)
                while Date() < deadline, pids.contains(where: { kill($0, 0) == 0 }) {
                    usleep(100_000)
                }
                for pid in pids where kill(pid, 0) == 0 { kill(pid, SIGKILL) }
            }
            if !installLaunchAgent(label: label, profileID: profileID, originalLabel: originalLabel, plist: plist, config: config, owner: owner) {
                return .failure(code: "launchctl_failed")
            }
        case let .deleted(profileID):
            // The profile is gone, so any of its managed LaunchAgents would only fail to start.
            removeStaleLaunchAgents(except: "", profileID: profileID, domain: "gui/\(owner.uid)")
            if let path = instanceRecordPath(profileID) { try? FileManager.default.removeItem(atPath: path) }
            refreshCollector()
        case let .removal(label, restoreOriginalLabel):
            guard case let .removeManagement(profileID, _, _) = request else { return response }
            removeLaunchAgent(label: label, profileID: profileID, restore: restoreOriginalLabel, config: config, owner: owner)
        default:
            break
        }
        return response
    }

    private func prepareStateDirectory(_ profileID: String, config: AgentGuardConfig, owner: OwnerRecord) {
        let base = config.stateRoot + "/" + profileID
        for directory in [base, base + "/tmp"] {
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try? FileManager.default.setAttributes([.posixPermissions: 0o700, .ownerAccountID: owner.uid], ofItemAtPath: directory)
        }
    }

    private func installLaunchAgent(label: String, profileID: String, originalLabel: String?, plist: Data, config: AgentGuardConfig, owner: OwnerRecord) -> Bool {
        let path = "/Library/LaunchAgents/\(label).plist"
        do {
            try plist.write(to: URL(fileURLWithPath: path), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o644, .ownerAccountID: 0, .groupOwnerAccountID: 0], ofItemAtPath: path)
        } catch {
            return false
        }
        let domain = "gui/\(owner.uid)"
        if let originalLabel {
            _ = Launchctl.run(["bootout", "\(domain)/\(originalLabel)"])
            for location in [owner.home + "/Library/LaunchAgents/\(originalLabel).plist", "/Library/LaunchAgents/\(originalLabel).plist"]
            where FileManager.default.fileExists(atPath: location) {
                let backup = config.configRoot + "/backups/\(originalLabel).plist"
                try? FileManager.default.removeItem(atPath: backup)
                try? FileManager.default.moveItem(atPath: location, toPath: backup)
                try? location.write(toFile: backup + ".location", atomically: true, encoding: .utf8)
            }
        }
        _ = Launchctl.run(["bootout", "\(domain)/\(label)"])
        // 换过 label（启动器重编 → 指纹变）之后，旧 plist 还留在 /Library/LaunchAgents 里，
        // 留着就是重复实例或永久失效的 EX_CONFIG 任务，这里顺手清干净。
        removeStaleLaunchAgents(except: label, profileID: profileID, domain: domain)
        return Launchctl.run(["bootstrap", domain, path]) == 0
    }

    private func removeStaleLaunchAgents(except keep: String, profileID: String, domain: String) {
        let base = AgentGuardConfig.labelPrefix + "." + profileID
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: "/Library/LaunchAgents") else { return }
        for entry in entries where entry.hasSuffix(".plist") {
            let label = String(entry.dropLast(6))
            // `<base>` or `<base>.<generation>`; a bare prefix match would also catch `knodo-work` for `knodo`.
            guard label == base || label.hasPrefix(base + "."), label != keep else { continue }
            _ = Launchctl.run(["bootout", "\(domain)/\(label)"])
            try? FileManager.default.removeItem(atPath: "/Library/LaunchAgents/\(entry)")
        }
    }

    private func removeLaunchAgent(label: String, profileID: String, restore originalLabel: String?, config: AgentGuardConfig, owner: OwnerRecord) {
        let domain = "gui/\(owner.uid)"
        _ = Launchctl.run(["bootout", "\(domain)/\(label)"])
        try? FileManager.default.removeItem(atPath: "/Library/LaunchAgents/\(label).plist")
        removeStaleLaunchAgents(except: "", profileID: profileID, domain: domain)
        guard let originalLabel else { return }
        let backup = config.configRoot + "/backups/\(originalLabel).plist"
        guard let location = try? String(contentsOfFile: backup + ".location", encoding: .utf8), FileManager.default.fileExists(atPath: backup) else { return }
        try? FileManager.default.moveItem(atPath: backup, toPath: location)
        try? FileManager.default.removeItem(atPath: backup + ".location")
        _ = Launchctl.run(["bootstrap", domain, location])
    }

    /// File events are only collected while some profile is learning; lifecycle events always.
    private func refreshCollector() {
        guard let config else {
            os_log("refreshCollector: 还没有 owner/config，跳过", log: .default, type: .error)
            return
        }
        let learning = ((try? config.store.profileIDs()) ?? []).contains { id in
            (try? config.store.latest(id))?.mode != .enforce
        }
        // 文件事件占采集流量的九成以上（实测 open+close ≈ 95%），只有学习模式需要它。
        // 用标记文件通知采集器，免得为了切订阅把守护进程整条重启。
        let flag = AgentGuardConfig.collectorFileEventsFlagPath
        if learning {
            if !FileManager.default.fileExists(atPath: flag) {
                FileManager.default.createFile(atPath: flag, contents: Data())
            }
        } else {
            try? FileManager.default.removeItem(atPath: flag)
        }
        collector.start(fileEvents: learning)
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
