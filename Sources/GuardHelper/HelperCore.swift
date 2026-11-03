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
            self.queue.async { self.service?.updateCollectorHealth(health) }
        }
        refreshCollector()
    }

    func handle(_ data: Data, identity: CallerIdentity, process: ProcessKey) -> Data {
        let response: HelperResponse
        if let request = try? HelperWire.decodeRequest(data) {
            claimOwnershipIfNeeded(identity)
            if let service {
                response = apply(service.handle(request, caller: identity, process: process), for: request)
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
        for directory in [config.configRoot, config.stateRoot, config.releasesRoot, config.logDirectory, config.configRoot + "/backups"] {
            try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        }
        self.config = config
        service = HelperService(
            store: config.store, environment: config.environment, catalog: TemplateCatalog(config.templates),
            trust: CallerTrustPolicy(allowedUID: record.uid, identities: identities),
            verifier: SystemAuthorizationVerifier(), settings: config.helperSettings,
            clock: Date.init, makeID: { UUID().uuidString.lowercased() }
        )
        service?.onAcknowledgeCollectorProblems = { [weak self] in
            guard let self else { return }
            self.collector.acknowledge()
            self.service?.updateCollectorHealth(self.collector.health())
        }
        if started { refreshCollector() }
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
            if !installLaunchAgent(label: label, originalLabel: originalLabel, plist: plist, config: config, owner: owner) {
                return .failure(code: "launchctl_failed")
            }
        case let .removal(label, restoreOriginalLabel):
            removeLaunchAgent(label: label, restore: restoreOriginalLabel, config: config, owner: owner)
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

    private func installLaunchAgent(label: String, originalLabel: String?, plist: Data, config: AgentGuardConfig, owner: OwnerRecord) -> Bool {
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
        return Launchctl.run(["bootstrap", domain, path]) == 0
    }

    private func removeLaunchAgent(label: String, restore originalLabel: String?, config: AgentGuardConfig, owner: OwnerRecord) {
        let domain = "gui/\(owner.uid)"
        _ = Launchctl.run(["bootout", "\(domain)/\(label)"])
        try? FileManager.default.removeItem(atPath: "/Library/LaunchAgents/\(label).plist")
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
