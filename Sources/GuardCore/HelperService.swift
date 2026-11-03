import Foundation
#if canImport(os)
import os
#endif

/// Verifies the system authorization the user granted for one specific change (Authorization Services on macOS).
public protocol AuthorizationVerifier: Sendable {
    /// True when `token` proves the user just authenticated for exactly `scope` (one change or one removal).
    func verify(token: Data?, scope: String, summary: [String]) -> Bool
}

public struct HelperSettings: Sendable {
    public var labelPrefix: String
    public var launcherPath: String
    public var logDirectory: String
    public var throttleInterval: Int

    public init(labelPrefix: String, launcherPath: String, logDirectory: String, throttleInterval: Int) {
        self.labelPrefix = labelPrefix
        self.launcherPath = launcherPath
        self.logDirectory = logDirectory
        self.throttleInterval = throttleInterval
    }
}

public enum HelperRequest: Codable, Equatable, Sendable {
    case status
    case proposeChange(profile: Profile)
    case approveChange(changeID: String, digest: String, authorization: Data?)
    case applyTightening(profile: Profile)
    case registerInstance(profileID: String, revision: Int)
    case reportVerification(instance: Int, passed: Bool)
    case installLaunchAgent(profileID: String)
    case pendingItems(profileID: String)
    case acknowledgeCollectorProblems
    case removeManagement(profileID: String, restoreOriginal: Bool, authorization: Data?)
    /// 重启受管实例：改完规则后旧进程还按老沙箱在跑，必须重启才会装载新规则。
    case restartManagedInstance(profileID: String)
    case deleteProfile(profileID: String, authorization: Data?)
}

public struct PendingChangeInfo: Codable, Equatable, Sendable {
    public var id: String
    public var digest: String
    public var summary: [String]
    public var requiresAuthorization: Bool
    public var baseRevision: Int
    public var expiresAt: Date

    public init(id: String, digest: String, summary: [String], requiresAuthorization: Bool, baseRevision: Int, expiresAt: Date) {
        self.id = id
        self.digest = digest
        self.summary = summary
        self.requiresAuthorization = requiresAuthorization
        self.baseRevision = baseRevision
        self.expiresAt = expiresAt
    }
}

public struct ProfileStatusReport: Codable, Equatable, Sendable {
    public var profileID: String
    public var savedRevision: Int
    public var mode: Mode
    public var revisionState: RevisionState
    public var runningInstances: [Int]
    public var pendingCount: Int
    /// Running instances whose launchd entry has exited; see `InstanceSnapshot.detachedFromLaunchd`.
    public var detachedInstances: [Int]
    /// PIDs running one of the profile's programs outside any managed instance, as of the last process scan.
    public var unmanagedProcesses: [Int32]

    public init(profileID: String, savedRevision: Int, mode: Mode, revisionState: RevisionState, runningInstances: [Int], pendingCount: Int,
                detachedInstances: [Int] = [], unmanagedProcesses: [Int32] = []) {
        self.profileID = profileID
        self.savedRevision = savedRevision
        self.mode = mode
        self.revisionState = revisionState
        self.runningInstances = runningInstances
        self.pendingCount = pendingCount
        self.detachedInstances = detachedInstances
        self.unmanagedProcesses = unmanagedProcesses
    }

    enum CodingKeys: String, CodingKey {
        case profileID, savedRevision, mode, revisionState, runningInstances, pendingCount, detachedInstances, unmanagedProcesses
    }

    /// The app and the helper are updated separately; a report from an older helper has no `detachedInstances`.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        profileID = try c.decode(String.self, forKey: .profileID)
        savedRevision = try c.decode(Int.self, forKey: .savedRevision)
        mode = try c.decode(Mode.self, forKey: .mode)
        revisionState = try c.decode(RevisionState.self, forKey: .revisionState)
        runningInstances = try c.decode([Int].self, forKey: .runningInstances)
        pendingCount = try c.decode(Int.self, forKey: .pendingCount)
        detachedInstances = try c.decodeIfPresent([Int].self, forKey: .detachedInstances) ?? []
        unmanagedProcesses = try c.decodeIfPresent([Int32].self, forKey: .unmanagedProcesses) ?? []
    }
}

public struct StatusReport: Codable, Equatable, Sendable {
    public var profiles: [ProfileStatusReport]
    /// Empty only while the collector is healthy; an empty list never means "nothing happened".
    public var collectorProblems: [String]

    public init(profiles: [ProfileStatusReport], collectorProblems: [String]) {
        self.profiles = profiles
        self.collectorProblems = collectorProblems
    }
}

public enum HelperResponse: Codable, Equatable, Sendable {
    case status(StatusReport)
    case pending(PendingChangeInfo)
    case applied(revision: Int)
    case registered(instance: Int, sbpl: String)
    /// The platform layer writes `plist` as a root-owned LaunchAgent and boots out `originalLabel`.
    case launchAgent(label: String, originalLabel: String?, plist: Data)
    /// The platform layer removes `label`; it restores the original item only when `restoreOriginalLabel` is set.
    case removal(label: String, restoreOriginalLabel: String?)
    case pendingItems([PendingItem])
    /// 平台层先结束 `pids` 里的进程，再用 `plist` 重新注册 `label`。
    case restartManaged(label: String, originalLabel: String?, plist: Data, pids: [Int32])
    /// The profile was archived; the platform layer removes its managed LaunchAgents and state.
    case deleted(profileID: String)
    case ok
    case failure(code: String)
}

public enum HelperWire {
    static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys]
        return e
    }

    static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    public static func encode(_ request: HelperRequest) throws -> Data { try encoder().encode(request) }
    public static func encode(_ response: HelperResponse) throws -> Data { try encoder().encode(response) }
    public static func decodeRequest(_ data: Data) throws -> HelperRequest { try decoder().decode(HelperRequest.self, from: data) }
    public static func decodeResponse(_ data: Data) throws -> HelperResponse { try decoder().decode(HelperResponse.self, from: data) }
}

/// Platform-independent core of the privileged Helper. The XPC layer only supplies the caller's
/// code identity and audit-token process key; every decision is made here.
public final class HelperService {
    private let store: ProfileStore
    private let compiler: PolicyCompiler
    private let renderer: SBPLRenderer
    private let catalog: TemplateCatalog
    private var trust: CallerTrustPolicy
    private let verifier: any AuthorizationVerifier
    private let settings: HelperSettings
    /// 启动器 cdhash 的短指纹；由 Helper 在启动时算好传进来（GuardCore 不依赖 CodeSigning）。
    private let launcherGeneration: String
    /// 受管启动项的日志目录。必须落在属主可写的位置：launchd 以用户身份打开
    /// StandardOutPath，指向 root 专属的 /Library/Logs 会让 spawn 直接 EX_CONFIG(78)。
    private let managedLogDirectory: String
    private let clock: () -> Date
    private var ledger: ApprovalLedger
    private var tracker = InstanceTracker()
    private var proposals: [String: (profile: Profile, info: PendingChangeInfo)] = [:]
    private var verified: [Int: Bool] = [:]
    private var nextInstance = 1
    private var observations: [String: [Observation]] = [:]
    private var collectorHealth = CollectorHealth(problems: [.notStarted])
    private var runningProcesses: [RunningProcess] = []
    private let environment: CompileEnvironment
    private static let observationLimit = 5000
    /// Set by the platform layer, which owns the collector's health monitor.
    public var onAcknowledgeCollectorProblems: (() -> Void)?

    public init(store: ProfileStore, environment: CompileEnvironment, catalog: TemplateCatalog, trust: CallerTrustPolicy,
                verifier: any AuthorizationVerifier, settings: HelperSettings, clock: @escaping () -> Date, makeID: @escaping () -> String,
                launcherGeneration: String = "", managedLogDirectory: String = "") {
        self.store = store
        self.environment = environment
        self.compiler = PolicyCompiler(environment: environment)
        self.renderer = SBPLRenderer(environment: environment)
        self.catalog = catalog
        self.trust = trust
        self.verifier = verifier
        self.settings = settings
        self.launcherGeneration = launcherGeneration
        self.managedLogDirectory = managedLogDirectory
        self.clock = clock
        self.ledger = ApprovalLedger(trust: trust, makeID: makeID)
    }

    /// Feeds process lifecycle events from the collector.
    /// The bundled binaries are re-read from disk when they change, so a rebuilt — and therefore
    /// re-signed — app keeps working without restarting this root daemon.
    /// Puts an instance that survived a Helper restart back into the tracker; without this the UI
    /// reports a running managed agent as "已停止" until it is restarted.
    public func instances(ofProfile profileID: String) -> [InstanceSnapshot] {
        tracker.instances(ofProfile: profileID)
    }

    public func restoreInstance(id: Int, profileID: String, revision: Int, root: ProcessKey, supervisedByLaunchd: Bool) {
        tracker.register(instance: id, profileID: profileID, revision: revision, root: root, supervisedByLaunchd: supervisedByLaunchd)
    }

    public func updateIdentities(_ identities: [CallerRole: CodeIdentity]) {
        trust.identities = identities
    }

    public func ingest(_ event: ProcessEvent) {
        tracker.handle(event)
    }

    public func managedInstance(of process: ProcessKey) -> Int? {
        tracker.owner(of: process)
    }

    /// The latest scan of running processes, used to report programs started outside AgentGuard.
    public func updateRunningProcesses(_ processes: [RunningProcess]) {
        runningProcesses = processes
    }

    public func updateCollectorHealth(_ health: CollectorHealth) {
        collectorHealth = health
    }

    /// One eslogger event: lifecycle goes to the tracker, accesses of managed processes are recorded.
    public func observe(line: ESLine) {
        let instance = tracker.owner(of: line.process)
        if let event = line.processEvent { tracker.handle(event) }
        guard let instance else { return }
        for access in line.observedAccesses { record(Observation(instance: instance, access: access, denied: false), instance: instance) }
    }

    /// One sandbox denial from the unified log; only denials of managed processes are kept.
    public func observe(denial: SandboxDenial) {
        guard let access = denial.access, let instance = tracker.owner(ofPID: denial.pid) else { return }
        record(Observation(instance: instance, access: access, denied: true), instance: instance)
    }

    private func record(_ observation: Observation, instance: Int) {
        guard let profileID = tracker.snapshot(of: instance)?.profileID else { return }
        var list = observations[profileID, default: []]
        list.append(observation)
        if list.count > Self.observationLimit { list.removeFirst(list.count - Self.observationLimit) }
        observations[profileID] = list
    }

    private func pendingItems(for profile: Profile) throws -> [PendingItem] {
        let engine = SuggestionEngine(home: environment.homeDirectory, aggregationThreshold: 20,
                                      templates: catalog.templates.values.sorted { $0.id < $1.id },
                                      resolver: environment.resolver, caseInsensitive: environment.caseInsensitive)
        return engine.pendingItems(observations: observations[profile.id] ?? [], policy: try compiler.compile(profile, catalog: catalog),
                                   enabledTemplates: Set(profile.templates.map(\.id)))
    }

    public func handle(_ request: HelperRequest, caller: CallerIdentity, process: ProcessKey) -> HelperResponse {
        var caller = caller
        caller.managedInstance = tracker.owner(of: process)
        // 受管对象里的进程不能反过来操控权限；但“上报自己被装进了沙箱”正是启动器
        // 该做的事——它注册完自己就已经是实例根进程，不豁免的话这条永远发不进来。
        if caller.managedInstance != nil, !isSelfReport(request) { return .failure(code: "managed_caller") }
        guard let role = trust.role(of: caller) else {
            let known = trust.identities
                .map { "\($0.key)=\($0.value.cdhashes.sorted().joined(separator: "|"))" }
                .joined(separator: " ")
            let detail = "id=\(caller.signingIdentifier) cdhash=\(caller.cdhash ?? "nil") uid=\(caller.uid) allowedUID=\(trust.allowedUID) 已知=\(known)"
            #if canImport(os)
            Logger(subsystem: "com.lsclpangpang.agentguard", category: "trust").error("\(detail, privacy: .public)")
            #endif
            return .failure(code: "not_trusted")
        }
        do {
            switch request {
            case .status:
                return .status(try statusReport())
            case let .proposeChange(profile):
                try require(role, in: [.app])
                return try propose(profile, caller: caller)
            case let .approveChange(changeID, digest, authorization):
                try require(role, in: [.app])
                return try approve(changeID: changeID, digest: digest, token: authorization, caller: caller)
            case let .applyTightening(profile):
                try require(role, in: [.app])
                return try tighten(profile, caller: caller)
            case let .registerInstance(profileID, revision):
                try require(role, in: [.cli, .launcher])
                return try register(profileID: profileID, revision: revision, process: process, supervisedByLaunchd: role == .launcher)
            case let .reportVerification(instance, passed):
                try require(role, in: [.app, .launcher])
                verified[instance] = passed
                return .ok
            case let .installLaunchAgent(profileID):
                try require(role, in: [.app])
                return try installLaunchAgent(profileID)
            case .acknowledgeCollectorProblems:
                try require(role, in: [.app])
                onAcknowledgeCollectorProblems?()
                return .ok
            case let .pendingItems(profileID):
                try require(role, in: [.app])
                guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
                return .pendingItems(try pendingItems(for: latest))
            case let .removeManagement(profileID, restoreOriginal, authorization):
                try require(role, in: [.app])
                return try removeManagement(profileID, restoreOriginal: restoreOriginal, token: authorization)
            case let .restartManagedInstance(profileID):
                try require(role, in: [.app])
                return try restartManaged(profileID)
            case let .deleteProfile(profileID, authorization):
                try require(role, in: [.app])
                return try deleteProfile(profileID, token: authorization)
            }
        } catch let failure as Failure {
            return .failure(code: failure.code)
        } catch let error as ApprovalError {
            return .failure(code: Self.code(error))
        } catch is CompileError {
            return .failure(code: "compile_error")
        } catch let error as StoreError {
            if case .invalidProfileID = error { return .failure(code: "invalid_profile") }
            return .failure(code: "revision_conflict")
        } catch {
            return .failure(code: "internal_error")
        }
    }

    private func isSelfReport(_ request: HelperRequest) -> Bool {
        if case .reportVerification = request { return true }
        return false
    }

    private struct Failure: Error {
        let code: String
    }

    private func require(_ role: CallerRole, in allowed: Set<CallerRole>) throws {
        guard allowed.contains(role) else { throw Failure(code: "not_trusted") }
    }

    private func currentAndBase(_ profile: Profile) throws -> (current: EffectivePolicy, base: Int) {
        let latest = try store.latest(profile.id)
        let base = latest?.revision ?? 0
        guard profile.revision == base + 1 else { throw Failure(code: "revision_conflict") }
        let empty = Profile(id: profile.id, revision: 0, mode: .enforce, templates: [], files: [], exec: [], network: NetworkPolicy())
        return (try compiler.compile(latest ?? empty, catalog: catalog), base)
    }

    private func propose(_ profile: Profile, caller: CallerIdentity) throws -> HelperResponse {
        let (current, base) = try currentAndBase(profile)
        let diff = PolicyDiff(from: current, to: try compiler.compile(profile, catalog: catalog))
        let pending = try ledger.propose(profileID: profile.id, baseRevision: base, diff: diff, caller: caller, now: clock())
        let info = PendingChangeInfo(id: pending.id, digest: pending.diffDigest, summary: pending.summaryLines,
                                     requiresAuthorization: pending.requiresAuthorization, baseRevision: base, expiresAt: pending.expiresAt)
        proposals[pending.id] = (profile, info)
        return .pending(info)
    }

    private func approve(changeID: String, digest: String, token: Data?, caller: CallerIdentity) throws -> HelperResponse {
        guard let proposal = proposals.removeValue(forKey: changeID) else { throw ApprovalError.unknownChange }
        let granted = verifier.verify(token: token, scope: Self.authorizationScope(forChange: changeID), summary: proposal.info.summary)
        let evidence: AuthorizationEvidence = granted ? .verified(changeID: changeID) : .none
        let current = try store.latest(proposal.profile.id)?.revision ?? 0
        let approved = try ledger.approve(changeID: changeID, presentedDigest: digest, currentRevision: current,
                                          caller: caller, authorization: evidence, now: clock())
        try store.save(proposal.profile, approval: approved)
        return .applied(revision: approved.newRevision)
    }

    private func tighten(_ profile: Profile, caller: CallerIdentity) throws -> HelperResponse {
        let (current, base) = try currentAndBase(profile)
        let diff = PolicyDiff(from: current, to: try compiler.compile(profile, catalog: catalog))
        let approved = try ledger.applyTightening(profileID: profile.id, baseRevision: base, currentRevision: base, diff: diff, caller: caller)
        try store.save(profile, approval: approved)
        return .applied(revision: approved.newRevision)
    }

    private func register(profileID: String, revision: Int, process: ProcessKey, supervisedByLaunchd: Bool) throws -> HelperResponse {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        guard latest.revision == revision else { throw Failure(code: "stale_revision") }
        let sbpl = renderer.render(try compiler.compile(latest, catalog: catalog))
        let instance = nextInstance
        nextInstance += 1
        tracker.register(instance: instance, profileID: profileID, revision: revision, root: process, supervisedByLaunchd: supervisedByLaunchd)
        return .registered(instance: instance, sbpl: sbpl)
    }

    public static func authorizationScope(forChange changeID: String) -> String { "change." + changeID }
    public static func authorizationScope(forRemoval profileID: String) -> String { "remove." + profileID }
    public static func authorizationScope(forDeletion profileID: String) -> String { "delete." + profileID }

    /// Archives the profile. A running instance keeps the sandbox it started with, but nothing could
    /// restart it or show its state any more, so it has to be stopped first.
    private func deleteProfile(_ profileID: String, token: Data?) throws -> HelperResponse {
        guard try store.latest(profileID) != nil else { throw Failure(code: "unknown_profile") }
        guard !tracker.instances(ofProfile: profileID).contains(where: \.isRunning) else { throw Failure(code: "profile_running") }
        guard verifier.verify(token: token, scope: Self.authorizationScope(forDeletion: profileID), summary: ["删除配置档 \(profileID)"]) else {
            throw ApprovalError.authorizationMissing
        }
        let stamp = String(Int(clock().timeIntervalSince1970))
        try store.archive(profileID, stamp: stamp)
        observations.removeValue(forKey: profileID)
        proposals = proposals.filter { $0.value.profile.id != profileID }
        return .deleted(profileID: profileID)
    }

    private func launchDefinition(_ profileID: String) throws -> (LaunchAgentDefinition, LaunchSettings) {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        guard let launch = latest.launch else { throw Failure(code: "no_launch_settings") }
        // 启动器每次重编都会重签，把它的 cdhash 前 8 位带进 label：launchd 的 BTM 记录按 label
        // 缓存 LWCR，不换 label 的话重编后任务会以 EX_CONFIG(78) 起不来。
        let fingerprint = launcherGeneration
        let definition = LaunchAgentDefinition(labelPrefix: settings.labelPrefix, launcherPath: settings.launcherPath, profileID: profileID,
                                               runAtLoad: true, restartOnCleanExit: launch.restartOnCleanExit,
                                               throttleInterval: settings.throttleInterval,
                                               logDirectory: managedLogDirectory.isEmpty ? settings.logDirectory : managedLogDirectory,
                                               generation: fingerprint)
        return (definition, launch)
    }

    private func installLaunchAgent(_ profileID: String) throws -> HelperResponse {
        let (definition, launch) = try launchDefinition(profileID)
        return .launchAgent(label: definition.label, originalLabel: launch.originalLabel, plist: try definition.xmlData())
    }

    private func restartManaged(_ profileID: String) throws -> HelperResponse {
        let (definition, launch) = try launchDefinition(profileID)
        let pids = tracker.instances(ofProfile: profileID)
            .flatMap { $0.liveProcesses.map(\.pid) }
            .sorted()
        return .restartManaged(label: definition.label, originalLabel: launch.originalLabel,
                               plist: try definition.xmlData(), pids: pids)
    }

    private func removeManagement(_ profileID: String, restoreOriginal: Bool, token: Data?) throws -> HelperResponse {
        let (definition, launch) = try launchDefinition(profileID)
        let summary = restoreOriginal ? ["移除管控并恢复原启动项（将无限制运行）"] : ["停止并移除管控"]
        guard verifier.verify(token: token, scope: Self.authorizationScope(forRemoval: profileID), summary: summary) else {
            throw ApprovalError.authorizationMissing
        }
        return .removal(label: definition.label, restoreOriginalLabel: restoreOriginal ? launch.originalLabel : nil)
    }

    private func statusReport() throws -> StatusReport {
        var targets: [String: [String]] = [:]
        for id in try store.profileIDs() {
            if let latest = try store.latest(id), let policy = try? compiler.compile(latest, catalog: catalog) {
                targets[id] = policy.detectionTargets
            }
        }
        let unmanaged = UnmanagedDetector.detect(running: runningProcesses, tracker: tracker, targets: targets,
                                                 resolver: environment.resolver, caseInsensitive: environment.caseInsensitive)
        let profiles = try store.profileIDs().compactMap { id -> ProfileStatusReport? in
            guard let latest = try store.latest(id) else { return nil }
            let instances = tracker.instances(ofProfile: id)
            return ProfileStatusReport(
                profileID: id,
                savedRevision: latest.revision,
                mode: latest.mode,
                revisionState: RevisionState.evaluate(savedRevision: latest.revision, instances: instances, verified: verified),
                runningInstances: instances.filter(\.isRunning).map(\.id),
                pendingCount: try pendingItems(for: latest).count,
                detachedInstances: instances.filter(\.detachedFromLaunchd).map(\.id),
                unmanagedProcesses: unmanaged[id]?.map(\.pid) ?? []
            )
        }
        return StatusReport(profiles: profiles, collectorProblems: collectorHealth.problems.sorted { $0.sortKey < $1.sortKey }.map(\.description))
    }

    static func code(_ error: ApprovalError) -> String {
        switch error {
        case .callerNotTrusted: return "not_trusted"
        case .callerIsManaged: return "managed_caller"
        case .unknownChange: return "unknown_change"
        case .alreadyUsed: return "already_used"
        case .expired: return "expired"
        case .digestMismatch: return "digest_mismatch"
        case .baseRevisionChanged: return "revision_conflict"
        case .authorizationMissing: return "authorization_missing"
        case .authorizationRequired: return "authorization_required"
        }
    }
}
