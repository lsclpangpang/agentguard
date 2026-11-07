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
    case installLaunchAgent(profileID: String)
    case pendingItems(profileID: String)
    case acknowledgeCollectorProblems
    case removeManagement(profileID: String, restoreOriginal: Bool, authorization: Data?)
    /// 重启受管实例：改完规则后旧进程还按老沙箱在跑，必须重启才会装载新规则。
    case restartManagedInstance(profileID: String)
    /// `restoreOriginal` puts back the launch item a takeover replaced; it then runs unprotected.
    case deleteProfile(profileID: String, restoreOriginal: Bool, authorization: Data?)
    /// Stops the managed copies for this login only; the login setting is left as it is.
    case stopManaged(profileID: String)
    /// Puts the managed launch item where the saved login setting says, without stopping anything.
    case applyLoginSetting(profileID: String)
    /// Stores the login setting outside the revisions and applies it; nothing is stopped or started.
    case setRunAtLogin(profileID: String, enabled: Bool)
    /// Backs up and unloads another launch item that starts the same program outside AgentGuard.
    case disableLaunchItem(profileID: String, label: String, path: String, authorization: Data?)
    /// Puts back a launch item disabled earlier; it then runs outside AgentGuard again.
    case restoreLaunchItem(label: String, authorization: Data?)
    case decide(profileID: String, suggestion: Suggestion, decision: SuggestionDecision)
    case activity(profileID: String)
    /// Stops every managed program and removes AgentGuard's launch items and collector. Profiles,
    /// backups and the programs' working data are kept.
    case uninstall(restoreOriginals: Bool, authorization: Data?)
}

/// Bumped whenever the App and the Helper must be updated together; the App compares it with its own.
public enum HelperProtocol {
    public static let version = 6
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

/// The currently known processes of one instance, independent of missing lifecycle history.
public struct RuntimeInstanceReport: Codable, Equatable, Sendable {
    public var id: Int
    public var revision: Int
    public var entryPID: Int32?
    public var knownPIDs: [Int32]
    /// The representative process queried by the most recent sandbox check.
    public var checkedPID: Int32?
    public var verified: Bool?
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
    /// Nil means an older Helper has not reported the actual launch registration.
    public var launchAgent: LaunchAgentStatus?
    /// Why the running instances did not pass the Helper's sandbox check; empty when they did or it has not run yet.
    public var verificationIssues: [String]
    /// Checks without a verdict, e.g. a temporary file that does not currently exist.
    public var verificationPending: [String]
    /// Absent positive-only grants; their availability is checked after the path appears.
    public var verificationDeferred: [String]
    /// Includes historical instances with no known processes left.
    public var untrackedInstances: [Int]
    /// Only known running instances. Must not be used to claim complete revocation.
    public var runtimeRevisionState: RevisionState?
    public var runtimeInstances: [RuntimeInstanceReport]

    public var historicalTrackingGaps: [Int] { untrackedInstances.filter { !runningInstances.contains($0) } }
    public var activeTrackingGaps: [Int] { untrackedInstances.filter { runningInstances.contains($0) } }

    public init(profileID: String, savedRevision: Int, mode: Mode, revisionState: RevisionState, runningInstances: [Int], pendingCount: Int,
                detachedInstances: [Int] = [], unmanagedProcesses: [Int32] = [], launchAgent: LaunchAgentStatus? = nil,
                verificationIssues: [String] = [], untrackedInstances: [Int] = [], verificationPending: [String] = [],
                verificationDeferred: [String] = [], runtimeRevisionState: RevisionState? = nil,
                runtimeInstances: [RuntimeInstanceReport] = []) {
        self.profileID = profileID
        self.savedRevision = savedRevision
        self.mode = mode
        self.revisionState = revisionState
        self.runningInstances = runningInstances
        self.pendingCount = pendingCount
        self.detachedInstances = detachedInstances
        self.unmanagedProcesses = unmanagedProcesses
        self.launchAgent = launchAgent
        self.verificationIssues = verificationIssues
        self.verificationPending = verificationPending
        self.untrackedInstances = untrackedInstances
        self.verificationDeferred = verificationDeferred
        self.runtimeRevisionState = runtimeRevisionState
        self.runtimeInstances = runtimeInstances
    }

    enum CodingKeys: String, CodingKey {
        case profileID, savedRevision, mode, revisionState, runningInstances, pendingCount, detachedInstances, unmanagedProcesses, launchAgent
        case verificationIssues, untrackedInstances, verificationPending
        case verificationDeferred, runtimeRevisionState, runtimeInstances
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
        launchAgent = try c.decodeIfPresent(LaunchAgentStatus.self, forKey: .launchAgent)
        verificationIssues = try c.decodeIfPresent([String].self, forKey: .verificationIssues) ?? []
        verificationPending = try c.decodeIfPresent([String].self, forKey: .verificationPending) ?? []
        untrackedInstances = try c.decodeIfPresent([Int].self, forKey: .untrackedInstances) ?? []
        verificationDeferred = try c.decodeIfPresent([String].self, forKey: .verificationDeferred) ?? []
        runtimeRevisionState = try c.decodeIfPresent(RevisionState.self, forKey: .runtimeRevisionState)
        runtimeInstances = try c.decodeIfPresent([RuntimeInstanceReport].self, forKey: .runtimeInstances) ?? []
    }
}

public struct StatusReport: Codable, Equatable, Sendable {
    public var profiles: [ProfileStatusReport]
    /// Empty only while the collector is healthy; an empty list never means "nothing happened".
    public var collectorProblems: [String]
    /// `HelperProtocol.version` of the Helper that answered; 0 for one that predates it.
    public var helperProtocol: Int

    public init(profiles: [ProfileStatusReport], collectorProblems: [String], helperProtocol: Int = HelperProtocol.version) {
        self.profiles = profiles
        self.collectorProblems = collectorProblems
        self.helperProtocol = helperProtocol
    }

    enum CodingKeys: String, CodingKey { case profiles, collectorProblems, helperProtocol }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        profiles = try c.decode([ProfileStatusReport].self, forKey: .profiles)
        collectorProblems = try c.decode([String].self, forKey: .collectorProblems)
        helperProtocol = try c.decodeIfPresent(Int.self, forKey: .helperProtocol) ?? 0
    }
}

/// One profile an uninstall removes: its launch items, and the original item to put back if asked.
public struct UninstallTarget: Codable, Equatable, Sendable {
    public var profileID: String
    public var hasLaunchSettings: Bool
    public var restoreOriginalLabel: String?

    public init(profileID: String, hasLaunchSettings: Bool, restoreOriginalLabel: String?) {
        self.profileID = profileID
        self.hasLaunchSettings = hasLaunchSettings
        self.restoreOriginalLabel = restoreOriginalLabel
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
    /// The profile was archived; the platform layer removes its managed LaunchAgents, archives its state
    /// directory and, when `restoreOriginalLabel` is set, restores that original launch item.
    case deleted(profileID: String, restoreOriginalLabel: String?)
    case ok
    /// The action completed; some optional cleanup or direct process termination was skipped.
    case completed(warnings: [String])
    case failure(code: String)
    /// The action completed; says what was stopped and what could not be confirmed.
    case report(OperationReport)
    /// The platform layer unloads the profile's managed jobs and stops its processes, keeping the files.
    case stopManaged(profileID: String)
    /// The platform layer moves the managed launch item to match the saved login setting.
    case relocateLaunchAgent(profileID: String, runAtLogin: Bool)
    case disableLaunchItem(profileID: String, label: String, path: String)
    case restoreLaunchItem(label: String)
    case activity(ActivityLog)
    case uninstall(targets: [UninstallTarget])
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
    /// 唯一的一份信任表放在台账里：审批（propose/approve/tightening）也要看到重编后的新 cdhash。
    private var trust: CallerTrustPolicy {
        get { ledger.trust }
        set { ledger.trust = newValue }
    }
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
    /// Set only by the Helper's own sandbox check of the running process, never by the process.
    private var verified: [Int: Bool] = [:]
    private var verificationIssues: [Int: [String]] = [:]
    private var verificationPending: [Int: [String]] = [:]
    private var verificationDeferred: [Int: [String]] = [:]
    private var checkedPID: [Int: Int32] = [:]
    private var checkedAt: [Int: Date] = [:]
    public static let verificationRetryInterval: TimeInterval = 5
    private var registeredAt: [Int: Date] = [:]
    /// What each instance must look like, fixed when its rules were handed out: a later app update
    /// that changes templates must not change what an already running process is checked against.
    private var expectations: [Int: [SandboxExpectation]] = [:]
    private let probe: (any SandboxProbe)?
    private let activity: ActivityStore?
    private let login: LoginSettingStore
    /// How long a registered process may take to apply its sandbox before it counts as unprotected.
    public static let sandboxGracePeriod: TimeInterval = 15
    private var nextInstance = 1
    private var observations: [String: [Observation]] = [:]
    private var collectorHealth = CollectorHealth(problems: [.notStarted])
    private var runningProcesses: [RunningProcess] = []
    private let environment: CompileEnvironment
    private static let observationLimit = 5000
    /// Set by the platform layer, which owns the collector's health monitor.
    public var onAcknowledgeCollectorProblems: (() -> Void)?
    /// The platform wraps archival in startup cleanup/rollback, after trust and authorization.
    public var performProfileDeletion: ((_ id: String, _ restoreOriginalLabel: String?, _ archive: () throws -> Void) throws -> Void)?

    public init(store: ProfileStore, environment: CompileEnvironment, catalog: TemplateCatalog, trust: CallerTrustPolicy,
                verifier: any AuthorizationVerifier, settings: HelperSettings, clock: @escaping () -> Date, makeID: @escaping () -> String,
                launcherGeneration: String = "", managedLogDirectory: String = "", probe: (any SandboxProbe)? = nil,
                activity: ActivityStore? = nil) {
        self.store = store
        self.probe = probe
        self.activity = activity
        self.login = LoginSettingStore(root: store.root, files: activity?.files ?? InMemoryFileStore())
        self.environment = environment
        self.compiler = PolicyCompiler(environment: environment)
        self.renderer = SBPLRenderer(environment: environment)
        self.catalog = catalog
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

    /// The sandbox is checked again rather than restored: the process is still running, so the
    /// check can simply be repeated, and nothing written earlier has to be trusted.
    public func restoreInstance(id: Int, profileID: String, revision: Int, root: ProcessKey, supervisedByLaunchd: Bool) {
        tracker.register(instance: id, profileID: profileID, revision: revision, root: root,
                         supervisedByLaunchd: supervisedByLaunchd, restored: true)
        verified.removeValue(forKey: id)
        verificationIssues.removeValue(forKey: id)
        verificationPending.removeValue(forKey: id)
        verificationDeferred.removeValue(forKey: id)
        checkedPID.removeValue(forKey: id)
        checkedAt.removeValue(forKey: id)
        registeredAt.removeValue(forKey: id)
        expectations.removeValue(forKey: id)
        // Numbering restarts with the Helper; a new instance must never take a restored one's number.
        nextInstance = max(nextInstance, id + 1)
    }

    /// Rechecks running instances periodically: paths and system restrictions can change while
    /// a process runs. A stale failure or success must not remain the final verdict forever.
    public func verifyInstances() {
        guard let probe, let ids = try? store.profileIDs() else { return }
        let now = clock()
        for profileID in ids {
            // An exited instance's verdict is never read again (revision state looks only at running ones).
            for snapshot in tracker.instances(ofProfile: profileID) where !snapshot.isRunning {
                if registeredAt[snapshot.id] != nil || verified[snapshot.id] != nil || expectations[snapshot.id] != nil {
                    log(profileID, .stopped, snapshot.trackingIncomplete
                        ? "副本 #\(snapshot.id) 的已跟踪进程已退出" : "运行副本 #\(snapshot.id) 已退出",
                        snapshot.trackingIncomplete ? ["此前的子进程记录不完整，不能据此确认所有子进程都已退出。"] : [])
                }
                verified.removeValue(forKey: snapshot.id)
                verificationIssues.removeValue(forKey: snapshot.id)
                verificationPending.removeValue(forKey: snapshot.id)
                verificationDeferred.removeValue(forKey: snapshot.id)
                checkedPID.removeValue(forKey: snapshot.id)
                checkedAt.removeValue(forKey: snapshot.id)
                registeredAt.removeValue(forKey: snapshot.id)
                expectations.removeValue(forKey: snapshot.id)
            }
            for snapshot in tracker.instances(ofProfile: profileID) where snapshot.isRunning {
                if let checked = checkedAt[snapshot.id], now.timeIntervalSince(checked) < Self.verificationRetryInterval { continue }
                let previous = verified[snapshot.id]
                let previousIssues = verificationIssues[snapshot.id]
                // A restored instance's rules were handed out by an earlier Helper; recompiling its revision is the best evidence left.
                if expectations[snapshot.id] == nil, let profile = try? store.revision(profileID, snapshot.revision),
                   let policy = try? compiler.compile(profile, catalog: catalog) {
                    expectations[snapshot.id] = SandboxVerification.expectations(for: policy, environment: environment)
                }
                guard let expected = expectations[snapshot.id] else {
                    fail(snapshot.id, ["无法读取或编译这个实例使用的修订 \(snapshot.revision)"])
                    continue
                }
                // Every process of an instance inherits the sandbox its root applied before exec.
                guard let pid = (snapshot.entry ?? snapshot.liveProcesses.min())?.pid else { continue }
                checkedAt[snapshot.id] = now
                checkedPID[snapshot.id] = pid
                verificationDeferred.removeValue(forKey: snapshot.id)
                let verdict = SandboxVerification.verify(pid: pid, expectations: expected, probe: probe)
                switch verdict {
                case .passed, .passedWithDeferred:
                    verified[snapshot.id] = true
                    verificationIssues.removeValue(forKey: snapshot.id)
                    verificationPending.removeValue(forKey: snapshot.id)
                    if case let .passedWithDeferred(paths) = verdict { verificationDeferred[snapshot.id] = paths }
                    if previous != true {
                        var details = ["使用修订 \(snapshot.revision) 的权限；核验进程 PID \(pid)"]
                        if let paths = verificationDeferred[snapshot.id] {
                            details.append("以下授权路径尚未出现，出现后自动补查：" + paths.joined(separator: "、"))
                        }
                        log(profileID, .verified, "运行副本 #\(snapshot.id) 的可用权限检查已通过", details)
                    }
                case let .failed(issues):
                    fail(snapshot.id, issues)
                    if previous != false || previousIssues != issues {
                        log(profileID, .verificationFailed, "运行副本 #\(snapshot.id) 没有通过保护确认", issues)
                    }
                case let .inconclusive(reasons):
                    verified.removeValue(forKey: snapshot.id)
                    verificationIssues.removeValue(forKey: snapshot.id)
                    verificationPending[snapshot.id] = reasons
                case .notSandboxed:
                    // A restored instance has been running for a while; it gets no grace period.
                    let deadline = registeredAt[snapshot.id].map { $0.addingTimeInterval(Self.sandboxGracePeriod) } ?? now
                    if now >= deadline {
                        let issues = ["进程没有进入沙箱，它不受这份权限限制"]
                        fail(snapshot.id, issues)
                        if previous != false || previousIssues != issues {
                            log(profileID, .verificationFailed, "运行副本 #\(snapshot.id) 没有进入沙箱")
                        }
                    } else {
                        verified.removeValue(forKey: snapshot.id)
                        verificationIssues.removeValue(forKey: snapshot.id)
                        verificationPending.removeValue(forKey: snapshot.id)
                        // Do not delay the first confirmation while the launcher enters its sandbox.
                        checkedAt.removeValue(forKey: snapshot.id)
                    }
                case .unavailable:
                    verified.removeValue(forKey: snapshot.id)
                    verificationIssues.removeValue(forKey: snapshot.id)
                    verificationPending[snapshot.id] = ["系统暂时无法查询运行进程的保护状态"]
                }
            }
        }
    }

    /// For the platform layer: records an action in the history once it actually completed.
    public func recordHistory(_ profileID: String, _ kind: HistoryKind, _ title: String, _ details: [String] = []) {
        log(profileID, kind, title, details)
    }

    private func log(_ profileID: String, _ kind: HistoryKind, _ title: String, _ details: [String] = []) {
        try? activity?.append(HistoryEntry(at: clock(), kind: kind, title: title, details: details), profileID: profileID)
    }

    private func fail(_ instance: Int, _ issues: [String]) {
        verified[instance] = false
        verificationIssues[instance] = issues
        verificationPending.removeValue(forKey: instance)
        verificationDeferred.removeValue(forKey: instance)
    }

    public func updateIdentities(_ identities: [CallerRole: CodeIdentity]) {
        trust.identities = identities
    }

    public func ingest(_ event: ProcessEvent) {
        tracker.handle(event)
    }

    /// See `InstanceTracker.adoptDescendants`; returns the birth time of each process taken in.
    public func adoptDescendants(of processes: [RunningProcess], knownBirths: [ProcessKey: UInt64],
                                 birth: (Int32) -> UInt64?) -> [ProcessKey: UInt64] {
        tracker.adoptDescendants(of: processes, knownBirths: knownBirths, birth: birth)
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
        for access in line.observedAccesses { record(Observation(instance: instance, access: access, denied: false, at: clock()), instance: instance) }
    }

    /// One sandbox denial from the unified log; only denials of managed processes are kept.
    public func observe(denial: SandboxDenial) {
        guard let access = denial.access, let instance = tracker.owner(ofPID: denial.pid) else { return }
        record(Observation(instance: instance, access: access, denied: true, at: clock(),
                           networkTarget: denial.networkEndpoint?.rawValue, processName: denial.process, pid: denial.pid), instance: instance)
    }

    private func record(_ observation: Observation, instance: Int) {
        guard let profileID = tracker.snapshot(of: instance)?.profileID else { return }
        var list = observations[profileID, default: []]
        list.append(observation)
        if list.count > Self.observationLimit { list.removeFirst(list.count - Self.observationLimit) }
        observations[profileID] = list
    }

    /// Items still waiting for an answer: decided ones are listed in the activity log instead.
    private func pendingItems(for profile: Profile) throws -> [PendingItem] {
        let decided = activity?.activeDecisions(profile.id) ?? [:]
        return try allPendingItems(for: profile).filter { decided[$0.suggestion] == nil }
    }

    private func allPendingItems(for profile: Profile) throws -> [PendingItem] {
        let engine = SuggestionEngine(home: environment.homeDirectory, aggregationThreshold: 20,
                                      templates: catalog.templates.values.sorted { $0.id < $1.id },
                                      resolver: environment.resolver, caseInsensitive: environment.caseInsensitive)
        return engine.pendingItems(observations: observations[profile.id] ?? [], policy: try compiler.compile(profile, catalog: catalog),
                                   enabledTemplates: Set(profile.templates.map(\.id)))
    }

    public func handle(_ request: HelperRequest, caller: CallerIdentity, process: ProcessKey) -> HelperResponse {
        var caller = caller
        caller.managedInstance = tracker.owner(of: process)
        if caller.managedInstance != nil { return .failure(code: "managed_caller") }
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
            case let .deleteProfile(profileID, restoreOriginal, authorization):
                try require(role, in: [.app])
                return try deleteProfile(profileID, restoreOriginal: restoreOriginal, token: authorization)
            case let .stopManaged(profileID):
                try require(role, in: [.app])
                guard try store.latest(profileID) != nil else { throw Failure(code: "unknown_profile") }
                return .stopManaged(profileID: profileID)
            case let .applyLoginSetting(profileID):
                try require(role, in: [.app])
                guard let latest = try store.latest(profileID), let runAtLogin = login.runAtLogin(of: latest) else { throw Failure(code: "no_launch_settings") }
                return .relocateLaunchAgent(profileID: profileID, runAtLogin: runAtLogin)
            case let .setRunAtLogin(profileID, enabled):
                try require(role, in: [.app])
                guard try store.latest(profileID)?.launch != nil else { throw Failure(code: "no_launch_settings") }
                try login.set(enabled, for: profileID)
                log(profileID, .decision, enabled ? "开启登录自启" : "关闭登录自启", ["只影响以后的登录"])
                return .relocateLaunchAgent(profileID: profileID, runAtLogin: enabled)
            case let .disableLaunchItem(profileID, label, path, authorization):
                try require(role, in: [.app])
                guard try store.latest(profileID) != nil else { throw Failure(code: "unknown_profile") }
                guard PolicyCompiler.isSafeLaunchLabel(label) else { throw Failure(code: "invalid_launch_item") }
                guard verifier.verify(token: authorization, scope: Self.authorizationScope(forDisabling: label), summary: ["停用启动项 \(label)"]) else {
                    throw ApprovalError.authorizationMissing
                }
                return .disableLaunchItem(profileID: profileID, label: label, path: path)
            case let .restoreLaunchItem(label, authorization):
                try require(role, in: [.app])
                guard PolicyCompiler.isSafeLaunchLabel(label) else { throw Failure(code: "invalid_launch_item") }
                guard verifier.verify(token: authorization, scope: Self.authorizationScope(forRestoring: label), summary: ["恢复启动项 \(label)（将无限制运行）"]) else {
                    throw ApprovalError.authorizationMissing
                }
                return .restoreLaunchItem(label: label)
            case let .decide(profileID, suggestion, decision):
                try require(role, in: [.app])
                return try decide(profileID, suggestion: suggestion, decision: decision)
            case let .activity(profileID):
                try require(role, in: [.app])
                return .activity(try activityLog(profileID))
            case let .uninstall(restoreOriginals, authorization):
                try require(role, in: [.app])
                return try uninstall(restoreOriginals: restoreOriginals, token: authorization)
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
        // A stored revision that no longer compiles (stricter rules arrived later) must stay repairable.
        // Comparing against the empty policy makes every grant of the repair need authorization.
        let current = try (try? compiler.compile(latest ?? empty, catalog: catalog)) ?? compiler.compile(empty, catalog: catalog)
        return (current, base)
    }

    /// Expiring grants stay closed until expiry is enforced, including for instances already running.
    /// A grant that is already stored with an expiry may be kept, so such a profile stays editable.
    private func rejectNewTemporaryGrants(_ profile: Profile) throws {
        let stored = Set(try store.latest(profile.id)?.files ?? [])
        if profile.files.contains(where: { $0.expiresAt != nil && !stored.contains($0) }) {
            throw Failure(code: "temporary_grants_unavailable")
        }
    }

    private func propose(_ profile: Profile, caller: CallerIdentity) throws -> HelperResponse {
        try rejectNewTemporaryGrants(profile)
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
        log(proposal.profile.id, .permissionChange, "权限已保存为修订 \(approved.newRevision)", proposal.info.summary)
        return .applied(revision: approved.newRevision)
    }

    private func tighten(_ profile: Profile, caller: CallerIdentity) throws -> HelperResponse {
        try rejectNewTemporaryGrants(profile)
        let (current, base) = try currentAndBase(profile)
        let diff = PolicyDiff(from: current, to: try compiler.compile(profile, catalog: catalog))
        let approved = try ledger.applyTightening(profileID: profile.id, baseRevision: base, currentRevision: base, diff: diff, caller: caller)
        try store.save(profile, approval: approved)
        if !diff.changes.isEmpty { log(profile.id, .permissionChange, "权限已收紧为修订 \(approved.newRevision)", diff.summaryLines) }
        return .applied(revision: approved.newRevision)
    }

    private func register(profileID: String, revision: Int, process: ProcessKey, supervisedByLaunchd: Bool) throws -> HelperResponse {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        guard latest.revision == revision else { throw Failure(code: "stale_revision") }
        let policy = try compiler.compile(latest, catalog: catalog)
        let sbpl = renderer.render(policy)
        let instance = nextInstance
        nextInstance += 1
        tracker.register(instance: instance, profileID: profileID, revision: revision, root: process, supervisedByLaunchd: supervisedByLaunchd)
        verified.removeValue(forKey: instance)
        verificationIssues.removeValue(forKey: instance)
        verificationPending.removeValue(forKey: instance)
        verificationDeferred.removeValue(forKey: instance)
        checkedPID.removeValue(forKey: instance)
        checkedAt.removeValue(forKey: instance)
        registeredAt[instance] = clock()
        expectations[instance] = SandboxVerification.expectations(for: policy, environment: environment)
        log(profileID, .started, "运行副本 #\(instance) 已启动", ["使用修订 \(revision) 的权限", supervisedByLaunchd ? "由 AgentGuard 启动项启动" : "由 guard run 启动"])
        return .registered(instance: instance, sbpl: sbpl)
    }

    public static func authorizationScope(forChange changeID: String) -> String { "change." + changeID }
    public static func authorizationScope(forDisabling label: String) -> String { "disable." + label }
    public static func authorizationScope(forRestoring label: String) -> String { "restore." + label }
    public static func authorizationScope(forUninstall restoreOriginals: Bool) -> String { restoreOriginals ? "uninstall.restore" : "uninstall" }
    public static func authorizationScope(forRemoval profileID: String) -> String { "remove." + profileID }
    /// Restoring the original item makes it run unprotected, so it gets its own scope: authorization for a
    /// plain delete must not also cover a restore.
    public static func authorizationScope(forDeletion profileID: String, restoreOriginal: Bool = false) -> String {
        (restoreOriginal ? "delete.restore." : "delete.") + profileID
    }

    /// Archives the profile. A running instance keeps the sandbox it started with, but nothing could
    /// restart it or show its state any more, so it has to be stopped first.
    private func deleteProfile(_ profileID: String, restoreOriginal: Bool, token: Data?) throws -> HelperResponse {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        guard !tracker.instances(ofProfile: profileID).contains(where: \.isRunning) else { throw Failure(code: "profile_running") }
        let restoreLabel = restoreOriginal ? latest.launch?.originalLabel : nil
        let summary = ["删除配置档 \(profileID)"] + (restoreLabel.map { ["恢复原启动项 \($0)（将无限制运行）"] } ?? [])
        guard verifier.verify(token: token, scope: Self.authorizationScope(forDeletion: profileID, restoreOriginal: restoreLabel != nil), summary: summary) else {
            throw ApprovalError.authorizationMissing
        }
        let archive = { try self.store.archive(profileID, stamp: String(Int(self.clock().timeIntervalSince1970))) }
        if let performProfileDeletion {
            do { try performProfileDeletion(profileID, restoreLabel, archive) }
            catch { throw Failure(code: "startup_error:" + String(describing: error)) }
        } else { try archive() }
        // A recreated profile with the same name must start clean, not inherit old instances or findings.
        for instance in tracker.removeInstances(ofProfile: profileID) {
            verified.removeValue(forKey: instance)
            verificationIssues.removeValue(forKey: instance)
            verificationPending.removeValue(forKey: instance)
            verificationDeferred.removeValue(forKey: instance)
            checkedPID.removeValue(forKey: instance)
            checkedAt.removeValue(forKey: instance)
            registeredAt.removeValue(forKey: instance)
            expectations.removeValue(forKey: instance)
        }
        observations.removeValue(forKey: profileID)
        try? activity?.removeAll(profileID)
        try? login.remove(profileID)
        proposals = proposals.filter { $0.value.profile.id != profileID }
        return .deleted(profileID: profileID, restoreOriginalLabel: restoreLabel)
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

    private func decide(_ profileID: String, suggestion: Suggestion, decision: SuggestionDecision) throws -> HelperResponse {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        guard let activity else { throw Failure(code: "internal_error") }
        let current = try allPendingItems(for: latest).first { $0.suggestion == suggestion }
        switch decision {
        case .keepBlocked:
            // Keeping something blocked is only meaningful when it was blocked.
            guard let current, current.wasBlocked else { throw Failure(code: "not_blocked") }
        case .dismissed:
            guard current != nil else { throw Failure(code: "unknown_item") }
        case .reopened:
            guard activity.activeDecisions(profileID)[suggestion] != nil else { throw Failure(code: "unknown_item") }
        }
        try activity.record(DecisionRecord(suggestion: suggestion, decision: decision, at: clock(), evidence: current?.evidence ?? 0), profileID: profileID)
        let title: String
        switch decision {
        case .keepBlocked: title = "保持阻止：\(suggestion.summary)"
        case .dismissed: title = "不再提示：\(suggestion.summary)（权限没有改变）"
        case .reopened: title = "重新提示：\(suggestion.summary)"
        }
        log(profileID, .decision, title)
        return .ok
    }

    private func activityLog(_ profileID: String) throws -> ActivityLog {
        guard let latest = try store.latest(profileID) else { throw Failure(code: "unknown_profile") }
        let items = (try? allPendingItems(for: latest)) ?? []
        let archived = (activity?.activeDecisions(profileID) ?? [:]).values.sorted { $0.at > $1.at }.map { record in
            ArchivedItem(decision: record, current: items.first { $0.suggestion == record.suggestion })
        }
        let recent = Array((observations[profileID] ?? []).suffix(400).reversed())
        return ActivityLog(recent: recent, archived: archived, history: (activity?.history(profileID) ?? []).reversed(),
                           recordsIncomplete: !collectorHealth.isHealthy)
    }

    /// Everything runs through the platform layer; the Helper decides only who may ask and what is affected.
    private func uninstall(restoreOriginals: Bool, token: Data?) throws -> HelperResponse {
        let summary = restoreOriginals ? ["卸载 AgentGuard，并恢复被替换的原启动方式（将无限制运行）"] : ["卸载 AgentGuard"]
        guard verifier.verify(token: token, scope: Self.authorizationScope(forUninstall: restoreOriginals), summary: summary) else {
            throw ApprovalError.authorizationMissing
        }
        let targets = try store.profileIDs().compactMap { id -> UninstallTarget? in
            guard let latest = try store.latest(id) else { return nil }
            return UninstallTarget(profileID: id, hasLaunchSettings: latest.launch != nil,
                                   restoreOriginalLabel: restoreOriginals ? latest.launch?.originalLabel : nil)
        }
        return .uninstall(targets: targets)
    }

    private func statusReport() throws -> StatusReport {
        verifyInstances()
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
                // One profile that no longer compiles must not hide the status of all the others.
                pendingCount: (try? pendingItems(for: latest).count) ?? 0,
                detachedInstances: instances.filter(\.detachedFromLaunchd).map(\.id),
                unmanagedProcesses: unmanaged[id]?.map(\.pid) ?? [],
                verificationIssues: instances.filter(\.isRunning).flatMap { verificationIssues[$0.id] ?? [] },
                untrackedInstances: instances.filter(\.trackingIncomplete).map(\.id),
                verificationPending: instances.filter(\.isRunning).flatMap { verificationPending[$0.id] ?? [] },
                verificationDeferred: Array(Set(instances.filter(\.isRunning).flatMap { verificationDeferred[$0.id] ?? [] })).sorted(),
                runtimeRevisionState: RevisionState.evaluateKnownProcesses(savedRevision: latest.revision, instances: instances, verified: verified),
                runtimeInstances: instances.filter(\.isRunning).map {
                    RuntimeInstanceReport(id: $0.id, revision: $0.revision, entryPID: $0.entry?.pid,
                                          knownPIDs: $0.liveProcesses.map(\.pid).sorted(),
                                          checkedPID: checkedPID[$0.id], verified: verified[$0.id])
                }
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
