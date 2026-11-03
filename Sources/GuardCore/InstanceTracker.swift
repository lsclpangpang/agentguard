/// Identifies one process image: macOS bumps the version on exec and on PID reuse.
public struct ProcessKey: Hashable, Comparable, Sendable, Codable {
    public var pid: Int32
    public var version: UInt32

    public init(pid: Int32, version: UInt32) {
        self.pid = pid
        self.version = version
    }

    public static func < (lhs: ProcessKey, rhs: ProcessKey) -> Bool {
        (lhs.pid, lhs.version) < (rhs.pid, rhs.version)
    }
}

public enum ProcessEvent: Equatable, Sendable {
    case fork(parent: ProcessKey, child: ProcessKey)
    case exec(from: ProcessKey, to: ProcessKey)
    case exit(ProcessKey)
    /// The collector lost events; lineage of anything still running can no longer be trusted.
    case gap
}

public struct InstanceSnapshot: Equatable, Sendable {
    public var id: Int
    public var profileID: String
    public var revision: Int
    public var liveProcesses: Set<ProcessKey>
    public var lifecycleConfirmed: Bool
    /// Started as a launchd job; launchd only watches the entry process, not its descendants.
    public var supervisedByLaunchd: Bool
    /// The process launchd started, following its execs; nil once it has exited.
    public var entry: ProcessKey?

    public init(id: Int, profileID: String, revision: Int, liveProcesses: Set<ProcessKey>, lifecycleConfirmed: Bool,
                supervisedByLaunchd: Bool = false, entry: ProcessKey? = nil) {
        self.id = id
        self.profileID = profileID
        self.revision = revision
        self.liveProcesses = liveProcesses
        self.lifecycleConfirmed = lifecycleConfirmed
        self.supervisedByLaunchd = supervisedByLaunchd
        self.entry = entry
    }

    public var isRunning: Bool { !liveProcesses.isEmpty }

    /// The entry exited but processes it started are still running, so launchd will not restart them
    /// if they crash. Typically an entry script that backgrounds the daemon instead of `exec`-ing it.
    public var detachedFromLaunchd: Bool { supervisedByLaunchd && entry == nil && isRunning }
}

/// Attributes processes to run instances by fork lineage, never by name or parent PID.
public struct InstanceTracker: Sendable {
    private var instances: [Int: InstanceSnapshot] = [:]
    private var owners: [ProcessKey: Int] = [:]

    public init() {}

    public mutating func register(instance id: Int, profileID: String, revision: Int, root: ProcessKey, supervisedByLaunchd: Bool = false) {
        instances[id] = InstanceSnapshot(id: id, profileID: profileID, revision: revision, liveProcesses: [root], lifecycleConfirmed: true,
                                         supervisedByLaunchd: supervisedByLaunchd, entry: root)
        owners[root] = id
    }

    public mutating func handle(_ event: ProcessEvent) {
        switch event {
        case let .fork(parent, child):
            guard let id = owners[parent] else { return }
            owners[child] = id
            instances[id]?.liveProcesses.insert(child)
        case let .exec(from, to):
            guard let id = owners.removeValue(forKey: from) else { return }
            owners[to] = id
            instances[id]?.liveProcesses.remove(from)
            instances[id]?.liveProcesses.insert(to)
            if instances[id]?.entry == from { instances[id]?.entry = to }
        case let .exit(key):
            guard let id = owners.removeValue(forKey: key) else { return }
            instances[id]?.liveProcesses.remove(key)
            if instances[id]?.entry == key { instances[id]?.entry = nil }
        case .gap:
            for (id, snapshot) in instances where snapshot.isRunning {
                instances[id]?.lifecycleConfirmed = false
            }
        }
    }

    public func liveProcesses(of id: Int) -> Set<ProcessKey> { instances[id]?.liveProcesses ?? [] }

    public func isRunning(_ id: Int) -> Bool { instances[id]?.isRunning ?? false }

    public func owner(of key: ProcessKey) -> Int? { owners[key] }

    /// Owner of any live process with this PID; for sources that report PIDs without versions.
    public func owner(ofPID pid: Int32) -> Int? {
        owners.first { $0.key.pid == pid }?.value
    }

    public func snapshot(of id: Int) -> InstanceSnapshot? { instances[id] }

    public func instances(ofProfile profileID: String) -> [InstanceSnapshot] {
        instances.values.filter { $0.profileID == profileID }.sorted { $0.id < $1.id }
    }
}
