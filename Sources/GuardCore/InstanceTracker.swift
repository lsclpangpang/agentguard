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

    public init(id: Int, profileID: String, revision: Int, liveProcesses: Set<ProcessKey>, lifecycleConfirmed: Bool) {
        self.id = id
        self.profileID = profileID
        self.revision = revision
        self.liveProcesses = liveProcesses
        self.lifecycleConfirmed = lifecycleConfirmed
    }

    public var isRunning: Bool { !liveProcesses.isEmpty }
}

/// Attributes processes to run instances by fork lineage, never by name or parent PID.
public struct InstanceTracker: Sendable {
    private var instances: [Int: InstanceSnapshot] = [:]
    private var owners: [ProcessKey: Int] = [:]

    public init() {}

    public mutating func register(instance id: Int, profileID: String, revision: Int, root: ProcessKey) {
        instances[id] = InstanceSnapshot(id: id, profileID: profileID, revision: revision, liveProcesses: [root], lifecycleConfirmed: true)
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
        case let .exit(key):
            guard let id = owners.removeValue(forKey: key) else { return }
            instances[id]?.liveProcesses.remove(key)
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
