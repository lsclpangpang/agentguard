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
    /// Put back after a Helper restart from the recorded root alone; its descendants were never observed.
    public var restored: Bool = false

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

    /// Some of the instance's processes may have started outside our view: it was restored without
    /// its history, or the collector lost events while it ran.
    public var trackingIncomplete: Bool { isRunning && (restored || !lifecycleConfirmed) }

    /// The entry exited but processes it started are still running, so launchd will not restart them
    /// if they crash. Typically an entry script that backgrounds the daemon instead of `exec`-ing it.
    public var detachedFromLaunchd: Bool { supervisedByLaunchd && entry == nil && isRunning }
}

/// Attributes processes to run instances by fork lineage, never by name or parent PID.
public struct InstanceTracker: Sendable {
    private var instances: [Int: InstanceSnapshot] = [:]
    private var owners: [ProcessKey: Int] = [:]

    public init() {}

    public mutating func register(instance id: Int, profileID: String, revision: Int, root: ProcessKey, supervisedByLaunchd: Bool = false,
                                  restored: Bool = false) {
        instances[id] = InstanceSnapshot(id: id, profileID: profileID, revision: revision, liveProcesses: [root], lifecycleConfirmed: true,
                                         supervisedByLaunchd: supervisedByLaunchd, entry: root)
        instances[id]?.restored = restored
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

    /// PIDs of live roots of restored instances: the only processes whose unobserved descendants count as theirs.
    public var restoredRootPIDs: Set<Int32> {
        Set(instances.values.filter(\.restored).compactMap(\.entry).filter { owners[$0] != nil }.map(\.pid))
    }

    /// Attaches the descendants of restored instances found in a process listing, by parent PID.
    /// Only restored instances need this: the collector reports every fork of the others. Returns
    /// the keys added, each built like a restored root's from the process birth time.
    public mutating func adoptDescendants(of processes: [RunningProcess], birth: (Int32) -> UInt64?) -> [ProcessKey: UInt64] {
        var ownerByPID: [Int32: Int] = [:]
        for (key, id) in owners where instances[id]?.restored == true { ownerByPID[key.pid] = id }
        guard !ownerByPID.isEmpty else { return [:] }
        var children: [Int32: [RunningProcess]] = [:]
        for process in processes { if let parent = process.parentPID { children[parent, default: []].append(process) } }
        var adopted: [ProcessKey: UInt64] = [:]
        var queue = Array(ownerByPID.keys)
        while let parent = queue.popLast() {
            guard let id = ownerByPID[parent] else { continue }
            for child in children[parent] ?? [] where ownerByPID[child.key.pid] == nil && owners.keys.allSatisfy({ $0.pid != child.key.pid }) {
                guard let born = birth(child.key.pid) else { continue }
                let key = ProcessKey(pid: child.key.pid, version: UInt32(truncatingIfNeeded: born))
                owners[key] = id
                instances[id]?.liveProcesses.insert(key)
                ownerByPID[child.key.pid] = id
                adopted[key] = born
                queue.append(child.key.pid)
            }
        }
        return adopted
    }

    /// Forgets every instance of a deleted profile; returns their IDs.
    public mutating func removeInstances(ofProfile profileID: String) -> [Int] {
        let ids = instances.values.filter { $0.profileID == profileID }.map(\.id)
        for id in ids { instances.removeValue(forKey: id) }
        owners = owners.filter { !ids.contains($0.value) }
        return ids.sorted()
    }

    public func instances(ofProfile profileID: String) -> [InstanceSnapshot] {
        instances.values.filter { $0.profileID == profileID }.sorted { $0.id < $1.id }
    }
}
