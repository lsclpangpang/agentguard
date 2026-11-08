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
    public var runUUID: String?
    public var instanceOrigin: String?
    public var bootSessionID: String?
    /// The original root, independent of whether its entry process subsequently exits.
    public var rootProcess: ProcessKey?
    public var rootStartTime: UInt64?

    public init(id: Int, profileID: String, revision: Int, liveProcesses: Set<ProcessKey>, lifecycleConfirmed: Bool,
                supervisedByLaunchd: Bool = false, entry: ProcessKey? = nil, runUUID: String? = nil,
                instanceOrigin: String? = nil, bootSessionID: String? = nil, rootProcess: ProcessKey? = nil,
                rootStartTime: UInt64? = nil) {
        self.id = id
        self.profileID = profileID
        self.revision = revision
        self.liveProcesses = liveProcesses
        self.lifecycleConfirmed = lifecycleConfirmed
        self.supervisedByLaunchd = supervisedByLaunchd
        self.entry = entry
        self.runUUID = runUUID
        self.instanceOrigin = instanceOrigin
        self.bootSessionID = bootSessionID
        self.rootProcess = rootProcess
        self.rootStartTime = rootStartTime
    }

    public var isRunning: Bool { !liveProcesses.isEmpty }

    /// Some of the instance's processes may have started outside our view: it was restored without
    /// its history, or the collector lost events while it ran.
    public var trackingIncomplete: Bool { restored || !lifecycleConfirmed }

    /// The entry exited but processes it started are still running, so launchd will not restart them
    /// if they crash. Typically an entry script that backgrounds the daemon instead of `exec`-ing it.
    public var detachedFromLaunchd: Bool { supervisedByLaunchd && entry == nil && isRunning }
}

/// Attributes processes to run instances by fork lineage, never by name or parent PID.
public struct InstanceTracker: Sendable {
    private var instances: [Int: InstanceSnapshot] = [:]
    private var owners: [ProcessKey: Int] = [:]
    /// Restored keys contain a birth-time placeholder, not an audit-token pidversion. Only the
    /// platform-validated full birth retained by adoption can bridge one to an observed ES key.
    private var restoredPlaceholders: Set<ProcessKey> = []
    private var validatedRestoredBirths: [ProcessKey: UInt64] = [:]

    public init() {}

    public mutating func register(instance id: Int, profileID: String, revision: Int, root: ProcessKey, supervisedByLaunchd: Bool = false,
                                  restored: Bool = false, runUUID: String? = nil, instanceOrigin: String? = nil,
                                  bootSessionID: String? = nil, rootStartTime: UInt64? = nil) {
        instances[id] = InstanceSnapshot(id: id, profileID: profileID, revision: revision, liveProcesses: [root], lifecycleConfirmed: true,
                                         supervisedByLaunchd: supervisedByLaunchd, entry: root, runUUID: runUUID,
                                         instanceOrigin: instanceOrigin, bootSessionID: bootSessionID,
                                         rootProcess: root, rootStartTime: rootStartTime)
        instances[id]?.restored = restored
        owners[root] = id
        validatedRestoredBirths.removeValue(forKey: root)
        if restored { restoredPlaceholders.insert(root) }
        else { restoredPlaceholders.remove(root) }
    }

    /// Platform-validated root metadata, not inferred later from an event's potentially reused PID.
    public mutating func updateIdentity(instance: Int, bootSessionID: String?, rootStartTime: UInt64?) {
        if let bootSessionID { instances[instance]?.bootSessionID = bootSessionID }
        if let rootStartTime { instances[instance]?.rootStartTime = rootStartTime }
    }

    public mutating func handle(_ event: ProcessEvent) {
        switch event {
        case let .fork(parent, child):
            guard let id = owners[parent] else { return }
            // A process scan may have adopted this child before a buffered fork arrives. The
            // caller must resolve that placeholder with its exact validated birth first.
            guard !restoredPlaceholders.contains(where: { $0.pid == child.pid }) else { return }
            guard owners[child] == nil || owners[child] == id else { return }
            restoredPlaceholders.remove(child)
            validatedRestoredBirths.removeValue(forKey: child)
            owners[child] = id
            instances[id]?.liveProcesses.insert(child)
        case let .exec(from, to):
            guard let id = owners.removeValue(forKey: from) else { return }
            restoredPlaceholders.remove(from)
            restoredPlaceholders.remove(to)
            validatedRestoredBirths.removeValue(forKey: from)
            validatedRestoredBirths.removeValue(forKey: to)
            owners[to] = id
            instances[id]?.liveProcesses.remove(from)
            instances[id]?.liveProcesses.insert(to)
            if instances[id]?.entry == from { instances[id]?.entry = to }
        case let .exit(key):
            guard let id = owners.removeValue(forKey: key) else { return }
            restoredPlaceholders.remove(key)
            validatedRestoredBirths.removeValue(forKey: key)
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

    /// Resolve an ES actor without a PID-only fallback. An ordinary tracked audit token remains
    /// authoritative; a recovery placeholder needs an exact full birth independently validated by
    /// the platform. Return its old key so the platform can migrate its own birth bookkeeping too.
    public mutating func resolveObservedProcess(_ key: ProcessKey, startTime: UInt64?, expectedInstance: Int? = nil)
        -> (instance: Int, previousKey: ProcessKey?)? {
        if let id = owners[key], !restoredPlaceholders.contains(key) {
            return expectedInstance == nil || expectedInstance == id ? (id, nil) : nil
        }
        guard let startTime, startTime > 0 else { return nil }
        let candidates = restoredPlaceholders.filter { previous in
            guard previous.pid == key.pid, validatedRestoredBirths[previous] == startTime,
                  let id = owners[previous], expectedInstance == nil || expectedInstance == id,
                  let snapshot = instances[id] else { return false }
            return snapshot.restored && snapshot.liveProcesses.contains(previous)
        }
        guard candidates.count == 1, let previous = candidates.first, let id = owners[previous],
              owners[key] == nil || previous == key else { return nil }
        owners.removeValue(forKey: previous)
        owners[key] = id
        instances[id]?.liveProcesses.remove(previous)
        instances[id]?.liveProcesses.insert(key)
        if instances[id]?.entry == previous { instances[id]?.entry = key }
        if instances[id]?.rootProcess == previous { instances[id]?.rootProcess = key }
        restoredPlaceholders.remove(previous)
        validatedRestoredBirths.removeValue(forKey: previous)
        return (id, previous)
    }

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
    public mutating func adoptDescendants(of processes: [RunningProcess], knownBirths: [ProcessKey: UInt64],
                                         birth: (Int32) -> UInt64?) -> [ProcessKey: UInt64] {
        var ownerByPID: [Int32: Int] = [:]
        var validatedBirths: [Int32: UInt64] = [:]
        for (key, id) in owners where instances[id]?.restored == true {
            guard let expected = knownBirths[key], birth(key.pid) == expected else {
                handle(.exit(key))
                continue
            }
            ownerByPID[key.pid] = id
            validatedBirths[key.pid] = expected
            if restoredPlaceholders.contains(key) { validatedRestoredBirths[key] = expected }
        }
        guard !ownerByPID.isEmpty else { return [:] }
        var children: [Int32: [RunningProcess]] = [:]
        for process in processes { if let parent = process.parentPID { children[parent, default: []].append(process) } }
        var adopted: [ProcessKey: UInt64] = [:]
        var queue = Array(ownerByPID.keys)
        while let parent = queue.popLast() {
            guard let id = ownerByPID[parent], let parentBirth = validatedBirths[parent],
                  birth(parent) == parentBirth else { continue }
            for child in children[parent] ?? [] where ownerByPID[child.key.pid] == nil && owners.keys.allSatisfy({ $0.pid != child.key.pid }) {
                // A stale process listing must not attach a process born before its claimed parent,
                // nor a child whose parent was reused while the scan was in progress.
                guard let born = child.startTime, birth(child.key.pid) == born,
                      born >= parentBirth, birth(parent) == parentBirth else { continue }
                let key = ProcessKey(pid: child.key.pid, version: UInt32(truncatingIfNeeded: born))
                owners[key] = id
                instances[id]?.liveProcesses.insert(key)
                restoredPlaceholders.insert(key)
                validatedRestoredBirths[key] = born
                ownerByPID[child.key.pid] = id
                adopted[key] = born
                validatedBirths[key.pid] = born
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
        restoredPlaceholders = restoredPlaceholders.filter { owners[$0] != nil }
        validatedRestoredBirths = validatedRestoredBirths.filter { owners[$0.key] != nil }
        return ids.sorted()
    }

    public func instances(ofProfile profileID: String) -> [InstanceSnapshot] {
        instances.values.filter { $0.profileID == profileID }.sorted { $0.id < $1.id }
    }
}
