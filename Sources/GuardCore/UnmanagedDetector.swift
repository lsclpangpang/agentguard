public struct RunningProcess: Hashable, Sendable {
    public var key: ProcessKey
    public var executablePath: String
    public var parentPID: Int32?

    public init(key: ProcessKey, executablePath: String, parentPID: Int32? = nil) {
        self.key = key
        self.executablePath = executablePath
        self.parentPID = parentPID
    }
}

/// Finds managed programs running outside any tracked instance. This is detection, not prevention.
public enum UnmanagedDetector {
    public static func detect(running: [RunningProcess], tracker: InstanceTracker, targets: [String: [String]],
                              resolver: any PathResolver, caseInsensitive: Bool) -> [String: [ProcessKey]] {
        let parents = Dictionary(running.compactMap { p in p.parentPID.map { (p.key.pid, $0) } }, uniquingKeysWith: { a, _ in a })
        let anchors = tracker.restoredRootPIDs
        let unowned = running.filter { !isManaged($0, tracker: tracker, parents: parents, anchors: anchors) }
        let paths = unowned.map { (key: $0.key, path: try? CanonicalPath($0.executablePath, resolver: resolver)) }
        var found: [String: [ProcessKey]] = [:]
        for (profileID, targetPaths) in targets {
            let canonicalTargets = targetPaths.compactMap { try? CanonicalPath($0, resolver: resolver) }
            let matches = paths.filter { entry in
                guard let path = entry.path else { return false }
                return canonicalTargets.contains { $0.isSame(as: path, caseInsensitive: caseInsensitive) }
            }
            if !matches.isEmpty { found[profileID] = matches.map(\.key).sorted() }
        }
        return found
    }

    /// Owned by an instance (by PID: a listing carries no audit-token version), or descended from the
    /// root of an instance restored after a Helper restart, whose forks were never observed. Sandboxes
    /// are inherited, so those descendants are confined. Only restored roots vouch for descendants: a
    /// stale owner entry whose PID was reused by a shell must not hide everything started from it.
    private static func isManaged(_ process: RunningProcess, tracker: InstanceTracker, parents: [Int32: Int32], anchors: Set<Int32>) -> Bool {
        if tracker.owner(of: process.key) != nil || tracker.owner(ofPID: process.key.pid) != nil { return true }
        guard !anchors.isEmpty else { return false }
        var pid = process.key.pid
        var seen: Set<Int32> = []
        while pid > 1, seen.insert(pid).inserted {
            if anchors.contains(pid) { return true }
            guard let parent = parents[pid] else { return false }
            pid = parent
        }
        return false
    }

    /// Profiles whose original, unprotected launch item has been written back (for example by a vendor installer).
    public static func reappearedStartupItems(existingLabels: Set<String>, takenOver: [String: String]) -> [String] {
        takenOver.filter { existingLabels.contains($0.value) }.map(\.key).sorted()
    }
}
