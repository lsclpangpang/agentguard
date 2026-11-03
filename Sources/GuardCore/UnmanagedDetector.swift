public struct RunningProcess: Hashable, Sendable {
    public var key: ProcessKey
    public var executablePath: String

    public init(key: ProcessKey, executablePath: String) {
        self.key = key
        self.executablePath = executablePath
    }
}

/// Finds managed programs running outside any tracked instance. This is detection, not prevention.
public enum UnmanagedDetector {
    public static func detect(running: [RunningProcess], tracker: InstanceTracker, targets: [String: [String]],
                              resolver: any PathResolver, caseInsensitive: Bool) -> [String: [ProcessKey]] {
        var found: [String: [ProcessKey]] = [:]
        for (profileID, paths) in targets {
            let canonicalTargets = paths.compactMap { try? CanonicalPath($0, resolver: resolver) }
            let matches = running.filter { process in
                guard tracker.owner(of: process.key) == nil, let path = try? CanonicalPath(process.executablePath, resolver: resolver) else { return false }
                return canonicalTargets.contains { $0.isSame(as: path, caseInsensitive: caseInsensitive) }
            }
            if !matches.isEmpty { found[profileID] = matches.map(\.key).sorted() }
        }
        return found
    }

    /// Profiles whose original, unprotected launch item has been written back (for example by a vendor installer).
    public static func reappearedStartupItems(existingLabels: Set<String>, takenOver: [String: String]) -> [String] {
        takenOver.filter { existingLabels.contains($0.value) }.map(\.key).sorted()
    }
}
