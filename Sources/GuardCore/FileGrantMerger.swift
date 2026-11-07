/// Normalizes file grants after a user explicitly adds one or widens its access.
///
/// A directory grant already covers every path below it. Keeping a child grant whose access is
/// no wider than the directory only duplicates the effective sandbox rule; in the read-write
/// parent/read-only child case it also makes the policy compiler reject an otherwise intentional
/// change. A narrower read-write child under a read-only parent is meaningful and is retained.
public enum FileGrantMerger {
    private struct Entry {
        var grant: FileGrant
        let path: CanonicalPath
    }

    /// Preserve an explicit downgrade so the compiler can reject a writable parent that would
    /// override it. Removing that child as redundant would look like a successful revocation.
    public static func changingAccess(of grant: FileGrant, to access: Access, in grants: [FileGrant],
                                      resolver: any PathResolver, caseInsensitive: Bool) throws -> [FileGrant] {
        guard grant.access != access, let index = grants.firstIndex(of: grant) else { return grants }
        var changed = grants
        changed[index].access = access
        if access > grant.access {
            return try normalize(changed, resolver: resolver, caseInsensitive: caseInsensitive)
        }
        // Legacy profiles can have both a read-only and a read-write grant for the same path.
        // After a downgrade, exact duplicates must not become duplicate SwiftUI row identifiers.
        var seen: Set<FileGrant> = []
        return changed.filter { seen.insert($0).inserted }
    }

    /// Combines duplicate grants and removes descendants covered by an equal-or-wider directory
    /// grant. The first spelling of a path is retained so adding `/tmp` does not unexpectedly make
    /// the UI display its `/private/tmp` alias; comparisons still use the canonical path.
    /// Wildcard grants are kept as written (exact duplicates aside): whether one covers another is
    /// not decided here, and the compiler still checks them.
    public static func normalize(_ grants: [FileGrant], resolver: any PathResolver,
                                 caseInsensitive: Bool) throws -> [FileGrant] {
        var entries: [Entry] = []
        entries.reserveCapacity(grants.count)
        var seenPatterns: Set<FileGrant> = []
        let patterns = grants.filter { $0.pattern && seenPatterns.insert($0).inserted }

        for grant in grants where !grant.pattern {
            let path = try CanonicalPath(grant.path, resolver: resolver)
            if let index = entries.firstIndex(where: {
                $0.path.isSame(as: path, caseInsensitive: caseInsensitive) && $0.grant.expiresAt == grant.expiresAt
            }) {
                entries[index].grant = mergedSamePath(entries[index].grant, grant)
            } else {
                entries.append(Entry(grant: grant, path: path))
            }
        }

        // Removing one entry can expose the next redundant level (for example A(read-write),
        // A/B(read-only), A/B/C(read-only)), so repeat until the set is stable.
        while true {
            var removedIndex: Int?
            for parentIndex in entries.indices {
                let parent = entries[parentIndex]
                guard parent.grant.kind == .directory else { continue }
                for childIndex in entries.indices where childIndex != parentIndex {
                    let child = entries[childIndex]
                    guard parent.path.contains(child.path, caseInsensitive: caseInsensitive),
                          parent.grant.access >= child.grant.access,
                          lastsAtLeastAsLong(parent.grant, as: child.grant)
                    else { continue }

                    entries[parentIndex].grant.readsSecrets =
                        entries[parentIndex].grant.readsSecrets || child.grant.readsSecrets
                    removedIndex = childIndex
                    break
                }
                if removedIndex != nil { break }
            }

            guard let removedIndex else { break }
            entries.remove(at: removedIndex)
        }

        return entries.map(\.grant) + patterns
    }

    private static func mergedSamePath(_ first: FileGrant, _ second: FileGrant) -> FileGrant {
        var result = first
        if second.kind == .directory { result.kind = .directory }
        result.access = max(result.access, second.access)
        result.readsSecrets = result.readsSecrets || second.readsSecrets
        return result
    }

    private static func lastsAtLeastAsLong(_ parent: FileGrant, as child: FileGrant) -> Bool {
        guard let parentExpiry = parent.expiresAt else { return true }
        guard let childExpiry = child.expiresAt else { return false }
        return parentExpiry >= childExpiry
    }
}
