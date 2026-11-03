public enum ObservedAccess: Hashable, Sendable, Codable {
    case read(String)
    case write(String)
    case exec(String)
    case connectLoopback(Int)
    case connectRemote
    case listen(Int)
}

public struct Observation: Hashable, Sendable {
    public var instance: Int?
    public var access: ObservedAccess
    public var denied: Bool
    public var count: Int

    public init(instance: Int?, access: ObservedAccess, denied: Bool, count: Int = 1) {
        self.instance = instance
        self.access = access
        self.denied = denied
        self.count = count
    }
}

public enum Suggestion: Hashable, Sendable, Codable {
    case template(id: String)
    case file(path: String, kind: PathKind, access: Access)
    case exec(String)
    case loopbackPort(Int)
    case outboundTCP
    case listen
}

public struct PendingItem: Hashable, Sendable, Codable {
    public var suggestion: Suggestion
    public var sensitive: Bool
    public var evidence: Int
    public var samples: [String]

    public init(suggestion: Suggestion, sensitive: Bool, evidence: Int, samples: [String]) {
        self.suggestion = suggestion
        self.sensitive = sensitive
        self.evidence = evidence
        self.samples = samples
    }
}

/// Turns observed accesses that the current policy does not cover into reviewable pending items.
public struct SuggestionEngine: Sendable {
    public var home: String
    public var aggregationThreshold: Int
    public var templates: [Template]
    public var resolver: any PathResolver
    public var caseInsensitive: Bool
    public var foldedPrefixes = ["/System", "/usr/lib", "/usr/share", "/private/var/db/dyld", "/dev", "/Library/Apple"]

    public init(home: String, aggregationThreshold: Int, templates: [Template], resolver: any PathResolver, caseInsensitive: Bool) {
        self.home = home
        self.aggregationThreshold = aggregationThreshold
        self.templates = templates
        self.resolver = resolver
        self.caseInsensitive = caseInsensitive
    }

    private struct PathGrant {
        var path: CanonicalPath
        var kind: PathKind
        var access: Access
    }

    public func pendingItems(observations: [Observation], policy: EffectivePolicy, enabledTemplates: Set<String>) -> [PendingItem] {
        let identity = AliasResolver(aliases: [:])
        let granted = policy.files.compactMap { g in (try? CanonicalPath(g.path, resolver: identity)).map { PathGrant(path: $0, kind: g.kind, access: g.access) } }
        let grantedExec = Set(policy.exec.map(\.path))
        let folded = foldedPrefixes.compactMap { try? CanonicalPath($0, resolver: identity) }
        let candidates = templates.filter { !enabledTemplates.contains($0.id) }.sorted { $0.id < $1.id }

        var templateEvidence: [String: (count: Int, samples: Set<String>)] = [:]
        var files: [String: (path: CanonicalPath, write: Bool, count: Int)] = [:]
        var execs: [String: Int] = [:]
        var ports: [Int: Int] = [:]
        var outbound = 0, listen = 0

        for observation in observations {
            switch observation.access {
            case let .read(raw), let .write(raw):
                let write = { if case .write = observation.access { return true } else { return false } }()
                guard let path = try? CanonicalPath(raw, resolver: resolver) else { continue }
                if folded.contains(where: { $0.contains(path, caseInsensitive: caseInsensitive) }) { continue }
                if covers(granted, path, write: write) { continue }
                if let template = candidates.first(where: { covers(grants(of: $0), path, write: write) }) {
                    templateEvidence[template.id, default: (0, [])].count += observation.count
                    templateEvidence[template.id]?.samples.insert(path.value)
                    continue
                }
                var entry = files[path.value] ?? (path, false, 0)
                entry.write = entry.write || write
                entry.count += observation.count
                files[path.value] = entry
            case let .exec(raw):
                guard let path = try? CanonicalPath(raw, resolver: resolver) else { continue }
                if policy.unrestrictedExec || grantedExec.contains(path.value) { continue }
                if let template = candidates.first(where: { t in t.exec.contains { (try? CanonicalPath($0.path, resolver: resolver))?.value == path.value } }) {
                    templateEvidence[template.id, default: (0, [])].count += observation.count
                    templateEvidence[template.id]?.samples.insert(path.value)
                    continue
                }
                execs[path.value, default: 0] += observation.count
            case let .connectLoopback(port):
                if !policy.network.loopbackTCPConnect.contains(port) { ports[port, default: 0] += observation.count }
            case .connectRemote:
                if policy.network.outboundTCP != .allowed { outbound += observation.count }
            case .listen:
                if policy.network.listen != .allowed { listen += observation.count }
            }
        }

        let sensitive = SensitivePaths(home: home)
        var items: [PendingItem] = templateEvidence.map { id, value in
            PendingItem(suggestion: .template(id: id), sensitive: value.samples.contains(where: sensitive.isSensitive), evidence: value.count, samples: Array(value.samples.sorted().prefix(3)))
        }
        items += aggregate(files, sensitive: sensitive)
        items += execs.map { PendingItem(suggestion: .exec($0.key), sensitive: sensitive.isSensitive($0.key), evidence: $0.value, samples: [$0.key]) }
        items += ports.map { PendingItem(suggestion: .loopbackPort($0.key), sensitive: false, evidence: $0.value, samples: []) }
        if outbound > 0 { items.append(PendingItem(suggestion: .outboundTCP, sensitive: false, evidence: outbound, samples: [])) }
        if listen > 0 { items.append(PendingItem(suggestion: .listen, sensitive: false, evidence: listen, samples: [])) }
        return items.sorted(by: Self.order)
    }

    private func aggregate(_ files: [String: (path: CanonicalPath, write: Bool, count: Int)], sensitive: SensitivePaths) -> [PendingItem] {
        let groups = Dictionary(grouping: files.values) { entry in "/" + entry.path.components.dropLast().joined(separator: "/") }
        return groups.flatMap { parent, entries -> [PendingItem] in
            let paths = entries.map(\.path.value).sorted()
            if entries.count >= aggregationThreshold {
                let access: Access = entries.contains(where: \.write) ? .readWrite : .readOnly
                return [PendingItem(suggestion: .file(path: parent, kind: .directory, access: access), sensitive: sensitive.overlapsSensitive(parent),
                                    evidence: entries.reduce(0) { $0 + $1.count }, samples: Array(paths.prefix(3)))]
            }
            return entries.map { entry in
                PendingItem(suggestion: .file(path: entry.path.value, kind: .file, access: entry.write ? .readWrite : .readOnly),
                            sensitive: sensitive.isSensitive(entry.path.value), evidence: entry.count, samples: [entry.path.value])
            }
        }
    }

    private func grants(of template: Template) -> [PathGrant] {
        template.files.compactMap { g in (try? CanonicalPath(g.path, resolver: resolver)).map { PathGrant(path: $0, kind: g.kind, access: g.access) } }
    }

    private func covers(_ grants: [PathGrant], _ path: CanonicalPath, write: Bool) -> Bool {
        grants.contains { grant in
            guard !write || grant.access == .readWrite else { return false }
            return grant.kind == .directory ? grant.path.contains(path, caseInsensitive: caseInsensitive) : grant.path.isSame(as: path, caseInsensitive: caseInsensitive)
        }
    }

    private static func order(_ a: PendingItem, _ b: PendingItem) -> Bool {
        if a.sensitive != b.sensitive { return a.sensitive }
        let (ra, ka) = rank(a.suggestion), (rb, kb) = rank(b.suggestion)
        return ra != rb ? ra < rb : ka < kb
    }

    private static func rank(_ s: Suggestion) -> (Int, String) {
        switch s {
        case let .template(id): return (0, id)
        case let .file(path, _, _): return (1, path)
        case let .exec(path): return (2, path)
        case let .loopbackPort(port):
            let digits = String(port)
            return (3, String(repeating: "0", count: max(0, 5 - digits.count)) + digits)
        case .outboundTCP: return (4, "")
        case .listen: return (5, "")
        }
    }
}
