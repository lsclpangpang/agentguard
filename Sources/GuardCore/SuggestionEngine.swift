import Foundation

public enum ObservedAccess: Hashable, Sendable, Codable {
    case read(String)
    case write(String)
    case exec(String)
    case connectLoopback(Int)
    case connectRemote
    case listen(Int)
    case unixSocket(path: String, operation: String)
}

public struct Observation: Hashable, Sendable, Codable {
    public var instance: Int?
    public var access: ObservedAccess
    /// True only when the sandbox reported refusing it; an access seen by the collector succeeded.
    public var denied: Bool
    public var count: Int
    public var at: Date?
    /// The original target is independent of the permission category, which deliberately groups
    /// remote connections. Optional fields preserve compatibility with older Helper reports.
    public var networkTarget: String?
    public var processName: String?
    public var pid: Int32?

    public init(instance: Int?, access: ObservedAccess, denied: Bool, count: Int = 1, at: Date? = nil,
                networkTarget: String? = nil, processName: String? = nil, pid: Int32? = nil) {
        self.instance = instance
        self.access = access
        self.denied = denied
        self.count = count
        self.at = at
        self.networkTarget = networkTarget
        self.processName = processName
        self.pid = pid
    }
}

public enum Suggestion: Hashable, Sendable, Codable {
    case template(id: String)
    case file(path: String, kind: PathKind, access: Access)
    case exec(String)
    case loopbackPort(Int)
    case outboundTCP
    case listen
    case systemDNS
}

public struct PendingItem: Hashable, Sendable, Codable {
    public var suggestion: Suggestion
    /// Judged on everything accepting the suggestion would grant, not on the accesses that led to it.
    public var sensitive: Bool
    public var evidence: Int
    public var samples: [String]
    /// How many of the `evidence` accesses the sandbox reported refusing. Zero means none is known
    /// to have been blocked: they were observed succeeding, so the item is only a suggestion.
    public var denied: Int
    public var firstSeen: Date?
    public var lastSeen: Date?
    /// False for items from an older Helper, which did not tell refusals from successes.
    public var refusalKnown: Bool = true

    public init(suggestion: Suggestion, sensitive: Bool, evidence: Int, samples: [String], denied: Int = 0, firstSeen: Date? = nil, lastSeen: Date? = nil) {
        self.suggestion = suggestion
        self.sensitive = sensitive
        self.evidence = evidence
        self.samples = samples
        self.denied = denied
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    /// Blocked accesses are evidence of a refusal; the rest is a suggestion.
    public var wasBlocked: Bool { denied > 0 }
    /// Observed succeeding and never refused: only then may it be described as "not blocked".
    public var isSuggestionOnly: Bool { refusalKnown && denied == 0 }

    enum CodingKeys: String, CodingKey {
        case suggestion, sensitive, evidence, samples, denied, firstSeen, lastSeen
    }

    /// An older Helper reports no denial counts, so whether an item was blocked is unknown.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        suggestion = try c.decode(Suggestion.self, forKey: .suggestion)
        sensitive = try c.decode(Bool.self, forKey: .sensitive)
        evidence = try c.decode(Int.self, forKey: .evidence)
        samples = try c.decode([String].self, forKey: .samples)
        let denied = try c.decodeIfPresent(Int.self, forKey: .denied)
        self.denied = denied ?? 0
        refusalKnown = denied != nil
        firstSeen = try c.decodeIfPresent(Date.self, forKey: .firstSeen)
        lastSeen = try c.decodeIfPresent(Date.self, forKey: .lastSeen)
    }
}

/// Counts of one kind of access: how often, how often refused, and when.
struct Tally {
    var count = 0
    var denied = 0
    var first: Date?
    var last: Date?
    var samples: Set<String> = []

    mutating func add(_ observation: Observation, sample: String? = nil) {
        count += observation.count
        if observation.denied { denied += observation.count }
        if let at = observation.at {
            first = min(first ?? at, at)
            last = max(last ?? at, at)
        }
        if let sample { samples.insert(sample) }
    }

    mutating func merge(_ other: Tally) {
        count += other.count
        denied += other.denied
        if let at = other.first { first = min(first ?? at, at) }
        if let at = other.last { last = max(last ?? at, at) }
        samples.formUnion(other.samples)
    }

    func item(_ suggestion: Suggestion, sensitive: Bool, samples: [String]? = nil) -> PendingItem {
        PendingItem(suggestion: suggestion, sensitive: sensitive, evidence: count, samples: samples ?? Array(self.samples.sorted().prefix(3)),
                    denied: denied, firstSeen: first, lastSeen: last)
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
        let patterns = policy.patterns.compactMap { g in (try? PathPattern(g.pattern, resolver: identity)).map { (pattern: $0, grant: g) } }
        let grantedExec = Set(policy.exec.map(\.path))
        let folded = foldedPrefixes.compactMap { try? CanonicalPath($0, resolver: identity) }
        let candidates = templates.filter { !enabledTemplates.contains($0.id) }.sorted { $0.id < $1.id }

        var templateEvidence: [String: Tally] = [:]
        var files: [String: (path: CanonicalPath, write: Bool, tally: Tally)] = [:]
        var execs: [String: Tally] = [:]
        var ports: [Int: Tally] = [:]
        var outbound = Tally(), listen = Tally(), systemDNS = Tally()

        for observation in observations {
            switch observation.access {
            case let .read(raw), let .write(raw):
                let write = { if case .write = observation.access { return true } else { return false } }()
                guard let path = try? CanonicalPath(raw, resolver: resolver) else { continue }
                if folded.contains(where: { $0.contains(path, caseInsensitive: caseInsensitive) }) { continue }
                if covers(granted, path, write: write) { continue }
                if patterns.contains(where: { entry in
                    (!write || entry.grant.access == .readWrite) && (entry.grant.kind == .directory
                        ? entry.pattern.mayCover(path, caseInsensitive: caseInsensitive)
                        : entry.pattern.matches(path, caseInsensitive: caseInsensitive))
                }) { continue }
                if let template = candidates.first(where: { covers(grants(of: $0), path, write: write) }) {
                    templateEvidence[template.id, default: Tally()].add(observation, sample: path.value)
                    continue
                }
                var entry = files[path.value] ?? (path, false, Tally())
                entry.write = entry.write || write
                entry.tally.add(observation)
                files[path.value] = entry
            case let .exec(raw):
                guard let path = try? CanonicalPath(raw, resolver: resolver) else { continue }
                if policy.unrestrictedExec || grantedExec.contains(path.value) { continue }
                if let template = candidates.first(where: { t in t.exec.contains { (try? CanonicalPath($0.path, resolver: resolver))?.value == path.value } }) {
                    templateEvidence[template.id, default: Tally()].add(observation, sample: path.value)
                    continue
                }
                execs[path.value, default: Tally()].add(observation)
            case let .connectLoopback(port):
                // UDP has no equivalent TCP grant. Keep it in recent accesses without proposing
                // an unrelated TCP permission.
                if observation.networkEndpoint?.transport == "UDP" { continue }
                if !policy.network.loopbackTCPConnect.contains(port) {
                    ports[port, default: Tally()].add(observation, sample: observation.networkTarget)
                }
            case .connectRemote:
                if observation.networkEndpoint?.transport == "UDP" { continue }
                if policy.network.outboundTCP != .allowed { outbound.add(observation, sample: observation.networkTarget) }
            case .listen:
                if observation.networkEndpoint?.transport == "UDP" { continue }
                if policy.network.listen != .allowed { listen.add(observation, sample: observation.networkTarget) }
            case let .unixSocket(path, operation):
                // Only this known service gets a scoped suggestion. Other sockets must never
                // turn into a file grant or a general TCP/network grant.
                if SystemDNS.matches(path: path, operation: operation), policy.network.systemDNS != .allowed {
                    systemDNS.add(observation, sample: SystemDNS.socketPath)
                }
            }
        }

        let sensitive = SensitivePaths(home: home)
        let byID = Dictionary(templates.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var items: [PendingItem] = templateEvidence.map { id, tally in
            // Enabling a template grants all of it, so its sensitivity is that of every grant it holds.
            tally.item(.template(id: id), sensitive: byID[id].map { templateIsSensitive($0, sensitive) } ?? true)
        }
        items += aggregate(files, sensitive: sensitive)
        items += execs.map { $0.value.item(.exec($0.key), sensitive: sensitive.isSensitive($0.key), samples: [$0.key]) }
        items += ports.map { $0.value.item(.loopbackPort($0.key), sensitive: false) }
        if outbound.count > 0 { items.append(outbound.item(.outboundTCP, sensitive: false)) }
        if listen.count > 0 { items.append(listen.item(.listen, sensitive: false)) }
        if systemDNS.count > 0 { items.append(systemDNS.item(.systemDNS, sensitive: false)) }
        return items.sorted(by: Self.order)
    }

    private func templateIsSensitive(_ template: Template, _ sensitive: SensitivePaths) -> Bool {
        template.files.contains { grant in
            grant.readsSecrets || (grant.kind == .directory ? sensitive.overlapsSensitive(grant.path) : sensitive.isSensitive(grant.path))
        }
    }

    private func aggregate(_ files: [String: (path: CanonicalPath, write: Bool, tally: Tally)], sensitive: SensitivePaths) -> [PendingItem] {
        let groups = Dictionary(grouping: files.values) { entry in "/" + entry.path.components.dropLast().joined(separator: "/") }
        return groups.flatMap { parent, entries -> [PendingItem] in
            let paths = entries.map(\.path.value).sorted()
            // 临时目录里的文件名天然易变（xcrun_db-5AiXeqnE、claude-501/tmp-XXXX 之类），
            // 逐条建议既没法批准、批准了也立刻过期，所以一律按目录聚合，不受阈值限制。
            if entries.count >= aggregationThreshold || isUnderTemporaryRoot(parent) {
                let access: Access = entries.contains(where: \.write) ? .readWrite : .readOnly
                var total = Tally()
                for entry in entries { total.merge(entry.tally) }
                return [total.item(.file(path: parent, kind: .directory, access: access), sensitive: sensitive.overlapsSensitive(parent),
                                   samples: Array(paths.prefix(3)))]
            }
            return entries.map { entry in
                entry.tally.item(.file(path: entry.path.value, kind: .file, access: entry.write ? .readWrite : .readOnly),
                                 sensitive: sensitive.isSensitive(entry.path.value), samples: [entry.path.value])
            }
        }
    }

    /// `/private/tmp`、`/tmp` 以及 `$TMPDIR`（`/private/var/folders/<x>/<y>/T`）。
    private func isUnderTemporaryRoot(_ path: String) -> Bool {
        for root in ["/private/tmp", "/tmp"] where path == root || path.hasPrefix(root + "/") { return true }
        let parts = path.split(separator: "/")
        return parts.count >= 6 && parts[0] == "private" && parts[1] == "var" && parts[2] == "folders" && parts[5] == "T"
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
        case .systemDNS: return (6, "")
        }
    }
}
