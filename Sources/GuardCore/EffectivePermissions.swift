/// Where one permission of a profile comes from.
public enum PermissionSource: Hashable, Sendable {
    /// Added by the user in the profile itself.
    case user
    /// Part of an enabled runtime template.
    case template(String)
    /// Granted automatically so a managed program or the launch executable can start.
    case program
    /// The profile's private working directory under the state root.
    case stateDirectory
    /// A verbatim rule carried over from a migrated installation.
    case legacy(String)
}

/// One file grant together with its source. `path` is the canonical path, the pattern text for a
/// wildcard grant, or the raw prefix of a legacy `(prefix ...)` filter.
public struct SourcedFileGrant: Hashable, Sendable {
    public var source: PermissionSource
    public var path: String
    public var kind: PathKind
    public var access: Access
    public var pattern: Bool
    public var readsSecrets: Bool

    public init(source: PermissionSource, path: String, kind: PathKind, access: Access, pattern: Bool = false, readsSecrets: Bool = false) {
        self.source = source
        self.path = path
        self.kind = kind
        self.access = access
        self.pattern = pattern
        self.readsSecrets = readsSecrets
    }
}

/// Everything that grants access at one location.
public struct PermissionEntry: Hashable, Sendable {
    public var path: String
    public var kind: PathKind
    public var pattern: Bool
    /// Grants for exactly this location.
    public var sources: [SourcedFileGrant]
    /// Broader directory grants whose reach includes this location.
    public var inherited: [SourcedFileGrant]
    /// Grants reaching some matching locations; these do not prove the whole entry redundant.
    public var overlapping: [SourcedFileGrant] = []

    /// Widest known access anywhere in this entry, including partial overlaps.
    public var access: Access { (sources + inherited + overlapping).map(\.access).max() ?? .readOnly }
    public var ownAccess: Access { sources.map(\.access).max() ?? .readOnly }
    public var readsSecrets: Bool { (sources + inherited + overlapping).contains(where: \.readsSecrets) }
    /// A broader grant already allows at least as much, so removing this entry alone changes nothing.
    public var redundant: Bool { inherited.contains { $0.access >= ownAccess } }
}

public struct ExecPermission: Hashable, Sendable {
    public var path: String
    public var sources: [PermissionSource]
}

public struct PortPermission: Hashable, Sendable {
    public var port: Int
    public var sources: [PermissionSource]
}

/// The permissions a profile actually grants, merged from the user's grants, enabled templates,
/// the automatic grants and migrated rules, each with its source and overlaps.
public struct PermissionOverview: Hashable, Sendable {
    public var files: [PermissionEntry]
    public var exec: [ExecPermission]
    public var ports: [PortPermission]
    /// Structured settings; `unverifiedNetwork` / `unverifiedExec` prevent interpreting these as
    /// exhaustive when raw rules or system imports may grant additional rights.
    public var network: NetworkPolicy
    public var unrestrictedExec: Bool
    /// Migrated rules whose complete effects are not represented by this overview.
    public var unverifiedLegacy: [String]
    public var unverifiedBaseRules: [String] = []
    public var unverifiedNetwork: [String] = []
    public var unverifiedExec: [String] = []

    /// Only a complete overview may be presented as "this is everything the program can access".
    public var complete: Bool { unverifiedLegacy.isEmpty && unverifiedBaseRules.isEmpty }
}

/// What revoking access at one location leaves in place.
public struct RevocationCheck: Equatable, Sendable {
    /// The user's other grants that reach only inside the location; a full revocation changes them along with it.
    public var innerUserGrants: [FileGrant]
    /// The user's other grants that reach the location from above or also elsewhere; changing them
    /// would revoke more than asked, so they are only named.
    public var outerUserGrants: [FileGrant]
    /// Grants the user cannot change from the file list: templates, automatic grants.
    public var fixed: [SourcedFileGrant]
    public var unverifiedRules: [String] = []

    /// True when nothing but the inner grants (handled with the change) keeps the access.
    public var isComplete: Bool { fixed.isEmpty && outerUserGrants.isEmpty && unverifiedRules.isEmpty }
}

public enum EffectivePermissions {
    public static func overview(of profile: Profile, templates: [Template], environment: CompileEnvironment) -> PermissionOverview {
        let resolver = environment.resolver, ci = environment.caseInsensitive
        let grants = sourcedGrants(of: profile, templates: templates, environment: environment)
        let legacy = LegacyRuleAnalysis(rules: profile.extraRules, resolver: resolver, caseInsensitive: ci)

        // Group by location; a pattern or a prefix is its own location.
        var order: [String] = []
        var byKey: [String: [SourcedFileGrant]] = [:]
        for grant in grants {
            let key = (grant.pattern ? "*" : "") + (ci ? grant.path.lowercased() : grant.path)
            if byKey[key] == nil { order.append(key) }
            byKey[key, default: []].append(grant)
        }
        let plain = grants.filter { !$0.pattern }.compactMap { g in (try? CanonicalPath(g.path, resolver: identity)).map { (g, $0) } }
        var files: [PermissionEntry] = order.map { key in
            let sources = byKey[key] ?? []
            let first = sources[0]
            let kind: PathKind = sources.contains { $0.kind == .directory } ? .directory : .file
            var inherited: [SourcedFileGrant] = []
            if !first.pattern, let here = try? CanonicalPath(first.path, resolver: identity) {
                inherited = plain.filter { grant, path in
                    grant.kind == .directory && !path.isSame(as: here, caseInsensitive: ci) && path.contains(here, caseInsensitive: ci)
                }.map(\.0)
                inherited += patternGrants(in: grants).filter { grant, pattern in
                    pattern.covers(here, kind: grant.kind, caseInsensitive: ci)
                }.map(\.0)
                // A legacy string prefix reaches every path that starts with it.
                inherited += grants.filter { grant in
                    guard isLegacyPrefix(grant), grant.path != first.path else { return false }
                    let prefix = String(grant.path.dropLast())
                    return ci ? here.value.lowercased().hasPrefix(prefix.lowercased()) : here.value.hasPrefix(prefix)
                }
            }
            var overlapping: [SourcedFileGrant] = []
            if first.pattern, let target = try? PathPattern(first.path, resolver: identity) {
                for grant in grants where !sources.contains(grant) {
                    if !grant.pattern, grant.kind == .directory, let path = try? CanonicalPath(grant.path, resolver: identity),
                       path.contains(target.base, caseInsensitive: ci) {
                        inherited.append(grant)
                    } else if overlaps(grant, target: target, kind: kind, environment: environment) {
                        overlapping.append(grant)
                    }
                }
            }
            return PermissionEntry(path: first.path, kind: kind, pattern: first.pattern, sources: sources,
                                   inherited: inherited, overlapping: overlapping)
        }
        files.sort { ($0.path, $0.pattern ? 1 : 0) < ($1.path, $1.pattern ? 1 : 0) }

        var exec: [String: [PermissionSource]] = [:]
        func addExec(_ raw: String, _ source: PermissionSource) {
            let path = (try? CanonicalPath(raw, resolver: resolver))?.value ?? raw
            if !(exec[path]?.contains(source) ?? false) { exec[path, default: []].append(source) }
        }
        profile.exec.forEach { addExec($0.path, .user) }
        for template in enabled(templates, in: profile) { template.exec.forEach { addExec($0.path, .template(template.id)) } }
        (profile.programs + (profile.launch.map { [$0.executable] } ?? [])).forEach { addExec($0, .program) }

        var ports: [Int: [PermissionSource]] = [:]
        for port in profile.network.loopbackTCPConnect where !(ports[port]?.contains(.user) ?? false) { ports[port, default: []].append(.user) }
        for template in enabled(templates, in: profile) {
            for port in template.loopbackPorts where !(ports[port]?.contains(.template(template.id)) ?? false) {
                ports[port, default: []].append(.template(template.id))
            }
        }

        return PermissionOverview(
            files: files,
            exec: exec.map { ExecPermission(path: $0.key, sources: $0.value) }.sorted { $0.path < $1.path },
            ports: ports.map { PortPermission(port: $0.key, sources: $0.value) }.sorted { $0.port < $1.port },
            network: profile.network,
            unrestrictedExec: profile.unrestrictedExec,
            unverifiedLegacy: legacy.unverifiedPermissions,
            unverifiedBaseRules: environment.baseRules,
            unverifiedNetwork: legacy.networkRules + environment.baseRules,
            unverifiedExec: legacy.execRules + environment.baseRules
        )
    }

    /// Grants other than `excluded` (legacy rules for literal paths use `LegacyRevocation`)
    /// that keep access at `path` or inside it after the change. Revoking write (`keeping: .readOnly`)
    /// only counts writable grants; revoking all access (`keeping: nil`) counts every grant.
    public static func remaining(at path: String, kind: PathKind, keeping access: Access?, excluding excluded: FileGrant,
                                 in profile: Profile, templates: [Template], environment: CompileEnvironment) throws -> RevocationCheck {
        if excluded.pattern {
            let target = try PathPattern(path, resolver: environment.resolver)
            let revoked: Access = access == .readOnly ? .readWrite : .readOnly
            let grants = sourcedGrants(of: profile, templates: templates, environment: environment)
            let outer = profile.files.filter { grant in
                guard grant != excluded, grant.access >= revoked else { return false }
                let canonical = grant.pattern
                    ? (try? PathPattern(grant.path, resolver: environment.resolver))?.value
                    : (try? CanonicalPath(grant.path, resolver: environment.resolver))?.value
                guard let canonical else { return true }
                return overlaps(SourcedFileGrant(source: .user, path: canonical, kind: grant.kind, access: grant.access,
                                                 pattern: grant.pattern), target: target, kind: kind, environment: environment)
            }
            let fixed = grants.filter {
                $0.source != .user && $0.access >= revoked && overlaps($0, target: target, kind: kind, environment: environment)
            }
            let legacy = LegacyRuleAnalysis(rules: profile.extraRules, resolver: environment.resolver, caseInsensitive: environment.caseInsensitive)
            return RevocationCheck(innerUserGrants: [], outerUserGrants: outer, fixed: fixed,
                                   unverifiedRules: legacy.unverified)
        }
        let area = try CanonicalPath(path, resolver: environment.resolver)
        let revoked: Access = access == .readOnly ? .readWrite : .readOnly
        var inner: [FileGrant] = [], outer: [FileGrant] = []
        for grant in profile.files where grant != excluded && grant.access >= revoked {
            guard reaches(grant.path, kind: grant.kind, pattern: grant.pattern, into: area, areaKind: kind, environment: environment) else { continue }
            if kind == .directory && isInside(grant, area, environment: environment) { inner.append(grant) } else { outer.append(grant) }
        }
        let fixed = sourcedGrants(of: profile, templates: templates, environment: environment).filter { grant in
            switch grant.source {
            case .user, .legacy: return false
            default: break
            }
            return grant.access >= revoked && reaches(grant.path, kind: grant.kind, pattern: grant.pattern, into: area, areaKind: kind,
                                                       environment: environment, resolved: true)
        }
        return RevocationCheck(innerUserGrants: inner, outerUserGrants: outer, fixed: fixed)
    }

    // MARK: Building blocks

    /// Paths here are already canonical; re-resolving them must not change them.
    private static let identity = AliasResolver(aliases: [:])

    private static func overlaps(_ grant: SourcedFileGrant, target: PathPattern, kind: PathKind,
                                 environment: CompileEnvironment) -> Bool {
        // Legacy string prefixes are not glob components; retain uncertainty rather than
        // accidentally excluding their cross-directory reach.
        if isLegacyPrefix(grant) { return true }
        if grant.pattern {
            guard let pattern = try? PathPattern(grant.path, resolver: identity) else { return true }
            return target.overlaps(pattern, kind: kind, otherKind: grant.kind, caseInsensitive: environment.caseInsensitive)
        }
        guard let path = try? CanonicalPath(grant.path, resolver: identity) else { return true }
        return grant.kind == .directory
            ? target.mayReachInside(path, kind: kind, caseInsensitive: environment.caseInsensitive)
            : target.covers(path, kind: kind, caseInsensitive: environment.caseInsensitive)
    }

    static func enabled(_ templates: [Template], in profile: Profile) -> [Template] {
        let byID = Dictionary(templates.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return profile.templates.sorted { $0.id < $1.id }.compactMap { byID[$0.id] }
    }

    static func sourcedGrants(of profile: Profile, templates: [Template], environment: CompileEnvironment) -> [SourcedFileGrant] {
        let resolver = environment.resolver
        func canonical(_ grant: FileGrant, _ source: PermissionSource) -> SourcedFileGrant {
            let path: String
            if grant.pattern {
                path = (try? PathPattern(grant.path, resolver: resolver))?.value ?? grant.path
            } else {
                path = (try? CanonicalPath(grant.path, resolver: resolver))?.value ?? grant.path
            }
            return SourcedFileGrant(source: source, path: path, kind: grant.kind, access: grant.access, pattern: grant.pattern,
                                    readsSecrets: grant.readsSecrets)
        }
        var result = profile.files.map { canonical($0, .user) }
        for template in enabled(templates, in: profile) {
            result += template.files.map { canonical($0, .template(template.id)) }
        }
        if let root = environment.stateRoot {
            result.append(canonical(FileGrant(path: root + "/" + profile.id, kind: .directory, access: .readWrite), .stateDirectory))
        }
        for program in profile.programs + (profile.launch.map { [$0.executable] } ?? []) {
            result.append(canonical(FileGrant(path: program, kind: .file, access: .readOnly), .program))
        }
        let legacy = LegacyRuleAnalysis(rules: profile.extraRules, resolver: resolver, caseInsensitive: environment.caseInsensitive)
        for rule in legacy.fileRules {
            for match in rule.matches {
                switch match {
                case let .subpath(path):
                    result.append(SourcedFileGrant(source: .legacy(rule.rule), path: path.value, kind: .directory, access: rule.access))
                case let .literal(path):
                    result.append(SourcedFileGrant(source: .legacy(rule.rule), path: path.value, kind: .file, access: rule.access))
                case let .prefix(text):
                    // A string prefix is shown as written; it reaches every path starting with it.
                    result.append(SourcedFileGrant(source: .legacy(rule.rule), path: text + "*", kind: .directory, access: rule.access, pattern: true))
                }
            }
        }
        return result
    }

    private static func patternGrants(in grants: [SourcedFileGrant]) -> [(SourcedFileGrant, PathPattern)] {
        grants.filter { $0.pattern && !isLegacyPrefix($0) }.compactMap { g in (try? PathPattern(g.path, resolver: identity)).map { (g, $0) } }
    }

    private static func isLegacyPrefix(_ grant: SourcedFileGrant) -> Bool {
        if case .legacy = grant.source { return grant.pattern }
        return false
    }

    /// True when everything the grant reaches lies strictly inside `area`.
    private static func isInside(_ grant: FileGrant, _ area: CanonicalPath, environment: CompileEnvironment) -> Bool {
        let ci = environment.caseInsensitive
        if grant.pattern {
            guard let pattern = try? PathPattern(grant.path, resolver: environment.resolver) else { return false }
            return area.contains(pattern.base, caseInsensitive: ci) && !(pattern.base.isSame(as: area, caseInsensitive: ci) && pattern.rest.allSatisfy { $0 == "**" })
        }
        guard let path = try? CanonicalPath(grant.path, resolver: environment.resolver) else { return false }
        return area.contains(path, caseInsensitive: ci) && !path.isSame(as: area, caseInsensitive: ci)
    }

    /// True when a grant reaches `area` itself or, for a directory area, anything inside it.
    private static func reaches(_ raw: String, kind: PathKind, pattern: Bool, into area: CanonicalPath, areaKind: PathKind,
                                environment: CompileEnvironment, resolved: Bool = false) -> Bool {
        let ci = environment.caseInsensitive
        let resolver: any PathResolver = resolved ? identity : environment.resolver
        if pattern {
            guard let pattern = try? PathPattern(raw, resolver: resolver) else { return false }
            return areaKind == .directory ? pattern.mayReachInside(area, kind: kind, caseInsensitive: ci)
                : pattern.covers(area, kind: kind, caseInsensitive: ci)
        }
        guard let path = try? CanonicalPath(raw, resolver: resolver) else { return false }
        if kind == .directory && path.contains(area, caseInsensitive: ci) { return true }
        return areaKind == .directory ? area.contains(path, caseInsensitive: ci) : path.isSame(as: area, caseInsensitive: ci)
    }
}
