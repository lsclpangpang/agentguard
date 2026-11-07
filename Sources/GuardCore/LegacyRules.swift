/// A migrated `(allow ...)` rule that grants file access, reduced to what it reaches.
public struct LegacyFileRule: Equatable, Sendable {
    public enum Match: Equatable, Sendable {
        case subpath(CanonicalPath)
        case literal(CanonicalPath)
        /// String prefix: `(prefix "/a/b")` also matches `/a/bc`.
        case prefix(String)
    }

    public var rule: String
    public var access: Access
    public var matches: [Match]
}

/// Sorts verbatim legacy rules into file rules whose reach can be compared with paths, rules that
/// are not about files, and rules nobody can vouch for (regular expressions, unknown filters).
///
/// Legacy rules are rendered after every structured grant, so a legacy write rule silently keeps a
/// path writable after the user set it to read-only. Edits use this to say so, or to drop the rule.
public struct LegacyRuleAnalysis: Equatable, Sendable {
    public private(set) var fileRules: [LegacyFileRule] = []
    /// File rules whose reach cannot be determined; their effect on any path is unknown.
    public private(set) var unverified: [String] = []
    public private(set) var other: [String] = []
    /// Non-file effects are not interpreted as structured settings. Keep their uncertainty visible,
    /// including rules combining file and non-file operations.
    public private(set) var networkRules: [String] = []
    public private(set) var execRules: [String] = []
    private let caseInsensitive: Bool

    public init(rules: [String], resolver: any PathResolver, caseInsensitive: Bool) {
        self.caseInsensitive = caseInsensitive
        for rule in rules {
            if Self.mayGrant(rule, operation: "network") { networkRules.append(rule) }
            if Self.mayGrant(rule, operation: "process-exec") { execRules.append(rule) }
            switch Self.classify(rule, resolver: resolver) {
            case let .file(access, matches): fileRules.append(LegacyFileRule(rule: rule, access: access, matches: matches))
            case .other: other.append(rule)
            case .unverified: unverified.append(rule)
            }
        }
    }

    public var hasUnverifiedFileRules: Bool { !unverified.isEmpty }
    public var unverifiedPermissions: [String] { Array(Set(unverified + other + networkRules + execRules)).sorted() }

    private static func mayGrant(_ rule: String, operation: String) -> Bool {
        guard case let .list(items)? = SExpression.parse(rule), items.first == .atom("allow") else { return true }
        return items.dropFirst().contains {
            guard case let .atom(name) = $0 else { return false }
            return name == "default" || name == "*" || name.hasPrefix(operation)
                || (operation == "process-exec" && name == "process*")
        }
    }

    /// Narrowing a structured switch cannot revoke a verbatim rule. Name retained rules in the
    /// change confirmation; removing them explicitly remains a separately reviewable change.
    public static func revocationWarnings(from before: Profile, to after: Profile, environment: CompileEnvironment) -> [String] {
        let remaining = LegacyRuleAnalysis(rules: after.extraRules, resolver: environment.resolver,
                                           caseInsensitive: environment.caseInsensitive)
        let a = before.network, b = after.network
        let narrowsNetwork = (a.outboundTCP == .allowed && b.outboundTCP == .denied)
            || (a.listen == .allowed && b.listen == .denied) || (a.udp == .allowed && b.udp == .denied)
            || !Set(a.loopbackTCPConnect).isSubset(of: Set(b.loopbackTCPConnect))
        let narrowsExec = (before.unrestrictedExec && !after.unrestrictedExec)
            || !Set(before.exec).isSubset(of: Set(after.exec))
            || !Set(before.programs).isSubset(of: Set(after.programs))
        var warnings: [String] = []
        if narrowsNetwork && !remaining.networkRules.isEmpty {
            warnings += ["注意：以下旧规则仍可能允许网络访问，关闭开关不能保证收回："] + remaining.networkRules
        }
        if narrowsExec && !remaining.execRules.isEmpty {
            warnings += ["注意：以下旧规则仍可能允许运行程序，删除列表项不能保证收回："] + remaining.execRules
        }
        if (narrowsNetwork || narrowsExec) && !environment.baseRules.isEmpty {
            warnings.append("系统基础规则的访问范围尚未逐项核对；这次修改只收回所列显式授权。")
        }
        return warnings
    }

    /// Rules granting at least `access` only at `path` itself or below it: every filter is within.
    /// Removing them is part of revoking `path`; they reach nothing the user did not ask to revoke.
    public func rulesWithin(_ path: CanonicalPath, access: Access) -> [String] {
        fileRules.filter { rule in
            rule.access >= access && rule.matches.allSatisfy { isWithin($0, path) }
        }.map(\.rule)
    }

    /// Rules granting at least `access` at `path` that an edit of `path` cannot drop without
    /// revoking more than asked: they reach it from above, or also reach places outside it.
    public func rulesAbove(_ path: CanonicalPath, access: Access) -> [String] {
        fileRules.filter { rule in
            guard rule.access >= access, !rule.matches.allSatisfy({ isWithin($0, path) }) else { return false }
            return rule.matches.contains { isWithin($0, path) || isAbove($0, path) }
        }.map(\.rule)
    }

    private func isWithin(_ match: LegacyFileRule.Match, _ path: CanonicalPath) -> Bool {
        switch match {
        case let .subpath(p), let .literal(p): return path.contains(p, caseInsensitive: caseInsensitive)
        // A prefix equal to the path also reaches its siblings (`/a/b` matches `/a/bc`), so it is not within.
        case let .prefix(text): return text.lowercasedIf(caseInsensitive).hasPrefix(Self.directoryPrefix(path).lowercasedIf(caseInsensitive))
        }
    }

    private func isAbove(_ match: LegacyFileRule.Match, _ path: CanonicalPath) -> Bool {
        switch match {
        case let .subpath(p): return p.contains(path, caseInsensitive: caseInsensitive)
        case .literal: return false
        case let .prefix(text): return path.value.lowercasedIf(caseInsensitive).hasPrefix(text.lowercasedIf(caseInsensitive))
        }
    }

    private static func directoryPrefix(_ path: CanonicalPath) -> String {
        path.isRoot ? "/" : path.value + "/"
    }

    private enum Classification {
        case file(Access, [LegacyFileRule.Match])
        case other
        case unverified
    }

    private static func classify(_ rule: String, resolver: any PathResolver) -> Classification {
        guard let form = SExpression.parse(rule), case let .list(items) = form, items.first == .atom("allow") else { return .unverified }
        var operations: [String] = []
        var filters: [SExpression] = []
        for item in items.dropFirst() {
            switch item {
            case let .atom(name): operations.append(name)
            case .list: filters.append(item)
            case .string: return .unverified
            }
        }
        // Only operations on contents count as access; metadata, ioctl, mapping and the like do not.
        let fileOperations = operations.filter { $0 == "file*" || $0 == "file-read*" || $0 == "file-read-data" || $0.hasPrefix("file-write") }
        guard !fileOperations.isEmpty else { return operations.isEmpty ? .unverified : .other }
        let access: Access = fileOperations.contains { $0 == "file*" || $0.hasPrefix("file-write") } ? .readWrite : .readOnly
        guard let root = try? CanonicalPath("/", resolver: resolver) else { return .unverified }
        // A file operation without a filter applies everywhere.
        guard !filters.isEmpty else { return .file(access, [.subpath(root)]) }
        var matches: [LegacyFileRule.Match] = []
        for filter in filters {
            guard case let .list(parts) = filter, parts.count == 2, case let .atom(kind) = parts[0], case let .string(text) = parts[1]
            else { return .unverified }
            switch kind {
            case "subpath", "literal":
                guard let path = try? CanonicalPath(text, resolver: resolver) else { return .unverified }
                matches.append(kind == "subpath" ? .subpath(path) : .literal(path))
            case "prefix":
                guard text.hasPrefix("/") else { return .unverified }
                matches.append(.prefix(resolver.resolve(text)))
            default:
                return .unverified
            }
        }
        return .file(access, matches)
    }
}

/// What revoking access to one path does to the verbatim legacy rules.
public struct LegacyRevocation: Equatable, Sendable {
    /// The legacy rules to keep.
    public var extraRules: [String]
    /// Rules at or below the path, dropped as part of this revocation.
    public var removed: [String]
    /// Rules that will still grant the revoked access afterwards, or might: rules above the path
    /// and rules whose reach is unknown. While any remain, the revocation must not be shown as done.
    public var stillGranting: [String]

    /// `remaining` is the access the path keeps: read-only after a downgrade, nil when removed.
    public static func revoke(_ path: String, keeping remaining: Access?, from rules: [String],
                              resolver: any PathResolver, caseInsensitive: Bool) throws -> LegacyRevocation {
        let canonical = try CanonicalPath(path, resolver: resolver)
        let analysis = LegacyRuleAnalysis(rules: rules, resolver: resolver, caseInsensitive: caseInsensitive)
        // Removing a path revokes any access; downgrading revokes only writing.
        let revoked: Access = remaining == nil ? .readOnly : .readWrite
        let removed = Set(analysis.rulesWithin(canonical, access: revoked))
        return LegacyRevocation(extraRules: rules.filter { !removed.contains($0) },
                                removed: rules.filter { removed.contains($0) },
                                stillGranting: analysis.rulesAbove(canonical, access: revoked) + analysis.unverified)
    }
}

private extension String {
    func lowercasedIf(_ condition: Bool) -> String { condition ? lowercased() : self }
}

/// Just enough of SBPL's reader for one-line rules: lists, atoms and double-quoted strings.
/// `#"..."` regex literals are read as atoms, so any filter using one stays unverified.
enum SExpression: Equatable {
    case atom(String)
    case string(String)
    case list([SExpression])

    static func parse(_ text: String) -> SExpression? {
        var reader = Reader(chars: Array(text))
        guard let form = reader.read() else { return nil }
        reader.skipSpace()
        return reader.atEnd ? form : nil
    }

    private struct Reader {
        let chars: [Character]
        var index = 0

        var atEnd: Bool { index >= chars.count }

        mutating func skipSpace() {
            while !atEnd, chars[index].isWhitespace { index += 1 }
        }

        mutating func read() -> SExpression? {
            skipSpace()
            guard !atEnd else { return nil }
            switch chars[index] {
            case "(":
                index += 1
                var items: [SExpression] = []
                while true {
                    skipSpace()
                    guard !atEnd else { return nil }
                    if chars[index] == ")" { index += 1; return .list(items) }
                    guard let item = read() else { return nil }
                    items.append(item)
                }
            case ")":
                return nil
            case "\"":
                index += 1
                var value = ""
                while !atEnd {
                    let c = chars[index]
                    index += 1
                    if c == "\"" { return .string(value) }
                    if c == "\\" {
                        guard !atEnd else { return nil }
                        value.append(chars[index])
                        index += 1
                    } else {
                        value.append(c)
                    }
                }
                return nil
            default:
                var value = ""
                while !atEnd, !chars[index].isWhitespace, chars[index] != "(", chars[index] != ")" {
                    // Keep a regex literal's quoted body inside the atom.
                    if chars[index] == "\"" {
                        value.append(chars[index]); index += 1
                        while !atEnd, chars[index] != "\"" {
                            if chars[index] == "\\", index + 1 < chars.count { value.append(chars[index]); index += 1 }
                            value.append(chars[index]); index += 1
                        }
                        guard !atEnd else { return nil }
                    }
                    value.append(chars[index])
                    index += 1
                }
                return .atom(value)
            }
        }
    }
}
