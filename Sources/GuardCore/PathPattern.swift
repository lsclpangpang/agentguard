import Foundation

public enum PatternError: Error, Equatable, Sendable {
    case path(PathError)
    /// The text has no `*`, `?` or `**`; it should be added as an ordinary path.
    case noWildcard(String)
    /// `**` must be a whole component, and a component cannot contain `"` or a line break.
    case invalidComponent(String)
    /// A wildcard right below `/` or the home directory would reach nearly everything there.
    case tooBroad(String)
}

/// A path with shell-style wildcards: `*` matches any run of characters within one component, `?`
/// one character, and a component that is exactly `**` any number of directories (including none).
///
/// Everything before the first wildcard is canonicalized like an ordinary grant, so `/tmp/*.log`
/// becomes `/private/tmp/*.log`. Matching is on the path the kernel sees; components after the
/// first wildcard are not resolved, so a symlink there is not followed.
public struct PathPattern: Hashable, Sendable, CustomStringConvertible {
    /// The part before the first wildcard component.
    public let base: CanonicalPath
    /// The first wildcard component and everything after it, as written.
    public let rest: [String]

    public init(_ raw: String, resolver: any PathResolver) throws {
        guard !raw.contains("\""), !raw.contains("\n"), !raw.contains("\r") else { throw PatternError.invalidComponent(raw) }
        let normalized: CanonicalPath
        do { normalized = try CanonicalPath(raw, resolver: AliasResolver(aliases: [:])) } catch let error as PathError { throw PatternError.path(error) }
        let components = normalized.components
        guard let first = components.firstIndex(where: Self.isWildcard) else { throw PatternError.noWildcard(raw) }
        for component in components[first...] where component.contains("**") && component != "**" {
            throw PatternError.invalidComponent(component)
        }
        do {
            base = try CanonicalPath("/" + components[..<first].joined(separator: "/"), resolver: resolver)
        } catch let error as PathError {
            throw PatternError.path(error)
        }
        rest = Array(components[first...])
    }

    public var value: String { (base.isRoot ? "" : base.value) + "/" + rest.joined(separator: "/") }

    public var description: String { value }

    var components: [String] { base.components + rest }

    static func isWildcard(_ component: String) -> Bool {
        component.contains("*") || component.contains("?")
    }

    /// Refuses patterns whose first wildcard component is nothing but wildcards directly below `/`
    /// or `home`: `~/*` would cover every file there, secrets included.
    public func validateBreadth(home: CanonicalPath, caseInsensitive: Bool) throws {
        let onlyWildcards = rest[0].allSatisfy { $0 == "*" || $0 == "?" }
        if onlyWildcards && (base.isRoot || base.isSame(as: home, caseInsensitive: caseInsensitive)) || base.isRoot && rest[0] == "**" {
            throw PatternError.tooBroad(value)
        }
    }

    /// True when the grant covers `path` itself: a match, or for a directory-kind grant a match or
    /// anything below one.
    public func covers(_ path: CanonicalPath, kind: PathKind, caseInsensitive: Bool) -> Bool {
        kind == .directory ? mayCover(path, caseInsensitive: caseInsensitive) : matches(path, caseInsensitive: caseInsensitive)
    }

    /// True when `path` itself matches.
    public func matches(_ path: CanonicalPath, caseInsensitive: Bool) -> Bool {
        Self.match(components[...], path.components[...], caseInsensitive: caseInsensitive, prefixOnly: false)
    }

    /// True when some path covered by the grant lies inside `area` (or is `area`). A directory-kind
    /// grant covers its matches and everything below them; a file-kind grant only its matches.
    public func mayReachInside(_ area: CanonicalPath, kind: PathKind, caseInsensitive: Bool) -> Bool {
        // A match can be extended below `area` whenever the pattern can consume all of `area` first.
        if Self.match(components[...], area.components[...], caseInsensitive: caseInsensitive, prefixOnly: true) { return true }
        return kind == .directory && mayCover(area, caseInsensitive: caseInsensitive)
    }

    /// True when some match lies strictly below `area`: the pattern can consume all of `area` and
    /// still has components left, each of which (`**` included) can match one more level.
    public func mayMatchBelow(_ area: CanonicalPath, caseInsensitive: Bool) -> Bool {
        Self.consumes(components[...], area.components[...], caseInsensitive: caseInsensitive)
    }

    /// Whether the two grants share any concrete path. Walks the product of their glob
    /// automata, including epsilon transitions for `*` / `**`; sampling is insufficient.
    public func overlaps(_ other: PathPattern, kind: PathKind, otherKind: PathKind, caseInsensitive: Bool) -> Bool {
        let a = components + (kind == .directory ? ["**"] : [])
        let b = other.components + (otherKind == .directory ? ["**"] : [])
        var pending = [[0, 0]], seen: Set<[Int]> = []
        while let state = pending.popLast() {
            guard seen.insert(state).inserted else { continue }
            let i = state[0], j = state[1]
            if i == a.count && j == b.count { return true }
            if i < a.count && a[i] == "**" { pending.append([i + 1, j]) }
            if j < b.count && b[j] == "**" { pending.append([i, j + 1]) }
            guard i < a.count, j < b.count else { continue }
            if Self.globsOverlap(a[i] == "**" ? "*" : a[i], b[j] == "**" ? "*" : b[j], caseInsensitive: caseInsensitive) {
                pending.append([a[i] == "**" ? i : i + 1, b[j] == "**" ? j : j + 1])
            }
        }
        return false
    }

    private static func globsOverlap(_ first: String, _ second: String, caseInsensitive: Bool) -> Bool {
        let a = Array(caseInsensitive ? first.lowercased() : first)
        let b = Array(caseInsensitive ? second.lowercased() : second)
        // The third coordinate records whether a nonempty path component was consumed.
        var pending = [[0, 0, 0]], seen: Set<[Int]> = []
        while let state = pending.popLast() {
            guard seen.insert(state).inserted else { continue }
            let i = state[0], j = state[1], consumed = state[2]
            if i == a.count && j == b.count && consumed == 1 { return true }
            if i < a.count && a[i] == "*" { pending.append([i + 1, j, consumed]) }
            if j < b.count && b[j] == "*" { pending.append([i, j + 1, consumed]) }
            guard i < a.count, j < b.count else { continue }
            if a[i] == "*" || a[i] == "?" || b[j] == "*" || b[j] == "?" || a[i] == b[j] {
                pending.append([a[i] == "*" ? i : i + 1, b[j] == "*" ? j : j + 1, 1])
            }
        }
        return false
    }

    private static func consumes(_ pattern: ArraySlice<String>, _ path: ArraySlice<String>, caseInsensitive: Bool) -> Bool {
        guard let head = pattern.first else { return false }
        if path.isEmpty { return true }
        if head == "**" {
            return consumes(pattern.dropFirst(), path, caseInsensitive: caseInsensitive)
                || consumes(pattern, path.dropFirst(), caseInsensitive: caseInsensitive)
        }
        return glob(head, path.first!, caseInsensitive: caseInsensitive) && consumes(pattern.dropFirst(), path.dropFirst(), caseInsensitive: caseInsensitive)
    }

    /// True when a directory-kind grant would cover `area` because some match is `area` or above it.
    public func mayCover(_ area: CanonicalPath, caseInsensitive: Bool) -> Bool {
        (0...area.components.count).contains { length in
            Self.match(components[...], area.components.prefix(length), caseInsensitive: caseInsensitive, prefixOnly: false)
        }
    }

    /// An SBPL `regex` body matching exactly what the grant covers.
    public func regex(kind: PathKind) -> String {
        var body = "^" + Self.escape(base.isRoot ? "" : base.value)
        for component in rest {
            if component == "**" {
                body += "(/[^/]+)*"
            } else {
                body += "/" + component.map { char -> String in
                    switch char {
                    case "*": return "[^/]*"
                    case "?": return "[^/]"
                    default: return Self.escape(String(char))
                    }
                }.joined()
            }
        }
        return body + (kind == .directory ? "(/.*)?$" : "$")
    }

    /// One concrete path the pattern matches, for probing the sandbox. `**` stands for one directory,
    /// so the sample always ends in a concrete name (`/a/**` would otherwise sample `/a/`).
    public var sample: String {
        let parts = rest.map { $0 == "**" ? "x" : $0.replacingOccurrences(of: "*", with: "x").replacingOccurrences(of: "?", with: "x") }
        return (base.isRoot ? "" : base.value) + "/" + parts.joined(separator: "/")
    }

    private static func escape(_ text: String) -> String {
        var out = ""
        for char in text {
            if "\\.+*?()[]{}^$|".contains(char) { out.append("\\") }
            out.append(char)
        }
        return out
    }

    /// Matches pattern components against path components. With `prefixOnly`, succeeds once the
    /// whole path is consumed even if pattern components remain: a longer path would then match.
    private static func match(_ pattern: ArraySlice<String>, _ path: ArraySlice<String>, caseInsensitive: Bool, prefixOnly: Bool) -> Bool {
        guard let head = pattern.first else { return path.isEmpty }
        if path.isEmpty { return prefixOnly || pattern.allSatisfy { $0 == "**" } }
        if head == "**" {
            return match(pattern.dropFirst(), path, caseInsensitive: caseInsensitive, prefixOnly: prefixOnly)
                || match(pattern, path.dropFirst(), caseInsensitive: caseInsensitive, prefixOnly: prefixOnly)
        }
        return glob(head, path.first!, caseInsensitive: caseInsensitive)
            && match(pattern.dropFirst(), path.dropFirst(), caseInsensitive: caseInsensitive, prefixOnly: prefixOnly)
    }

    static func glob(_ pattern: String, _ text: String, caseInsensitive: Bool) -> Bool {
        let p = Array(caseInsensitive ? pattern.lowercased() : pattern), t = Array(caseInsensitive ? text.lowercased() : text)
        var pi = 0, ti = 0, star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == "?" || p[pi] == t[ti] {
                pi += 1; ti += 1
            } else if pi < p.count, p[pi] == "*" {
                star = pi; mark = ti; pi += 1
            } else if star >= 0 {
                pi = star + 1; mark += 1; ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}
