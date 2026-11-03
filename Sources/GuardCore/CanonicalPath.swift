public enum PathError: Error, Equatable, Sendable {
    case empty
    case notAbsolute(String)
    case containsNUL
}

/// Maps a lexically normalized absolute path to the path the kernel will actually check.
public protocol PathResolver: Sendable {
    func resolve(_ normalizedPath: String) -> String
}

/// Resolves known aliases (macOS firmlinks or symlinks discovered on disk) by longest component-wise prefix.
public struct AliasResolver: PathResolver, Equatable {
    public let aliases: [String: String]

    public init(aliases: [String: String]) {
        self.aliases = aliases
    }

    public static let macOSDefault = AliasResolver(aliases: [
        "/tmp": "/private/tmp",
        "/var": "/private/var",
        "/etc": "/private/etc",
    ])

    public func resolve(_ normalizedPath: String) -> String {
        let match = aliases.keys
            .filter { normalizedPath == $0 || normalizedPath.hasPrefix($0 + "/") }
            .max { $0.count < $1.count }
        guard let key = match, let target = aliases[key] else { return normalizedPath }
        return target + normalizedPath.dropFirst(key.count)
    }
}

public struct CanonicalPath: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public let components: [String]

    public init(_ raw: String, resolver: any PathResolver) throws {
        guard !raw.isEmpty else { throw PathError.empty }
        guard !raw.contains("\u{0}") else { throw PathError.containsNUL }
        guard raw.hasPrefix("/") else { throw PathError.notAbsolute(raw) }
        let resolved = resolver.resolve(Self.normalize(raw))
        self.components = Self.split(Self.normalize(resolved))
        self.value = "/" + components.joined(separator: "/")
    }

    public var description: String { value }

    public var isRoot: Bool { components.isEmpty }

    /// True when `other` is this path or lies beneath it.
    public func contains(_ other: CanonicalPath, caseInsensitive: Bool) -> Bool {
        guard other.components.count >= components.count else { return false }
        for (mine, theirs) in zip(components, other.components) where !Self.equal(mine, theirs, caseInsensitive) {
            return false
        }
        return true
    }

    public func isSame(as other: CanonicalPath, caseInsensitive: Bool) -> Bool {
        components.count == other.components.count && contains(other, caseInsensitive: caseInsensitive)
    }

    func comparisonKey(caseInsensitive: Bool) -> String {
        caseInsensitive ? value.lowercased() : value
    }

    private static func equal(_ a: String, _ b: String, _ caseInsensitive: Bool) -> Bool {
        caseInsensitive ? a.lowercased() == b.lowercased() : a == b
    }

    private static func split(_ path: String) -> [String] {
        path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    }

    private static func normalize(_ path: String) -> String {
        var stack: [String] = []
        for part in split(path) {
            switch part {
            case ".": continue
            case "..": if !stack.isEmpty { stack.removeLast() }
            default: stack.append(part)
            }
        }
        return "/" + stack.joined(separator: "/")
    }
}
