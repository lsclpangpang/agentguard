/// Locations whose contents are secrets or personal data; grants touching them are flagged in the UI.
public struct SensitivePaths: Sendable {
    public let roots: [[String]]

    public static let homeRelative = [
        ".ssh", ".aws", ".gnupg", ".netrc", ".config/gh", ".docker/config.json", ".kube/config",
        "Library/Keychains", "Library/Cookies", "Library/Safari", "Library/Messages", "Library/Mail",
        "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox", "Library/Application Support/com.apple.TCC",
        "Documents", "Desktop", "Downloads",
        ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".claude/plugins", ".claude/.credentials.json",
        ".codex/auth.json", ".codex/config.toml",
    ]

    public init(home: String) {
        let homeComponents = Self.components(home)
        roots = Self.homeRelative.map { homeComponents + Self.components($0) } + [Self.components("/Library/Keychains")]
    }

    /// True when `path` is a sensitive location or inside one.
    public func isSensitive(_ path: String) -> Bool {
        let target = Self.components(path)
        return roots.contains { target.starts(with: $0) }
    }

    /// True when a directory grant at `path` would cover any sensitive location.
    public func overlapsSensitive(_ path: String) -> Bool {
        let target = Self.components(path)
        return isSensitive(path) || roots.contains { $0.starts(with: target) }
    }

    /// True when a wildcard grant may cover any sensitive location.
    public func overlapsSensitive(_ pattern: PathPattern, kind: PathKind, caseInsensitive: Bool) -> Bool {
        roots.contains { root in
            guard let area = try? CanonicalPath("/" + root.joined(separator: "/"), resolver: AliasResolver(aliases: [:])) else { return false }
            // A file-kind grant above a sensitive root reaches nothing inside it.
            return pattern.mayReachInside(area, kind: kind, caseInsensitive: caseInsensitive)
        }
    }

    private static func components(_ path: String) -> [String] {
        path.split(separator: "/").map(String.init)
    }
}
