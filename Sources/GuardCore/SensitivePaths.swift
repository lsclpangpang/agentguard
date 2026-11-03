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

    private static func components(_ path: String) -> [String] {
        path.split(separator: "/").map(String.init)
    }
}
