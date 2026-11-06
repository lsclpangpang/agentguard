import Foundation

public struct LaunchAgentStatus: Codable, Equatable, Sendable {
    public var registered: Bool
    public var running: Bool
    public var runAtLogin: Bool
    public var canRestoreOriginal: Bool
    public var problem: String?
    public var originalProblem: String?

    public init(registered: Bool, running: Bool, runAtLogin: Bool, canRestoreOriginal: Bool, problem: String? = nil, originalProblem: String? = nil) {
        self.registered = registered
        self.running = running
        self.runAtLogin = runAtLogin
        self.canRestoreOriginal = canRestoreOriginal
        self.problem = problem
        self.originalProblem = originalProblem
    }

    public var displayText: String {
        if problem != nil { return "启动状态待检查" }
        if registered { return running ? "已由 AgentGuard 启动" : "已启用，当前未运行" }
        return runAtLogin ? "已设置自启，当前未加载" : "尚未启用受控启动"
    }
}

/// Parses arguments only. No shell, variable expansion, or command substitution is involved.
public enum LaunchArguments {
    public enum ParseError: Error, Equatable, CustomStringConvertible {
        case unfinishedQuote, unfinishedEscape
        public var description: String {
            self == .unfinishedQuote ? "启动参数的引号没有闭合" : "启动参数末尾的反斜杠没有对应字符"
        }
    }

    public static func parse(_ text: String) throws -> [String] {
        var result: [String] = [], value = ""
        var quote: Character?, escaped = false, started = false
        for c in text {
            if escaped { value.append(c); escaped = false; started = true; continue }
            if c == "\\", quote != "'" { escaped = true; started = true; continue }
            if let q = quote {
                if c == q { quote = nil } else { value.append(c) }
            } else if c == "\"" || c == "'" {
                quote = c; started = true
            } else if c.isWhitespace {
                if started { result.append(value); value = ""; started = false }
            } else {
                value.append(c); started = true
            }
        }
        if escaped { throw ParseError.unfinishedEscape }
        if quote != nil { throw ParseError.unfinishedQuote }
        if started { result.append(value) }
        return result
    }

    public static func format(_ arguments: [String]) -> String {
        arguments.map { value in
            if !value.isEmpty && !value.contains(where: { $0.isWhitespace || "\\\"'".contains($0) }) { return value }
            return "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }.joined(separator: " ")
    }
}

/// The login setting changed after a profile was saved. It is kept apart from the approved
/// revisions: it changes no permission, so it must neither need authorization nor make a running
/// program look out of date. `<root>/login/<profile>.json`; absent means the profile's own value.
public struct LoginSettingStore: Sendable {
    public let root: String
    let files: any FileStore

    public init(root: String, files: any FileStore) {
        self.root = root
        self.files = files
    }

    private struct Record: Codable { var runAtLogin: Bool }

    public func override(_ profileID: String) -> Bool? {
        guard ProfileID.isValid(profileID), let data = try? files.read(root + "/login/" + profileID + ".json") else { return nil }
        return (try? JSONDecoder().decode(Record.self, from: data))?.runAtLogin
    }

    public func runAtLogin(of profile: Profile) -> Bool? {
        guard let launch = profile.launch else { return nil }
        return override(profile.id) ?? launch.runAtLogin
    }

    /// The profile with the stored login setting applied.
    public func applied(to profile: Profile) -> Profile {
        var copy = profile
        if let value = override(profile.id) { copy.launch?.runAtLogin = value }
        return copy
    }

    public func set(_ value: Bool, for profileID: String) throws {
        guard ProfileID.isValid(profileID) else { throw StoreError.invalidProfileID(profileID) }
        try files.writeAtomically(try JSONEncoder().encode(Record(runAtLogin: value)), to: root + "/login/" + profileID + ".json")
    }

    public func remove(_ profileID: String) throws {
        guard ProfileID.isValid(profileID) else { return }
        try files.remove(root + "/login/" + profileID + ".json")
    }
}
