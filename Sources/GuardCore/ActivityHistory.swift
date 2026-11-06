import Foundation

/// The user's answer to a pending item. Only an item with refusal evidence can be kept blocked;
/// an observed access that succeeded can only be archived, because nothing blocked it.
public enum SuggestionDecision: String, Codable, Sendable {
    case keepBlocked = "keep_blocked"
    case dismissed
    /// Undoes an earlier decision; the item is listed again.
    case reopened
}

public struct DecisionRecord: Codable, Equatable, Sendable {
    public var suggestion: Suggestion
    public var decision: SuggestionDecision
    public var at: Date
    /// Accesses behind the item when the decision was made.
    public var evidence: Int

    public init(suggestion: Suggestion, decision: SuggestionDecision, at: Date, evidence: Int) {
        self.suggestion = suggestion
        self.decision = decision
        self.at = at
        self.evidence = evidence
    }
}

public enum HistoryKind: String, Codable, Sendable {
    case permissionChange = "permission_change"
    case decision
    case started
    case stopped
    case verified
    case verificationFailed = "verification_failed"
}

/// One line of a profile's history: what happened and how it was handled.
public struct HistoryEntry: Codable, Equatable, Sendable {
    public var at: Date
    public var kind: HistoryKind
    public var title: String
    public var details: [String]

    public init(at: Date, kind: HistoryKind, title: String, details: [String] = []) {
        self.at = at
        self.kind = kind
        self.title = title
        self.details = details
    }
}

/// A decided item, with what has been observed for it since.
public struct ArchivedItem: Codable, Equatable, Sendable {
    public var decision: DecisionRecord
    /// The item as it would be listed now; nil when nothing matching was observed in this session.
    public var current: PendingItem?

    public init(decision: DecisionRecord, current: PendingItem?) {
        self.decision = decision
        self.current = current
    }
}

public struct ActivityLog: Codable, Equatable, Sendable {
    /// Recent accesses of managed processes, newest first.
    public var recent: [Observation]
    public var archived: [ArchivedItem]
    /// Newest first.
    public var history: [HistoryEntry]
    /// Activity records may be incomplete, e.g. the collector lost events or lacks Full Disk Access.
    public var recordsIncomplete: Bool

    public init(recent: [Observation], archived: [ArchivedItem], history: [HistoryEntry], recordsIncomplete: Bool) {
        self.recent = recent
        self.archived = archived
        self.history = history
        self.recordsIncomplete = recordsIncomplete
    }
}

/// Decisions and history, kept per profile in the protected configuration root:
/// `<root>/activity/<profile>/{decisions,history}.json`.
public struct ActivityStore: Sendable {
    public let root: String
    private let files: any FileStore
    static let historyLimit = 500
    static let decisionLimit = 1000

    public init(root: String, files: any FileStore) {
        self.root = root
        self.files = files
    }

    public func decisions(_ profileID: String) -> [DecisionRecord] {
        read([DecisionRecord].self, profileID, "decisions.json") ?? []
    }

    /// The standing decision for each suggestion; a reopened one has none.
    public func activeDecisions(_ profileID: String) -> [Suggestion: DecisionRecord] {
        var latest: [Suggestion: DecisionRecord] = [:]
        for record in decisions(profileID) { latest[record.suggestion] = record }
        return latest.filter { $0.value.decision != .reopened }
    }

    public func record(_ decision: DecisionRecord, profileID: String) throws {
        var all = decisions(profileID)
        all.append(decision)
        try write(Array(all.suffix(Self.decisionLimit)), profileID, "decisions.json")
    }

    public func history(_ profileID: String) -> [HistoryEntry] {
        read([HistoryEntry].self, profileID, "history.json") ?? []
    }

    public func append(_ entry: HistoryEntry, profileID: String) throws {
        var all = history(profileID)
        all.append(entry)
        try write(Array(all.suffix(Self.historyLimit)), profileID, "history.json")
    }

    public func removeAll(_ profileID: String) throws {
        guard ProfileID.isValid(profileID) else { return }
        for name in ["decisions.json", "history.json"] { try files.remove(root + "/activity/" + profileID + "/" + name) }
    }

    private func read<T: Decodable>(_ type: T.Type, _ profileID: String, _ name: String) -> T? {
        guard ProfileID.isValid(profileID), let data = try? files.read(root + "/activity/" + profileID + "/" + name) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(type, from: data)
    }

    private func write<T: Encodable>(_ value: T, _ profileID: String, _ name: String) throws {
        guard ProfileID.isValid(profileID) else { throw StoreError.invalidProfileID(profileID) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try files.writeAtomically(try encoder.encode(value), to: root + "/activity/" + profileID + "/" + name)
    }
}

extension Suggestion {
    /// Plain description, shared by the Helper's history and the CLI.
    public var summary: String {
        switch self {
        case let .template(id): return "启用运行时模板 \(id)"
        case let .file(path, kind, access): return "\(access == .readWrite ? "读写" : "读取")\(kind == .directory ? "目录" : "文件") \(path)"
        case let .exec(path): return "运行 \(path)"
        case let .loopbackPort(port): return "连接本机端口 \(port)"
        case .outboundTCP: return "对外 TCP 连接"
        case .listen: return "监听端口"
        }
    }
}
