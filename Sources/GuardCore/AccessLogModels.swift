import Foundation

/// UTC wire/log timestamps preserve the microseconds supplied by event sources. The decoder
/// also accepts the whole-second ISO timestamps produced by older Helper protocols.
public enum AccessLogTimestamp {
    private final class Formatter: @unchecked Sendable {
        let lock = NSLock()
        let formatter: ISO8601DateFormatter = {
            let value = ISO8601DateFormatter()
            value.formatOptions = [.withInternetDateTime]
            value.timeZone = TimeZone(secondsFromGMT: 0)
            return value
        }()
    }
    private static let shared = Formatter()
    public static var encodingStrategy: JSONEncoder.DateEncodingStrategy {
        .custom { date, encoder in
            let value = date.timeIntervalSince1970
            guard value.isFinite else { throw EncodingError.invalidValue(date, .init(codingPath: encoder.codingPath, debugDescription: "invalid timestamp")) }
            var whole = floor(value)
            var micros = Int(((value - whole) * 1_000_000).rounded())
            if micros == 1_000_000 { whole += 1; micros = 0 }
            let base = shared.lock.withLock { shared.formatter.string(from: Date(timeIntervalSince1970: whole)) }
            var container = encoder.singleValueContainer()
            try container.encode(String(base.dropLast()) + String(format: ".%06dZ", micros))
        }
    }
    public static var decodingStrategy: JSONDecoder.DateDecodingStrategy {
        .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            if raw.hasSuffix("Z"), let dot = raw.lastIndex(of: ".") {
                let fraction = raw[raw.index(after: dot)..<raw.index(before: raw.endIndex)]
                if !fraction.isEmpty, fraction.count <= 9, fraction.utf8.allSatisfy({ (48...57).contains($0) }),
                   let numerator = Double(fraction),
                   let base = shared.lock.withLock({ shared.formatter.date(from: String(raw[..<dot]) + "Z") }) {
                    return base.addingTimeInterval(numerator / pow(10, Double(fraction.count)))
                }
            } else if let date = shared.lock.withLock({ shared.formatter.date(from: raw) }) {
                return date
            }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "invalid UTC access-log timestamp")
        }
    }
}

public enum AccessLogOutcome: String, Codable, Equatable, Sendable {
    case allowedObserved = "allowed_observed"
    case denied
    case unknown
}

public enum AccessLogSource: String, Codable, Equatable, Sendable {
    case eslogger
    case sandboxLog = "sandbox_log"
    case collector
    case storage
}

public enum AccessLogRecordKind: String, Codable, Equatable, Sendable {
    case access
    case gap
    case storageStatus = "storage_status"
}

public enum AccessLogAttributionStatus: String, Codable, Equatable, Sendable {
    case confirmed
    case pidOnly = "pid_only"
    case incomplete
}

public struct AccessLogProcessIdentity: Codable, Equatable, Sendable {
    public var pid: Int32
    public var pidversion: UInt32?
    public var startTime: UInt64?
    enum CodingKeys: String, CodingKey { case pid, pidversion; case startTime = "start_time" }
    public init(pid: Int32, pidversion: UInt32? = nil, startTime: UInt64? = nil) {
        self.pid = pid; self.pidversion = pidversion; self.startTime = startTime
    }
}

public struct AccessLogCoverage: Codable, Equatable, Sendable {
    public var fileEventsSubscribed: Bool?
    public var collectorHealthy: Bool?
    public var attributionComplete: Bool?
    public var successfulNetworkCovered: Bool
    enum CodingKeys: String, CodingKey {
        case fileEventsSubscribed = "file_events_subscribed", collectorHealthy = "collector_healthy"
        case attributionComplete = "attribution_complete", successfulNetworkCovered = "successful_network_covered"
    }
    public init(fileEventsSubscribed: Bool? = nil, collectorHealthy: Bool? = nil,
                attributionComplete: Bool? = nil, successfulNetworkCovered: Bool = false) {
        self.fileEventsSubscribed = fileEventsSubscribed; self.collectorHealthy = collectorHealthy
        self.attributionComplete = attributionComplete; self.successfulNetworkCovered = successfulNetworkCovered
    }
}

public struct AccessLogEndpoint: Codable, Equatable, Sendable {
    public var host: String?
    public var port: UInt16?
    public var transport: String?
    public var socketPath: String?
    enum CodingKeys: String, CodingKey { case host, port, transport; case socketPath = "socket_path" }
    public init(host: String? = nil, port: UInt16? = nil, transport: String? = nil, socketPath: String? = nil) {
        self.host = host; self.port = port; self.transport = transport; self.socketPath = socketPath
    }
}

public struct AccessLogGap: Codable, Equatable, Sendable {
    public var reason: String
    public var droppedCount: UInt64?
    public var firstSequence: UInt64?
    public var lastSequence: UInt64?
    public var from: Date?
    public var through: Date?
    enum CodingKeys: String, CodingKey {
        case reason, from, through
        case droppedCount = "dropped_count", firstSequence = "first_sequence", lastSequence = "last_sequence"
    }
    public init(reason: String, droppedCount: UInt64? = nil, firstSequence: UInt64? = nil,
                lastSequence: UInt64? = nil, from: Date? = nil, through: Date? = nil) {
        self.reason = reason; self.droppedCount = droppedCount; self.firstSequence = firstSequence
        self.lastSequence = lastSequence; self.from = from; self.through = through
    }
}

/// Metadata only. The Helper freezes attribution before append; the store fills event/writer/sequence.
/// `pidOnly` explicitly preserves the weaker identity supplied by kernel denial reports.
public struct AccessLogRecord: Codable, Equatable, Sendable, Identifiable {
    public var schemaVersion = 1
    public var kind: AccessLogRecordKind = .access
    public var eventID = ""
    public var writerID = ""
    public var sequence: UInt64 = 0
    public var receivedAt: Date
    public var sourceAt: Date?
    public var profileID: String
    public var profileRevision: Int?
    public var runUUID: String?
    public var instanceID: Int?
    public var instanceOrigin: String?
    public var bootID: String?
    public var rootProcess: AccessLogProcessIdentity?
    public var pid: Int32?
    public var pidversion: UInt32?
    public var processStartTime: UInt64?
    public var processName: String?
    public var executablePath: String?
    public var source: AccessLogSource
    public var sourceSequence: UInt64?
    public var sourceEventID: String?
    public var sourceSubsequence: Int?
    public var operation: String
    /// Original kernel open flags when supplied; an open event is not evidence of bytes read.
    public var openFlags: UInt32? = nil
    public var target: String?
    public var outcome: AccessLogOutcome
    public var evidence: String?
    public var rawTarget: String?
    public var endpointFields: AccessLogEndpoint?
    public var coverage: AccessLogCoverage
    public var attributionStatus: AccessLogAttributionStatus
    public var gap: AccessLogGap?
    /// Field -> original UTF-8 byte count; populated when a diagnostic or target must be bounded.
    public var truncatedFields: [String: Int] = [:]
    public var id: String { eventID }
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version", kind = "record_kind", eventID = "event_id", writerID = "writer_id"
        case sequence, receivedAt = "received_at", sourceAt = "source_at", profileID = "profile_id"
        case profileRevision = "profile_revision", runUUID = "run_uuid", instanceID = "instance_id"
        case instanceOrigin = "instance_origin", bootID = "boot_id", rootProcess = "root_process_identity"
        case pid, pidversion, processStartTime = "process_start_time", processName = "process_name"
        case executablePath = "executable_path", source, sourceSequence = "source_sequence"
        case sourceEventID = "source_event_id", sourceSubsequence = "source_subsequence"
        case operation, target, outcome, evidence, rawTarget = "raw_target", endpointFields = "endpoint_fields"
        case openFlags = "open_flags"
        case coverage, attributionStatus = "attribution_status", gap, truncatedFields = "truncated_fields"
    }

    public init(profileID: String, operation: String, outcome: AccessLogOutcome, receivedAt: Date,
                profileRevision: Int? = nil, runUUID: String? = nil, instanceID: Int? = nil,
                instanceOrigin: String? = nil, bootID: String? = nil, rootProcess: AccessLogProcessIdentity? = nil,
                pid: Int32? = nil, pidversion: UInt32? = nil, processStartTime: UInt64? = nil,
                processName: String? = nil, executablePath: String? = nil, source: AccessLogSource,
                sourceSequence: UInt64? = nil, sourceAt: Date? = nil, sourceEventID: String? = nil,
                sourceSubsequence: Int? = nil, target: String? = nil, rawTarget: String? = nil,
                endpointFields: AccessLogEndpoint? = nil, evidence: String? = nil,
                coverage: AccessLogCoverage = .init(), attributionStatus: AccessLogAttributionStatus = .confirmed) {
        self.profileID = profileID; self.operation = operation; self.outcome = outcome; self.receivedAt = receivedAt
        self.profileRevision = profileRevision; self.runUUID = runUUID; self.instanceID = instanceID
        self.instanceOrigin = instanceOrigin; self.bootID = bootID; self.rootProcess = rootProcess
        self.pid = pid; self.pidversion = pidversion; self.processStartTime = processStartTime
        self.processName = processName; self.executablePath = executablePath; self.source = source
        self.sourceSequence = sourceSequence; self.sourceAt = sourceAt; self.sourceEventID = sourceEventID
        self.sourceSubsequence = sourceSubsequence; self.target = target; self.rawTarget = rawTarget
        self.endpointFields = endpointFields; self.evidence = evidence; self.coverage = coverage
        self.attributionStatus = attributionStatus
    }
}

public struct AccessLogPolicy: Equatable, Sendable {
    public var retentionInterval: TimeInterval = 7 * 24 * 60 * 60
    public var profileByteLimit = 256 * 1024 * 1024
    public var globalByteLimit = 512 * 1024 * 1024
    public var segmentByteLimit = 16 * 1024 * 1024
    public var segmentInterval: TimeInterval = 60 * 60
    public var flushInterval: TimeInterval = 1
    public var batchCount = 256
    public var cleanupInterval: TimeInterval = 15 * 60
    public var minimumFreeBytes: UInt64 = 1024 * 1024 * 1024
    public var cleanupLowWatermark: Double = 0.8
    public var maxRecordBytes = 64 * 1024
    public var maxTextBytes = 16 * 1024
    public var scanByteLimit = 4 * 1024 * 1024
    public var responseByteLimit = 1024 * 1024
    public var maxDirectoryEntries = 8192
    public init() {}
    public static let `default` = AccessLogPolicy()
}

public struct AccessLogAppendResult: Equatable, Sendable {
    public var accepted: Bool
    public var eventID: String?
    public var sequence: UInt64?
    public var writerID: String?
    public init(accepted: Bool, eventID: String? = nil, sequence: UInt64? = nil, writerID: String? = nil) {
        self.accepted = accepted; self.eventID = eventID; self.sequence = sequence; self.writerID = writerID
    }
}

public struct AccessLogQuery: Codable, Equatable, Sendable {
    public var profileID: String
    public var from: Date?
    public var through: Date?
    public var outcome: AccessLogOutcome?
    public var cursor: String?
    public var limit: Int
    public init(profileID: String, from: Date? = nil, through: Date? = nil, outcome: AccessLogOutcome? = nil,
                cursor: String? = nil, limit: Int = 200) {
        self.profileID = profileID; self.from = from; self.through = through; self.outcome = outcome
        self.cursor = cursor; self.limit = limit
    }
}

public struct AccessLogExportQuery: Codable, Equatable, Sendable {
    public var query: AccessLogQuery
    public var byteLimit: Int
    public init(query: AccessLogQuery, byteLimit: Int = 256 * 1024) {
        self.query = query; self.byteLimit = byteLimit
    }
}

public struct AccessLogPage: Codable, Equatable, Sendable {
    public var records: [AccessLogRecord]
    public var nextCursor: String?
    public var generation: UInt64
    /// More scanning remains after the per-request scan budget, even if this page has no matches.
    public var incomplete: Bool
    public var scannedBytes: Int
    public init(records: [AccessLogRecord], nextCursor: String?, generation: UInt64, incomplete: Bool, scannedBytes: Int) {
        self.records = records; self.nextCursor = nextCursor; self.generation = generation
        self.incomplete = incomplete; self.scannedBytes = scannedBytes
    }
}

public struct AccessLogExportPage: Codable, Equatable, Sendable {
    public var data: Data
    public var nextCursor: String?
    public var generation: UInt64
    public var incomplete: Bool
    public var recordCount: Int
    public init(data: Data, nextCursor: String?, generation: UInt64, incomplete: Bool, recordCount: Int) {
        self.data = data; self.nextCursor = nextCursor; self.generation = generation
        self.incomplete = incomplete; self.recordCount = recordCount
    }
}

public struct AccessLogClearResult: Codable, Equatable, Sendable {
    public var profileID: String
    public var generation: UInt64
    public var cutoffSequence: UInt64
    public var writerID: String
    public var removedBytes: Int
    public init(profileID: String, generation: UInt64, cutoffSequence: UInt64, writerID: String, removedBytes: Int) {
        self.profileID = profileID; self.generation = generation; self.cutoffSequence = cutoffSequence
        self.writerID = writerID; self.removedBytes = removedBytes
    }
}

/// A synchronously installed writer barrier that can be awaited outside the Helper state queue.
/// It is deliberately one-shot: preparing a clear fixes its cutoff before later ingress resumes.
public final class AccessLogClearOperation: @unchecked Sendable {
    public let cutoffSequence: UInt64
    public let writerID: String
    private let lock = NSLock()
    private var result: Result<AccessLogClearResult, any Error>?
    private var waiter: CheckedContinuation<AccessLogClearResult, any Error>?
    init(cutoffSequence: UInt64, writerID: String) {
        self.cutoffSequence = cutoffSequence; self.writerID = writerID
    }
    public func value() async throws -> AccessLogClearResult {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let result { lock.unlock(); continuation.resume(with: result) }
            else if waiter != nil { lock.unlock(); continuation.resume(throwing: AccessLogError.queryBusy) }
            else { waiter = continuation; lock.unlock() }
        }
    }
    func finish(_ value: Result<AccessLogClearResult, any Error>) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = value
        let waiting = waiter; waiter = nil
        lock.unlock()
        waiting?.resume(with: value)
    }
}

public struct AccessLogCleanupSummary: Codable, Equatable, Sendable {
    public var occurredAt: Date
    /// retention, capacity, or low_disk; this is only the most recent in-memory cleanup attempt.
    public var reason: String
    public var releasedBytes: Int
    public var deletedSegments: Int
    public var earliestRetainedAt: Date?
    public init(occurredAt: Date, reason: String, releasedBytes: Int, deletedSegments: Int, earliestRetainedAt: Date?) {
        self.occurredAt = occurredAt; self.reason = reason; self.releasedBytes = releasedBytes
        self.deletedSegments = deletedSegments; self.earliestRetainedAt = earliestRetainedAt
    }
}

public struct AccessLogStatus: Codable, Equatable, Sendable {
    public var profileID: String?
    /// Filled from the Helper's independent settings; nil for aggregate status.
    public var loggingEnabled: Bool?
    public var enabledProfileIDs: [String] = []
    public var enabled: Bool? {
        get { loggingEnabled }
        set { loggingEnabled = newValue }
    }
    public var generation: UInt64 = 1
    public var writerID: String
    public var bytes = 0
    public var queuedCount = 0
    public var queuedBytes = 0
    public var droppedCount: UInt64 = 0
    public var sourceGapCount: UInt64 = 0
    public var storageGapCount: UInt64 = 0
    public var knownGapCount: UInt64 { sourceGapCount &+ storageGapCount }
    public var earliestRetainedAt: Date?
    public var lastWrittenAt: Date?
    public var lastSyncedAt: Date?
    public var lastCleanupSummary: AccessLogCleanupSummary?
    public var writtenThroughSequence: UInt64 = 0
    public var syncedThroughSequence: UInt64 = 0
    public var errors: [String] = []
    public var unsupportedSegments = 0
    public var quarantinedSegments = 0
    public var coverage: AccessLogCoverage = .init()
    public var isReady = false
    public init(profileID: String?, writerID: String) { self.profileID = profileID; self.writerID = writerID }
}

public enum AccessLogError: Error, Codable, Equatable, Sendable {
    case invalidProfileID
    case invalidCursor
    case historyExpired
    case generationConflict(expected: UInt64, actual: UInt64)
    case storageUnavailable(String)
    case unsupportedVersion(Int)
    case queryBusy
}

/// All names are single validated path components below a pre-opened, protected root.
/// Implementations must reject symlinks, wrong owners/types and traversal, including during rename/remove.
public protocol AccessLogFileSystem: Sendable {
    func profiles() throws -> [String]
    func files(profileID: String) throws -> [AccessLogFileInfo]
    func createProfile(_ profileID: String) throws
    func read(profileID: String, name: String, offset: UInt64, limit: Int) throws -> Data
    func append(profileID: String, name: String, data: Data) throws
    func replace(profileID: String, name: String, data: Data) throws
    func truncate(profileID: String, name: String, size: UInt64) throws
    func rename(profileID: String, from: String, to: String) throws
    func remove(profileID: String, name: String) throws
    func synchronize(profileID: String, name: String) throws
    func availableBytes() throws -> UInt64?
}

public struct AccessLogFileInfo: Equatable, Sendable {
    public var name: String
    public var size: UInt64
    public var isRegular: Bool
    public init(name: String, size: UInt64, isRegular: Bool = true) {
        self.name = name; self.size = size; self.isRegular = isRegular
    }
}

/// The writer is serial; reader work runs independently. Both are supplied by the platform layer.
public protocol AccessLogScheduling: Sendable {
    func write(after delay: TimeInterval, _ work: @escaping @Sendable () -> Void)
    func read(_ work: @escaping @Sendable () -> Void)
}
