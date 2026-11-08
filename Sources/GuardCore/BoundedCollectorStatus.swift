import Foundation

/// Daemon-reported state. An installed older collector sends no such envelope, leaving coverage
/// unknown rather than treating a requested flag as proof that file events are subscribed.
public struct CollectorRuntimeStatus: Equatable, Codable, Sendable {
    public static let currentProtocolVersion = 1
    public var protocolVersion: Int
    public var generation: String
    public var esloggerRunning: Bool
    public var sandboxRunning: Bool
    public var fileEvents: Bool?

    public init(generation: String, esloggerRunning: Bool, sandboxRunning: Bool, fileEvents: Bool?,
                protocolVersion: Int = Self.currentProtocolVersion) {
        self.protocolVersion = protocolVersion
        self.generation = generation
        self.esloggerRunning = esloggerRunning
        self.sandboxRunning = sandboxRunning
        self.fileEvents = fileEvents
    }
}

/// Starting a process is not proof that eslogger obtained authorization and subscribed. Coverage
/// becomes known only after a valid event from that exact source generation has been observed.
public struct CollectorSubscriptionState: Sendable {
    public private(set) var status = CollectorRuntimeStatus(generation: "", esloggerRunning: false,
                                                           sandboxRunning: false, fileEvents: nil)
    private var requestedFileEvents = false

    public init() {}

    public mutating func esloggerStarted(generation: String, fileEventsRequested: Bool) {
        requestedFileEvents = fileEventsRequested
        status.generation = generation
        status.esloggerRunning = true
        status.fileEvents = nil
    }

    public mutating func esloggerStopped(generation: String) {
        guard status.generation == generation else { return }
        status.esloggerRunning = false
        status.fileEvents = nil
    }

    public func needsConfirmation(generation: String) -> Bool {
        status.generation == generation && status.esloggerRunning && status.fileEvents == nil
    }

    public mutating func confirmEvent(generation: String) {
        guard needsConfirmation(generation: generation) else { return }
        status.fileEvents = requestedFileEvents
    }

    public mutating func sandboxRunning(_ running: Bool) { status.sandboxRunning = running }
}

public struct CollectorCoverageStatus: Equatable, Codable, Sendable {
    public var connected: Bool
    public var fileEventsSubscribed: Bool?
    public var esloggerRunning: Bool?
    public var sandboxRunning: Bool?
    public var lastStatusAt: Date?
    public var inputDroppedCount: UInt64
    public var oversizedLineCount: UInt64
    public var attributionIncomplete: Bool
    public var queuedCount: Int
    public var queuedBytes: Int

    public init(connected: Bool = false, fileEventsSubscribed: Bool? = nil,
                esloggerRunning: Bool? = nil, sandboxRunning: Bool? = nil, lastStatusAt: Date? = nil,
                inputDroppedCount: UInt64 = 0, oversizedLineCount: UInt64 = 0,
                attributionIncomplete: Bool = false, queuedCount: Int = 0, queuedBytes: Int = 0) {
        self.connected = connected
        self.fileEventsSubscribed = fileEventsSubscribed
        self.esloggerRunning = esloggerRunning
        self.sandboxRunning = sandboxRunning
        self.lastStatusAt = lastStatusAt
        self.inputDroppedCount = inputDroppedCount
        self.oversizedLineCount = oversizedLineCount
        self.attributionIncomplete = attributionIncomplete
        self.queuedCount = queuedCount
        self.queuedBytes = queuedBytes
    }
}
