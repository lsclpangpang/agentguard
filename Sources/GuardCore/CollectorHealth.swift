import Foundation

public enum CollectorSignal: Sendable {
    case started
    case exited
    case heartbeat
    case event(sequence: UInt64)
    case authorizationDenied
    case unparseableOutput
    case storageLimitReached
}

public enum CollectorProblem: Hashable, Sendable {
    case notStarted
    case droppedEvents(count: UInt64)
    case interrupted
    case restartedAfterInterruption
    case unauthorized
    case incompatibleOutput
    case storageFull
}

extension CollectorProblem: CustomStringConvertible {
    public var description: String {
        switch self {
        case .notStarted: return "采集器未启动"
        case let .droppedEvents(count): return "累计遗漏 \(count) 条系统活动记录"
        case .interrupted: return "采集中断"
        case .restartedAfterInterruption: return "采集曾中断，已重启"
        case .unauthorized: return "未授权（需要完全磁盘访问）"
        case .incompatibleOutput: return "采集输出格式不兼容"
        case .storageFull: return "事件存储已达上限"
        }
    }

    var sortKey: Int {
        switch self {
        case .notStarted: return 0
        case .droppedEvents: return 1
        case .interrupted: return 2
        case .restartedAfterInterruption: return 3
        case .unauthorized: return 4
        case .incompatibleOutput: return 5
        case .storageFull: return 6
        }
    }
}

public struct CollectorHealth: Equatable, Sendable {
    public var problems: Set<CollectorProblem>

    public init(problems: Set<CollectorProblem>) {
        self.problems = problems
    }

    public var isHealthy: Bool { problems.isEmpty }
}

/// Tracks whether observation is trustworthy. A healthy collector never implies complete coverage;
/// an unhealthy one must be surfaced rather than hidden.
public struct CollectorHealthMonitor: Sendable {
    public let silenceTimeout: TimeInterval
    private var hasStarted = false
    private var running = false
    private var lastSequence: UInt64?
    private var dropped: UInt64 = 0
    private var lastActivity: Date?
    private var exitedWhileRunning = false
    private var restartedAfterInterruption = false
    private var conditions: Set<CollectorProblem> = []

    public init(silenceTimeout: TimeInterval) {
        self.silenceTimeout = silenceTimeout
    }

    public mutating func record(_ signal: CollectorSignal, at time: Date) {
        switch signal {
        case .started:
            if exitedWhileRunning { restartedAfterInterruption = true }
            exitedWhileRunning = false
            hasStarted = true
            running = true
            lastSequence = nil
            lastActivity = time
        case .exited:
            running = false
            exitedWhileRunning = true
        case .heartbeat:
            lastActivity = time
        case let .event(sequence):
            lastActivity = time
            // A delivered event proves the collector is authorized now, whatever happened before.
            conditions.remove(.unauthorized)
            if let last = lastSequence {
                guard sequence > last else { return }
                dropped += sequence - last - 1
            }
            lastSequence = sequence
        case .authorizationDenied:
            conditions.insert(.unauthorized)
        case .unparseableOutput:
            conditions.insert(.incompatibleOutput)
        case .storageLimitReached:
            conditions.insert(.storageFull)
        }
    }

    public func health(at now: Date) -> CollectorHealth {
        guard hasStarted else { return CollectorHealth(problems: [.notStarted]) }
        var problems = conditions
        if dropped > 0 { problems.insert(.droppedEvents(count: dropped)) }
        if !running {
            problems.insert(.interrupted)
        } else if let last = lastActivity, now.timeIntervalSince(last) > silenceTimeout {
            problems.insert(.interrupted)
        }
        if restartedAfterInterruption { problems.insert(.restartedAfterInterruption) }
        return CollectorHealth(problems: problems)
    }

    public mutating func acknowledgeDroppedEvents() { dropped = 0 }

    public mutating func acknowledgeInterruption() { restartedAfterInterruption = false }

    /// Clears what has already been reported (dropped events, past interruptions); current conditions stay.
    public mutating func acknowledgeAll() {
        acknowledgeDroppedEvents()
        acknowledgeInterruption()
    }
}
