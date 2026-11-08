import Foundation

public enum CollectorSignal: Sendable {
    case started
    case exited
    case heartbeat
    case event(sequence: UInt64)
    case authorizationDenied
    case unparseableOutput
    case storageLimitReached
    case runtimeStatus(CollectorRuntimeStatus)
    case inputGap(CollectorInputGap)
}

public enum CollectorProblem: Hashable, Sendable {
    case notStarted
    case droppedEvents(count: UInt64)
    case interrupted
    case restartedAfterInterruption
    case unauthorized
    case incompatibleOutput
    case storageFull
    case inputOverflow(count: UInt64)
    case inputLineTooLong(count: UInt64)
    case attributionIncomplete
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
        case let .inputOverflow(count): return "采集入口拥塞，累计未保留 \(count) 条记录"
        case let .inputLineTooLong(count): return "采集输入超过单行上限，已丢弃 \(count) 行"
        case .attributionIncomplete: return "采集曾遗漏进程身份信息，部分访问无法确认归属"
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
        case .inputOverflow: return 7
        case .inputLineTooLong: return 8
        case .attributionIncomplete: return 9
        }
    }
}

public struct CollectorHealth: Equatable, Sendable {
    public var problems: Set<CollectorProblem>
    public var coverage: CollectorCoverageStatus

    public init(problems: Set<CollectorProblem>, coverage: CollectorCoverageStatus = CollectorCoverageStatus()) {
        self.problems = problems
        self.coverage = coverage
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
    private var coverage = CollectorCoverageStatus()
    private var sourceGeneration: String?
    private var inputOverflowCount: UInt64 = 0

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
            coverage.connected = true
            coverage.fileEventsSubscribed = nil
            coverage.esloggerRunning = nil
            coverage.sandboxRunning = nil
            coverage.lastStatusAt = nil
        case .exited:
            running = false
            exitedWhileRunning = true
            coverage.connected = false
            coverage.fileEventsSubscribed = nil
            coverage.esloggerRunning = nil
            coverage.sandboxRunning = nil
        case .heartbeat:
            lastActivity = time
        case let .event(sequence):
            lastActivity = time
            // A delivered event proves the collector is authorized now, whatever happened before.
            conditions.remove(.unauthorized)
            if let last = lastSequence {
                guard sequence > last else { return }
                dropped = adding(dropped, sequence - last - 1)
            }
            lastSequence = sequence
        case .authorizationDenied:
            conditions.insert(.unauthorized)
        case .unparseableOutput:
            conditions.insert(.incompatibleOutput)
        case .storageLimitReached:
            conditions.insert(.storageFull)
        case let .runtimeStatus(status):
            guard status.protocolVersion == CollectorRuntimeStatus.currentProtocolVersion else {
                conditions.insert(.incompatibleOutput)
                coverage.fileEventsSubscribed = nil
                return
            }
            // Before the first eslogger launch the daemon can report only its sandbox source.
            // That empty generation is not a previous ES subscription and cannot prove a restart.
            if !status.generation.isEmpty {
                if let previous = sourceGeneration, previous != status.generation {
                    lastSequence = nil
                    restartedAfterInterruption = true
                    coverage.attributionIncomplete = true
                }
                sourceGeneration = status.generation
            }
            running = status.esloggerRunning && status.sandboxRunning
            lastActivity = time
            coverage.fileEventsSubscribed = status.esloggerRunning ? status.fileEvents : nil
            coverage.esloggerRunning = status.esloggerRunning
            coverage.sandboxRunning = status.sandboxRunning
            coverage.lastStatusAt = time
        case let .inputGap(gap):
            coverage.inputDroppedCount = adding(coverage.inputDroppedCount, gap.droppedCount)
            coverage.attributionIncomplete = coverage.attributionIncomplete || gap.attributionIncomplete
            inputOverflowCount = adding(inputOverflowCount, gap.countsByReason[.queueOverflow] ?? 0)
            coverage.oversizedLineCount = adding(coverage.oversizedLineCount, gap.countsByReason[.oversizedLine] ?? 0)
        }
    }

    public func health(at now: Date) -> CollectorHealth {
        guard hasStarted else { return CollectorHealth(problems: [.notStarted], coverage: coverage) }
        var problems = conditions
        if dropped > 0 { problems.insert(.droppedEvents(count: dropped)) }
        if inputOverflowCount > 0 { problems.insert(.inputOverflow(count: inputOverflowCount)) }
        if coverage.oversizedLineCount > 0 { problems.insert(.inputLineTooLong(count: coverage.oversizedLineCount)) }
        if coverage.attributionIncomplete { problems.insert(.attributionIncomplete) }
        if !running {
            problems.insert(.interrupted)
        } else if let last = lastActivity, now.timeIntervalSince(last) > silenceTimeout {
            problems.insert(.interrupted)
        }
        if restartedAfterInterruption { problems.insert(.restartedAfterInterruption) }
        return CollectorHealth(problems: problems, coverage: coverage)
    }

    public mutating func acknowledgeDroppedEvents() { dropped = 0 }

    public mutating func acknowledgeInterruption() { restartedAfterInterruption = false }

    /// Clears what has already been reported (dropped events, past interruptions); current conditions stay.
    public mutating func acknowledgeAll() {
        acknowledgeDroppedEvents()
        acknowledgeInterruption()
    }

    private func adding(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? .max : result
    }
}
