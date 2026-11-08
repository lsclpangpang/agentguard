import Foundation

public struct EventQueueBudgetSnapshot: Equatable, Sendable {
    public let bytes: Int
    public let count: Int
    public let maxBytes: Int
    public let maxCount: Int
}

/// Shared by collector delivery and access-log writing. Reservations include the encoded payload
/// and an explicit allocation allowance, and remain held while a delivery batch is being handled.
public final class EventQueueBudget: @unchecked Sendable {
    private let lock = NSLock()
    public let maxBytes: Int
    public let maxCount: Int
    private let priorityReserveBytes: Int
    private let priorityReserveCount: Int
    private var bytes = 0
    private var count = 0

    public init(maxBytes: Int = 8 * 1024 * 1024, maxCount: Int = 10_000,
                priorityReserveBytes: Int? = nil, priorityReserveCount: Int? = nil) {
        self.maxBytes = max(0, maxBytes)
        self.maxCount = max(0, maxCount)
        self.priorityReserveBytes = min(self.maxBytes, max(0, priorityReserveBytes ?? self.maxBytes / 8))
        self.priorityReserveCount = min(self.maxCount, max(0, priorityReserveCount ?? self.maxCount / 8))
    }

    public var snapshot: EventQueueBudgetSnapshot {
        lock.lock(); defer { lock.unlock() }
        return EventQueueBudgetSnapshot(bytes: bytes, count: count, maxBytes: maxBytes, maxCount: maxCount)
    }

    public func tryReserve(bytes requestedBytes: Int, count requestedCount: Int = 1, priority: Bool = false) -> Bool {
        guard requestedBytes >= 0, requestedCount >= 0, requestedBytes > 0 || requestedCount > 0 else { return false }
        lock.lock(); defer { lock.unlock() }
        let byteLimit = priority ? maxBytes : maxBytes - priorityReserveBytes
        let countLimit = priority ? maxCount : maxCount - priorityReserveCount
        // Subtraction avoids integer overflow for hostile/accidental Int.max requests.
        guard bytes <= byteLimit, requestedBytes <= byteLimit - bytes,
              count <= countLimit, requestedCount <= countLimit - count else { return false }
        bytes += requestedBytes
        count += requestedCount
        return true
    }

    public func release(bytes releasedBytes: Int, count releasedCount: Int = 1) {
        guard releasedBytes >= 0, releasedCount >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        bytes = max(0, bytes - min(bytes, releasedBytes))
        count = max(0, count - min(count, releasedCount))
    }
}

/// Scans each newly received byte once. An oversized line is discarded through its newline; its
/// tail can never be interpreted as a new collector message. No complete-line array accumulates.
public struct BoundedCollectorLineBuffer: Sendable {
    public let maxLineBytes: Int
    private var pending = Data()
    public private(set) var isDiscardingOversizedLine = false
    public private(set) var scannedByteCount: UInt64 = 0
    public var retainedBytes: Int { pending.count }

    public init(maxLineBytes: Int = 1024 * 1024) {
        self.maxLineBytes = max(0, maxLineBytes)
    }

    public mutating func consume(_ data: Data, onLine: (Data) -> Void, onOversizedLine: () -> Void) {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var segmentStart = 0
            for index in 0..<raw.count {
                scannedByteCount = saturatedAdd(scannedByteCount, 1)
                if raw[index] == 0x0a {
                    if !isDiscardingOversizedLine {
                        pending.append(contentsOf: raw[segmentStart..<index])
                        onLine(pending)
                        pending.removeAll(keepingCapacity: true)
                    }
                    isDiscardingOversizedLine = false
                    segmentStart = index + 1
                } else if !isDiscardingOversizedLine, index - segmentStart >= maxLineBytes - pending.count {
                    pending.removeAll(keepingCapacity: false)
                    isDiscardingOversizedLine = true
                    onOversizedLine()
                }
            }
            if !isDiscardingOversizedLine, segmentStart < raw.count {
                pending.append(contentsOf: raw[segmentStart..<raw.count])
            }
        }
    }

    /// A transport/source boundary cannot join an unfinished line from a previous producer.
    @discardableResult
    public mutating func reset() -> Bool {
        let incomplete = !pending.isEmpty || isDiscardingOversizedLine
        pending.removeAll(keepingCapacity: false)
        isDiscardingOversizedLine = false
        return incomplete
    }
}

public enum CollectorInputKind: String, Codable, Sendable {
    case file, lifecycle, denial, unknown
}

public enum CollectorInputGapReason: String, Codable, Hashable, Sendable {
    case queueOverflow, oversizedLine, disconnected, sourceRestarted, sourceSequenceGap, invalidWire, unparseableEvent, transportOverflow
}

/// A bounded aggregate, never raw system events. A possible unknown loss (such as disconnect) is
/// represented separately from counted events; it does not invent an exact missing-event count.
public struct CollectorInputGap: Equatable, Codable, Sendable {
    public var reasons: Set<CollectorInputGapReason>
    public var countsByReason: [CollectorInputGapReason: UInt64]
    public var droppedCount: UInt64
    public var lifecycleDropped: UInt64
    public var denialDropped: UInt64
    public var fileDropped: UInt64
    public var unknownDropped: UInt64
    public var possibleUnknownLoss: Bool
    public var firstSourceSequence: UInt64?
    public var lastSourceSequence: UInt64?
    public var firstAt: Date
    public var lastAt: Date
    public var attributionIncomplete: Bool { lifecycleDropped > 0 || unknownDropped > 0 || possibleUnknownLoss }

    public init(reason: CollectorInputGapReason, kind: CollectorInputKind, droppedCount: UInt64 = 1,
                sourceSequence: UInt64? = nil, possibleUnknownLoss: Bool = false, at: Date) {
        self.reasons = [reason]
        self.countsByReason = [reason: droppedCount]
        self.droppedCount = droppedCount
        self.lifecycleDropped = kind == .lifecycle ? droppedCount : 0
        self.denialDropped = kind == .denial ? droppedCount : 0
        self.fileDropped = kind == .file ? droppedCount : 0
        self.unknownDropped = kind == .unknown ? droppedCount : 0
        self.possibleUnknownLoss = possibleUnknownLoss
        self.firstSourceSequence = sourceSequence
        self.lastSourceSequence = sourceSequence
        self.firstAt = at
        self.lastAt = at
    }

    public mutating func merge(_ other: CollectorInputGap) {
        reasons.formUnion(other.reasons)
        for (reason, count) in other.countsByReason {
            countsByReason[reason] = saturatedAdd(countsByReason[reason] ?? 0, count)
        }
        droppedCount = saturatedAdd(droppedCount, other.droppedCount)
        lifecycleDropped = saturatedAdd(lifecycleDropped, other.lifecycleDropped)
        denialDropped = saturatedAdd(denialDropped, other.denialDropped)
        fileDropped = saturatedAdd(fileDropped, other.fileDropped)
        unknownDropped = saturatedAdd(unknownDropped, other.unknownDropped)
        possibleUnknownLoss = possibleUnknownLoss || other.possibleUnknownLoss
        if let sequence = other.firstSourceSequence { firstSourceSequence = min(firstSourceSequence ?? sequence, sequence) }
        if let sequence = other.lastSourceSequence { lastSourceSequence = max(lastSourceSequence ?? sequence, sequence) }
        firstAt = min(firstAt, other.firstAt)
        lastAt = max(lastAt, other.lastAt)
    }
}

public enum CollectorInput: Equatable, Sendable {
    case es(ESLine)
    case denial(SandboxDenial)
    case gap(CollectorInputGap)

    public var kind: CollectorInputKind {
        switch self {
        case let .es(line):
            switch line.kind {
            case .fork, .exec, .exit: return .lifecycle
            case .open, .openUnclassified, .create, .rename, .unlink, .close: return .file
            case .unsupported: return .unknown
            }
        case .denial: return .denial
        case .gap: return .unknown
        }
    }
    public var sourceSequence: UInt64? {
        if case let .es(line) = self { return line.globalSequence }
        return nil
    }
    public var isPriority: Bool { kind == .lifecycle || kind == .denial }
}

public struct BoundedCollectorQueueStatus: Equatable, Sendable {
    public let queuedCount: Int
    public let queuedBytes: Int
    public let pendingGapCount: Int
    public let droppedCount: UInt64
    public let attributionIncomplete: Bool
}

public final class BoundedCollectorBatch: @unchecked Sendable {
    public let inputs: [CollectorInput]
    private let budget: EventQueueBudget
    private let reservedBytes: Int
    private let reservedCount: Int
    private let lock = NSLock()
    private var released = false

    init(inputs: [CollectorInput], budget: EventQueueBudget, reservedBytes: Int, reservedCount: Int) {
        self.inputs = inputs
        self.budget = budget
        self.reservedBytes = reservedBytes
        self.reservedCount = reservedCount
    }
    public func release() {
        lock.lock()
        let shouldRelease = !released
        released = true
        lock.unlock()
        if shouldRelease { budget.release(bytes: reservedBytes, count: reservedCount) }
    }
    deinit { release() }
}

/// Retained events stay FIFO, including when lifecycle/denial events use reserved headroom. At
/// most two independent gap aggregates are held (before/after a clear boundary), so continued loss
/// cannot grow diagnostic memory.
public final class BoundedCollectorInputQueue: @unchecked Sendable {
    private struct Entry {
        let order: UInt64
        let input: CollectorInput
        let bytes: Int
    }
    private let lock = NSLock()
    private let budget: EventQueueBudget
    private let eventOverheadBytes: Int
    private var entries: [Entry?] = []
    private var head = 0
    private var nextOrder: UInt64 = 0
    private var queuedBytes = 0
    private var pendingGap: (order: UInt64, gap: CollectorInputGap)?
    private var checkpointGap: (order: UInt64, gap: CollectorInputGap)?
    private var droppedCount: UInt64 = 0
    private var attributionIncomplete = false

    /// Includes spare array capacity as well as the retained enum and allocation bookkeeping.
    public static var defaultEventOverheadBytes: Int { max(768, MemoryLayout<CollectorInput>.stride * 3 + 256) }

    public init(budget: EventQueueBudget, eventOverheadBytes: Int = BoundedCollectorInputQueue.defaultEventOverheadBytes) {
        self.budget = budget
        self.eventOverheadBytes = max(0, eventOverheadBytes)
    }

    public var status: BoundedCollectorQueueStatus {
        lock.lock(); defer { lock.unlock() }
        return BoundedCollectorQueueStatus(queuedCount: entries.count - head, queuedBytes: queuedBytes,
                                           pendingGapCount: (pendingGap == nil ? 0 : 1) + (checkpointGap == nil ? 0 : 1),
                                           droppedCount: droppedCount, attributionIncomplete: attributionIncomplete)
    }
    public var hasPending: Bool {
        lock.lock(); defer { lock.unlock() }
        return head < entries.count || pendingGap != nil || checkpointGap != nil
    }
    var retainedEntryCapacity: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.capacity
    }

    /// An exclusive boundary for a synchronous finite-prefix flush. Capturing a newer checkpoint
    /// replaces the prior boundary; callers finish that flush before beginning another clear.
    /// Freeze the diagnostic too, so losses arriving after clear cannot be erased with old input.
    public var checkpoint: UInt64 {
        lock.lock(); defer { lock.unlock() }
        if let pendingGap {
            if checkpointGap != nil { checkpointGap!.gap.merge(pendingGap.gap) }
            else { checkpointGap = pendingGap }
            self.pendingGap = nil
        }
        return nextOrder
    }

    @discardableResult
    public func enqueue(_ input: CollectorInput, encodedBytes: Int, at: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let order = nextOrder
        nextOrder = saturatedAdd(nextOrder, 1)
        if case let .gap(gap) = input {
            appendGap(gap, order: order)
            return true
        }
        let (bytes, overflow) = encodedBytes.addingReportingOverflow(eventOverheadBytes)
        guard encodedBytes >= 0, !overflow, budget.tryReserve(bytes: bytes, priority: input.isPriority) else {
            appendGap(CollectorInputGap(reason: .queueOverflow, kind: input.kind, sourceSequence: input.sourceSequence, at: at), order: order)
            return false
        }
        entries.append(Entry(order: order, input: input, bytes: bytes))
        queuedBytes += bytes
        return true
    }

    public func recordGap(_ gap: CollectorInputGap) {
        lock.lock(); defer { lock.unlock() }
        let order = nextOrder
        nextOrder = saturatedAdd(nextOrder, 1)
        appendGap(gap, order: order)
    }

    private func appendGap(_ gap: CollectorInputGap, order: UInt64) {
        droppedCount = saturatedAdd(droppedCount, gap.droppedCount)
        attributionIncomplete = attributionIncomplete || gap.attributionIncomplete
        if pendingGap != nil { pendingGap!.gap.merge(gap) }
        else { pendingGap = (order, gap) }
    }

    public func takeBatch(maxCount: Int = 256, before checkpoint: UInt64? = nil) -> BoundedCollectorBatch {
        lock.lock(); defer { lock.unlock() }
        var inputs: [CollectorInput] = []
        var bytes = 0
        var count = 0
        while inputs.count < max(0, maxCount) {
            let entry = head < entries.count ? entries[head] : nil
            let frozenFirst = checkpointGap != nil && (pendingGap == nil || checkpointGap!.order <= pendingGap!.order)
            let gap = frozenFirst ? checkpointGap : pendingGap
            if let gap, entry == nil || gap.order <= entry!.order {
                if let checkpoint, gap.order >= checkpoint { break }
                inputs.append(.gap(gap.gap))
                if frozenFirst { checkpointGap = nil } else { pendingGap = nil }
            } else if let entry {
                if let checkpoint, entry.order >= checkpoint { break }
                inputs.append(entry.input)
                bytes += entry.bytes
                queuedBytes -= entry.bytes
                count += 1
                entries[head] = nil
                head += 1
            } else { break }
        }
        if head == entries.count { entries.removeAll(keepingCapacity: false); head = 0 }
        else if head >= entries.count / 2 {
            // removeFirst keeps the old allocation. Copy the live suffix when half is consumed
            // so reservations released for delivered events do not leave their capacity behind.
            entries = Array(entries.dropFirst(head))
            head = 0
        }
        return BoundedCollectorBatch(inputs: inputs, budget: budget, reservedBytes: bytes, reservedCount: count)
    }

    deinit {
        for entry in entries.compactMap({ $0 }) { budget.release(bytes: entry.bytes) }
    }
}

private func saturatedAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? .max : value
}
