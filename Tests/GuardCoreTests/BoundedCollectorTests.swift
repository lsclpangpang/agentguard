import Foundation
import Testing
@testable import GuardCore

@Suite struct BoundedCollectorTests {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    @Test func oneMiBLineIsAcceptedAndOneExtraByteIsDropped() {
        var buffer = BoundedCollectorLineBuffer()
        var lengths: [Int] = []
        var drops = 0
        buffer.consume(Data(repeating: 65, count: 1024 * 1024), onLine: { lengths.append($0.count) }, onOversizedLine: { drops += 1 })
        #expect(buffer.retainedBytes == 1024 * 1024)
        buffer.consume(Data([10]), onLine: { lengths.append($0.count) }, onOversizedLine: { drops += 1 })
        #expect(lengths == [1024 * 1024])
        #expect(drops == 0)
        buffer.consume(Data(repeating: 66, count: 1024 * 1024 + 1), onLine: { lengths.append($0.count) }, onOversizedLine: { drops += 1 })
        #expect(buffer.retainedBytes == 0)
        #expect(buffer.isDiscardingOversizedLine)
        buffer.consume(Data("tail\nok\n".utf8), onLine: { lengths.append($0.count) }, onOversizedLine: { drops += 1 })
        #expect(lengths == [1024 * 1024, 2])
        #expect(drops == 1)
        #expect(!buffer.isDiscardingOversizedLine)
    }

    @Test func repeatedChunksNeverRetainOrRescanAnOversizedLine() {
        var buffer = BoundedCollectorLineBuffer(maxLineBytes: 1024)
        var lines: [Data] = []
        var drops = 0
        let chunk = Data(repeating: 65, count: 256)
        for _ in 0..<5000 {
            buffer.consume(chunk, onLine: { lines.append($0) }, onOversizedLine: { drops += 1 })
            #expect(buffer.retainedBytes <= 1024)
        }
        #expect(buffer.scannedByteCount == 5000 * 256)
        #expect(buffer.retainedBytes == 0)
        #expect(drops == 1)
        buffer.consume(Data("\nvalid\n".utf8), onLine: { lines.append($0) }, onOversizedLine: { drops += 1 })
        #expect(lines == [Data("valid".utf8)])
        #expect(drops == 1)
    }

    @Test func fragmentedUtf8AndMultipleLinesKeepBytesIntact() {
        var buffer = BoundedCollectorLineBuffer(maxLineBytes: 8)
        var lines: [Data] = []
        let data = Data("你\nabc\n\n".utf8)
        for byte in data { buffer.consume(Data([byte]), onLine: { lines.append($0) }, onOversizedLine: {}) }
        #expect(lines == [Data("你".utf8), Data("abc".utf8), Data()])
        #expect(buffer.scannedByteCount == UInt64(data.count))
    }

    @Test func budgetReservesPrioritySpaceWithoutCrossingEitherLimit() {
        let budget = EventQueueBudget(maxBytes: 1024, maxCount: 8, priorityReserveBytes: 256, priorityReserveCount: 2)
        #expect(budget.tryReserve(bytes: 768, count: 6))
        #expect(!budget.tryReserve(bytes: 1))
        #expect(budget.tryReserve(bytes: 256, count: 2, priority: true))
        #expect(budget.snapshot.bytes == 1024)
        #expect(budget.snapshot.count == 8)
        #expect(!budget.tryReserve(bytes: 1, priority: true))
        budget.release(bytes: 768, count: 6)
        #expect(budget.snapshot.bytes == 256)
        #expect(budget.snapshot.count == 2)
        // Ordinary offers always leave the headroom free, even while a priority offer remains.
        #expect(!budget.tryReserve(bytes: 768, count: 6))
        #expect(budget.tryReserve(bytes: 512, count: 4))
    }

    @Test func countBudgetAppliesEvenToTinyPayloadsAndConcurrentProducers() async {
        let budget = EventQueueBudget(maxBytes: 1_000_000, maxCount: 100, priorityReserveBytes: 0, priorityReserveCount: 0)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask { for _ in 0..<100 { _ = budget.tryReserve(bytes: 1) } }
            }
        }
        #expect(budget.snapshot.count == 100)
        #expect(budget.snapshot.bytes == 100)
        #expect(!budget.tryReserve(bytes: 1))
    }

    @Test func negativeAndOverflowingReservationsCannotBypassBudget() {
        let budget = EventQueueBudget(maxBytes: 1024, maxCount: 100, priorityReserveBytes: 0, priorityReserveCount: 0)
        #expect(!budget.tryReserve(bytes: -1))
        #expect(!budget.tryReserve(bytes: 1, count: -1))
        #expect(!budget.tryReserve(bytes: Int.max))
        #expect(budget.tryReserve(bytes: 1024))
        #expect(!budget.tryReserve(bytes: Int.max))
        #expect(budget.snapshot.bytes == 1024)
        #expect(budget.snapshot.count == 1)
    }

    func line(sequence: UInt64, kind: ESEventKind = .open(path: "/tmp/f", write: false)) -> ESLine {
        ESLine(globalSequence: sequence, process: ProcessKey(pid: 10, version: 1), executablePath: "/bin/test", kind: kind)
    }

    @Test func inputQueueAccountsForOverheadPreservesOrderAndHoldsBatchReservation() {
        let budget = EventQueueBudget(maxBytes: 4096, maxCount: 4, priorityReserveBytes: 0, priorityReserveCount: 1)
        let queue = BoundedCollectorInputQueue(budget: budget, eventOverheadBytes: 256)
        #expect(queue.enqueue(.es(line(sequence: 1)), encodedBytes: 20, at: t0))
        #expect(queue.enqueue(.es(line(sequence: 2)), encodedBytes: 20, at: t0))
        #expect(queue.enqueue(.es(line(sequence: 3)), encodedBytes: 20, at: t0))
        #expect(!queue.enqueue(.es(line(sequence: 4)), encodedBytes: 20, at: t0))
        #expect(queue.enqueue(.es(line(sequence: 5, kind: .exit)), encodedBytes: 20, at: t0))
        #expect(budget.snapshot.bytes == 4 * (20 + 256))
        #expect(budget.snapshot.count == 4)
        let batch = queue.takeBatch(maxCount: 10)
        #expect(budget.snapshot.count == 4)
        let sequences = batch.inputs.compactMap { input -> UInt64? in if case let .es(line) = input { return line.globalSequence }; return nil }
        #expect(sequences == [1, 2, 3, 5])
        #expect(batch.inputs.count == 5)
        if case let .gap(gap) = batch.inputs[3] {
            #expect(gap.droppedCount == 1)
            #expect(gap.firstSourceSequence == 4)
            #expect(!gap.attributionIncomplete)
        } else { Issue.record("gap must precede the next retained source event") }
        batch.release()
        batch.release()
        #expect(budget.snapshot.bytes == 0)
        #expect(budget.snapshot.count == 0)
    }

    @Test func droppedLifecycleAndUnknownLinesMakeAttributionIncomplete() {
        let budget = EventQueueBudget(maxBytes: 300, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget, eventOverheadBytes: 256)
        #expect(queue.enqueue(.es(line(sequence: 1)), encodedBytes: 40, at: t0))
        #expect(!queue.enqueue(.es(line(sequence: 2, kind: .exit)), encodedBytes: 40, at: t0))
        queue.recordGap(CollectorInputGap(reason: .oversizedLine, kind: .unknown, droppedCount: 1, at: t0))
        let batch = queue.takeBatch(maxCount: 10)
        let gaps = batch.inputs.compactMap { input -> CollectorInputGap? in if case let .gap(gap) = input { return gap }; return nil }
        #expect(gaps.count == 1)
        #expect(gaps.first?.droppedCount == 2)
        #expect(gaps.first?.attributionIncomplete == true)
        #expect(queue.status.attributionIncomplete)
        #expect(queue.status.droppedCount == 2)
        batch.release()
    }

    @Test func overflowSummaryRemainsBoundedUnderSustainedLoss() {
        let budget = EventQueueBudget(maxBytes: 300, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget, eventOverheadBytes: 256)
        #expect(queue.enqueue(.es(line(sequence: 1)), encodedBytes: 40, at: t0))
        for seq in 2...100_001 { #expect(!queue.enqueue(.es(line(sequence: UInt64(seq))), encodedBytes: 40, at: t0)) }
        #expect(queue.status.queuedCount == 1)
        #expect(queue.status.pendingGapCount == 1)
        #expect(queue.status.droppedCount == 100_000)
        #expect(budget.snapshot.bytes == 296)
        #expect(budget.snapshot.count == 1)
        let batch = queue.takeBatch(maxCount: 256)
        #expect(batch.inputs.count == 2)
        batch.release()
    }

    @Test func batchBoundAllowsControlWorkBetweenDrains() {
        let budget = EventQueueBudget(maxBytes: 1_000_000, maxCount: 1000, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget)
        for seq in 1...600 { #expect(queue.enqueue(.es(line(sequence: UInt64(seq))), encodedBytes: 20, at: t0)) }
        let first = queue.takeBatch(maxCount: 256)
        #expect(first.inputs.count == 256)
        #expect(queue.status.queuedCount == 344)
        first.release()
        let second = queue.takeBatch(maxCount: 256)
        #expect(second.inputs.count == 256)
        second.release()
        let last = queue.takeBatch(maxCount: 256)
        #expect(last.inputs.count == 88)
        last.release()
        #expect(budget.snapshot.count == 0)
    }

    @Test func drainingAQueueReleasesItsUnusedEntryCapacity() {
        let budget = EventQueueBudget(maxBytes: 2_000_000, maxCount: 1000, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget)
        for seq in 1...1000 { #expect(queue.enqueue(.es(line(sequence: UInt64(seq))), encodedBytes: 20, at: t0)) }
        let batch = queue.takeBatch(maxCount: 900)
        batch.release()
        #expect(queue.status.queuedCount == 100)
        #expect(queue.retainedEntryCapacity <= 2 * queue.status.queuedCount)
        queue.takeBatch(maxCount: 100).release()
        #expect(queue.retainedEntryCapacity == 0)
        #expect(budget.snapshot.count == 0)
    }

    @Test func wireRoundTripsStatusWithoutInventingOldDaemonCoverage() {
        let status = CollectorRuntimeStatus(generation: "test-source", esloggerRunning: true, sandboxRunning: true, fileEvents: true)
        #expect(CollectorWire.decode(CollectorWire.encode(.status(status))) == .status(status))
        var monitor = CollectorHealthMonitor(silenceTimeout: 30)
        monitor.record(.started, at: t0)
        #expect(monitor.health(at: t0).coverage.fileEventsSubscribed == nil)
        monitor.record(.runtimeStatus(status), at: t0)
        #expect(monitor.health(at: t0).coverage.fileEventsSubscribed == true)
        monitor.record(.inputGap(CollectorInputGap(reason: .oversizedLine, kind: .unknown, droppedCount: 1, at: t0)), at: t0)
        #expect(monitor.health(at: t0).coverage.attributionIncomplete)
        #expect(!monitor.health(at: t0).isHealthy)
    }

    @Test func mixedGapReasonsRetainTheirOwnCountsAndSurviveSuccessfulEvents() {
        var gap = CollectorInputGap(reason: .queueOverflow, kind: .lifecycle, droppedCount: 3, at: t0)
        gap.merge(CollectorInputGap(reason: .oversizedLine, kind: .unknown, at: t0))
        var monitor = CollectorHealthMonitor(silenceTimeout: 30)
        monitor.record(.started, at: t0)
        monitor.record(.inputGap(gap), at: t0)
        monitor.record(.event(sequence: 100), at: t0)
        let health = monitor.health(at: t0)
        #expect(health.coverage.inputDroppedCount == 4)
        #expect(health.coverage.oversizedLineCount == 1)
        #expect(health.problems.contains(.inputOverflow(count: 3)))
        #expect(health.problems.contains(.inputLineTooLong(count: 1)))
        #expect(health.coverage.attributionIncomplete)
    }

    @Test func clearCheckpointFlushesOnlyTheAlreadyReceivedPrefix() {
        let budget = EventQueueBudget(maxBytes: 1_000_000, maxCount: 1000, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget)
        for seq in 1...300 { #expect(queue.enqueue(.es(line(sequence: UInt64(seq))), encodedBytes: 20, at: t0)) }
        let checkpoint = queue.checkpoint
        for seq in 301...310 { #expect(queue.enqueue(.es(line(sequence: UInt64(seq))), encodedBytes: 20, at: t0)) }
        let first = queue.takeBatch(maxCount: 256, before: checkpoint)
        #expect(first.inputs.count == 256)
        #expect(budget.snapshot.count == 310)
        first.release()
        #expect(budget.snapshot.count == 54)
        let second = queue.takeBatch(maxCount: 256, before: checkpoint)
        #expect(second.inputs.count == 44)
        second.release()
        #expect(queue.takeBatch(maxCount: 256, before: checkpoint).inputs.isEmpty)
        #expect(queue.status.queuedCount == 10)
        #expect(budget.snapshot.count == 10)
        let after = queue.takeBatch(maxCount: 256)
        let sequences = after.inputs.compactMap { input -> UInt64? in if case let .es(line) = input { return line.globalSequence }; return nil }
        #expect(sequences == Array(301...310).map(UInt64.init))
        after.release()
        #expect(budget.snapshot.count == 0)
    }

    @Test func clearCheckpointSeparatesGapCountersFromLaterLoss() {
        let budget = EventQueueBudget(maxBytes: 300, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let queue = BoundedCollectorInputQueue(budget: budget, eventOverheadBytes: 256)
        #expect(queue.enqueue(.es(line(sequence: 1)), encodedBytes: 40, at: t0))
        #expect(!queue.enqueue(.es(line(sequence: 2)), encodedBytes: 40, at: t0))
        let checkpoint = queue.checkpoint
        #expect(!queue.enqueue(.es(line(sequence: 3)), encodedBytes: 40, at: t0.addingTimeInterval(1)))
        let before = queue.takeBatch(maxCount: 256, before: checkpoint)
        #expect(before.inputs.count == 2)
        if case let .gap(gap) = before.inputs[1] {
            #expect(gap.droppedCount == 1)
            #expect(gap.lastSourceSequence == 2)
        } else { Issue.record("pre-clear loss must be a separate bounded diagnostic") }
        before.release()
        #expect(queue.takeBatch(maxCount: 256, before: checkpoint).inputs.isEmpty)
        let after = queue.takeBatch(maxCount: 256)
        #expect(after.inputs.count == 1)
        if case let .gap(gap) = after.inputs[0] {
            #expect(gap.droppedCount == 1)
            #expect(gap.firstSourceSequence == 3)
        } else { Issue.record("post-clear loss must remain visible") }
        after.release()
    }

    @Test func fileSubscriptionRemainsUnknownUntilTheCurrentSourceProducesAnEvent() {
        var subscriptions = CollectorSubscriptionState()
        subscriptions.esloggerStarted(generation: "first", fileEventsRequested: true)
        #expect(subscriptions.status.esloggerRunning)
        #expect(subscriptions.status.fileEvents == nil)
        subscriptions.confirmEvent(generation: "first")
        #expect(subscriptions.status.fileEvents == true)
        subscriptions.esloggerStarted(generation: "second", fileEventsRequested: false)
        #expect(subscriptions.status.fileEvents == nil)
        subscriptions.confirmEvent(generation: "first")
        #expect(subscriptions.status.fileEvents == nil)
        subscriptions.esloggerStopped(generation: "first")
        #expect(subscriptions.status.esloggerRunning)
        subscriptions.confirmEvent(generation: "second")
        #expect(subscriptions.status.fileEvents == false)
        subscriptions.esloggerStopped(generation: "second")
        #expect(!subscriptions.status.esloggerRunning)
        #expect(subscriptions.status.fileEvents == nil)
    }

    @Test func initialEmptySourceStatusDoesNotInventACollectorRestart() {
        var monitor = CollectorHealthMonitor(silenceTimeout: 30)
        monitor.record(.started, at: t0)
        monitor.record(.runtimeStatus(CollectorRuntimeStatus(generation: "", esloggerRunning: false,
                                                             sandboxRunning: true, fileEvents: nil)), at: t0)
        monitor.record(.runtimeStatus(CollectorRuntimeStatus(generation: "first", esloggerRunning: true,
                                                             sandboxRunning: true, fileEvents: true)), at: t0)
        let startedHealth = monitor.health(at: t0)
        #expect(startedHealth.isHealthy)
        #expect(!startedHealth.coverage.attributionIncomplete)
        monitor.record(.runtimeStatus(CollectorRuntimeStatus(generation: "second", esloggerRunning: true,
                                                             sandboxRunning: true, fileEvents: true)), at: t0)
        let restartedHealth = monitor.health(at: t0)
        #expect(restartedHealth.problems.contains(.restartedAfterInterruption))
        #expect(restartedHealth.coverage.attributionIncomplete)
    }
}
