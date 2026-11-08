import Foundation
import Testing
@testable import GuardCore

struct AccessLogPresentationTests {
    private let date = Date(timeIntervalSince1970: 1_000)

    @Test func savedAndQueuedCopiesAppearOnlyOnceWithoutCollapsingRepeatedAccesses() {
        var first = record("first", at: date)
        first.sequence = 1
        let second = record("second", at: date.addingTimeInterval(1))
        let cached = Observation(instance: 1, access: .read("/same"), denied: false, at: date,
                                 eventID: "first", accessLogSequence: 1, accessLogWriterID: "writer",
                                 accessLogDisposition: .queued)
        let queued = Observation(instance: 1, access: .read("/same"), denied: false, at: date.addingTimeInterval(2),
                                 eventID: "queued", accessLogSequence: 3, accessLogWriterID: "writer",
                                 accessLogDisposition: .queued)
        let items = AccessLogPresentation.merge(records: [first, second], recent: [queued, cached],
                                                status: status(written: 1), query: .init(profileID: "sample"))
        #expect(items.map(\.id) == ["queued", "second", "first"])
    }

    @Test func writtenRecordsOutsideLoadedPageDoNotReturnAsUnsavedMemoryRows() {
        let cached = Observation(instance: 1, access: .read("/older"), denied: false, at: date,
                                 eventID: "older", accessLogSequence: 1, accessLogWriterID: "writer",
                                 accessLogDisposition: .queued)
        #expect(AccessLogPresentation.merge(records: [], recent: [cached], status: status(written: 2),
                                            query: .init(profileID: "sample")).isEmpty)
        // A new Helper's sequence must not be compared with a previous writer's sequence.
        let newWriter = Observation(instance: 2, access: .read("/new"), denied: false, at: date,
                                    eventID: "new", accessLogSequence: 1, accessLogWriterID: "next-writer",
                                    accessLogDisposition: .queued)
        #expect(AccessLogPresentation.merge(records: [], recent: [newWriter], status: status(written: 2),
                                            query: .init(profileID: "sample")).count == 1)
    }

    @Test func memoryRowsRespectTimeAndOutcomeAndUnknownTimesDoNotEnterDatedQueries() {
        let allowed = Observation(instance: 1, access: .read("/allowed"), denied: false, at: date)
        let denied = Observation(instance: 1, access: .read("/denied"), denied: true, at: date)
        let outside = Observation(instance: 1, access: .read("/outside"), denied: true, at: date.addingTimeInterval(-20))
        let unknownTime = Observation(instance: 1, access: .read("/unknown"), denied: true)
        let query = AccessLogQuery(profileID: "sample", from: date.addingTimeInterval(-10), outcome: .denied)
        let items = AccessLogPresentation.merge(records: [], recent: [allowed, denied, outside, unknownTime],
                                                status: nil, query: query)
        #expect(items.count == 1)
        #expect(items.first?.observation?.access == .read("/denied"))
    }

    @Test func duplicateLegacyObservationsKeepSeparateStableIdentities() {
        let observation = Observation(instance: 1, access: .read("/same"), denied: false, at: date)
        let items = AccessLogPresentation.merge(records: [], recent: [observation, observation], status: nil,
                                                query: .init(profileID: "sample"))
        #expect(items.count == 2)
        #expect(Set(items.map(\.id)).count == 2)
    }

    @Test func unknownCoverageIsNotPresentedAsComplete() {
        let text = AccessLogPresentation.coverageText(.init())
        #expect(text.contains("待确认"))
        #expect(text.contains("成功的网络连接"))
        let incomplete = AccessLogPresentation.coverageText(.init(fileEventsSubscribed: true, collectorHealthy: true,
                                                                 attributionComplete: false))
        #expect(incomplete.contains("归属"))
        #expect(incomplete.contains("缺口"))
    }

    @Test func memoryOnlyAndRejectedEventsNeverDisappearBehindAnotherEventsHighWatermark() {
        let memory = Observation(instance: 1, access: .read("/memory"), denied: false, at: date,
                                 eventID: "memory", accessLogSequence: 1, accessLogWriterID: "writer",
                                 accessLogDisposition: .memoryOnly)
        let rejected = Observation(instance: 1, access: .read("/rejected"), denied: true, at: date,
                                   eventID: "rejected", accessLogSequence: 2, accessLogWriterID: "writer",
                                   accessLogDisposition: .rejected)
        var snapshot = status(written: 3)
        snapshot.loggingEnabled = true
        let items = AccessLogPresentation.merge(records: [], recent: [memory, rejected], status: snapshot,
                                                query: .init(profileID: "sample"))
        #expect(items.count == 2)
        #expect(items.first { $0.id == "memory" }?.persistence == "仅本次运行")
        #expect(items.first { $0.id == "rejected" }?.persistence == "未保存")
    }

    @Test func failedWritesCannotBeProvenSavedByALaterSequence() {
        let cached = Observation(instance: 1, access: .read("/failed"), denied: false, at: date,
                                 eventID: "failed", accessLogSequence: 1, accessLogWriterID: "writer",
                                 accessLogDisposition: .queued)
        var snapshot = status(written: 2)
        snapshot.loggingEnabled = true
        snapshot.errors = ["write failed"]
        let items = AccessLogPresentation.merge(records: [], recent: [cached], status: snapshot,
                                                query: .init(profileID: "sample"))
        #expect(items.count == 1)
        #expect(items.first?.persistence == "保存结果待确认")
        snapshot.errors = []
        snapshot.droppedCount = 1
        #expect(AccessLogPresentation.merge(records: [], recent: [cached], status: snapshot,
                                            query: .init(profileID: "sample")).count == 1)
    }

    private func record(_ id: String, at: Date) -> AccessLogRecord {
        var value = AccessLogRecord(profileID: "sample", operation: "open", outcome: .allowedObserved,
                                    receivedAt: at, source: .eslogger, target: "/same")
        value.eventID = id
        value.writerID = "writer"
        return value
    }

    private func status(written: UInt64) -> AccessLogStatus {
        var value = AccessLogStatus(profileID: "sample", writerID: "writer")
        value.writtenThroughSequence = written
        return value
    }
}
