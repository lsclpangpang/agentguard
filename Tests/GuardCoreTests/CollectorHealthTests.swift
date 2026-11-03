import Foundation
import Testing
@testable import GuardCore

@Suite struct CollectorHealthTests {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func started() -> CollectorHealthMonitor {
        var m = CollectorHealthMonitor(silenceTimeout: 30)
        m.record(.started, at: t0)
        return m
    }

    @Test func monitorThatNeverStartedIsNotHealthy() {
        let m = CollectorHealthMonitor(silenceTimeout: 30)
        #expect(m.health(at: t0).problems == [.notStarted])
        #expect(!m.health(at: t0).isHealthy)
    }

    @Test func contiguousSequenceIsHealthy() {
        var m = started()
        for seq in 1...3 { m.record(.event(sequence: UInt64(seq)), at: t0.addingTimeInterval(Double(seq))) }
        #expect(m.health(at: t0.addingTimeInterval(5)).isHealthy)
    }

    @Test func firstEventSetsBaselineWithoutGap() {
        var m = started()
        m.record(.event(sequence: 1000), at: t0)
        m.record(.event(sequence: 1001), at: t0)
        #expect(m.health(at: t0).isHealthy)
    }

    @Test func sequenceGapReportsMissingCount() {
        var m = started()
        m.record(.event(sequence: 1), at: t0)
        m.record(.event(sequence: 2), at: t0)
        m.record(.event(sequence: 5), at: t0)
        #expect(m.health(at: t0).problems == [.droppedEvents(count: 2)])
    }

    @Test func gapsAccumulateUntilAcknowledged() {
        var m = started()
        m.record(.event(sequence: 1), at: t0)
        m.record(.event(sequence: 3), at: t0)
        m.record(.event(sequence: 4), at: t0)
        m.record(.event(sequence: 7), at: t0)
        #expect(m.health(at: t0).problems == [.droppedEvents(count: 3)])
        m.acknowledgeDroppedEvents()
        #expect(m.health(at: t0).isHealthy)
    }

    @Test func duplicateOrOlderSequenceIsIgnored() {
        var m = started()
        m.record(.event(sequence: 5), at: t0)
        m.record(.event(sequence: 5), at: t0)
        m.record(.event(sequence: 3), at: t0)
        m.record(.event(sequence: 6), at: t0)
        #expect(m.health(at: t0).isHealthy)
    }

    @Test func silenceBeyondTimeoutIsInterruption() {
        var m = started()
        m.record(.event(sequence: 1), at: t0)
        #expect(m.health(at: t0.addingTimeInterval(30)).isHealthy)
        #expect(m.health(at: t0.addingTimeInterval(31)).problems == [.interrupted])
    }

    @Test func heartbeatPreventsInterruption() {
        var m = started()
        m.record(.heartbeat, at: t0.addingTimeInterval(25))
        #expect(m.health(at: t0.addingTimeInterval(50)).isHealthy)
    }

    @Test func exitIsInterruptionAndRestartResetsSequenceBaseline() {
        var m = started()
        m.record(.event(sequence: 10), at: t0)
        m.record(.exited, at: t0.addingTimeInterval(1))
        #expect(m.health(at: t0.addingTimeInterval(2)).problems == [.interrupted])
        m.record(.started, at: t0.addingTimeInterval(3))
        m.record(.event(sequence: 1), at: t0.addingTimeInterval(4))
        #expect(m.health(at: t0.addingTimeInterval(5)).problems == [.restartedAfterInterruption])
        m.acknowledgeInterruption()
        #expect(m.health(at: t0.addingTimeInterval(5)).isHealthy)
    }

    @Test(arguments: [
        (CollectorSignal.authorizationDenied, CollectorProblem.unauthorized),
        (CollectorSignal.unparseableOutput, CollectorProblem.incompatibleOutput),
        (CollectorSignal.storageLimitReached, CollectorProblem.storageFull),
    ])
    func conditionsAreReported(signal: CollectorSignal, problem: CollectorProblem) {
        var m = started()
        m.record(signal, at: t0)
        #expect(m.health(at: t0).problems.contains(problem))
        #expect(!m.health(at: t0).isHealthy)
    }
}
