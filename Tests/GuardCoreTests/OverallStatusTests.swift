import Foundation
import Testing
@testable import GuardCore

@Suite struct OverallStatusTests {
    let healthy = CollectorHealth(problems: [])

    func object(_ protection: ProtectionState = .enforced, revision: RevisionState = .applied(running: true), pending: Int = 0, unmanaged: Int = 0) -> ObjectStatus {
        ObjectStatus(profileID: "knodo", protection: protection, revision: revision, pendingItems: pending, unmanagedInstances: unmanaged)
    }

    @Test func allGoodRequiresEveryConditionToHold() {
        #expect(OverallStatus.evaluate(objects: [object()], collector: healthy) == .allGood)
    }

    @Test func collectorProblemPreventsAllGood() {
        let s = OverallStatus.evaluate(objects: [object()], collector: CollectorHealth(problems: [.droppedEvents(count: 1)]))
        #expect(s.level == .attention)
    }

    @Test func unprotectedObserveIsAProblem() {
        let s = OverallStatus.evaluate(objects: [object(.unprotectedObserve(until: Date(timeIntervalSince1970: 0)))], collector: healthy)
        #expect(s.level == .problem)
    }

    @Test func unmanagedInstanceIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object(unmanaged: 1)], collector: healthy).level == .problem)
    }

    @Test func instanceDetachedFromLaunchdNeedsAttention() {
        var detached = object()
        detached.detachedInstances = 1
        let s = OverallStatus.evaluate(objects: [detached], collector: healthy)
        #expect(s.level == .attention)
        #expect(s.reasons == ["knodo：已脱离 launchd 看护"])
    }

    @Test func staleStatusIsNeverAllGood() {
        let s = OverallStatus.evaluate(objects: [object()], collector: healthy, freshness: .stale(confirmedAt: nil))
        #expect(s.level == .attention)
        #expect(s.reasons.contains { $0.hasPrefix("状态待确认") })
    }

    @Test func freshnessExpires() {
        let t = Date(timeIntervalSince1970: 1_000)
        #expect(StatusFreshness.evaluate(confirmedAt: t, now: t.addingTimeInterval(StatusFreshness.maxAge)) == .current)
        #expect(StatusFreshness.evaluate(confirmedAt: t, now: t.addingTimeInterval(StatusFreshness.maxAge + 1)) == .stale(confirmedAt: t))
        #expect(StatusFreshness.evaluate(confirmedAt: nil, now: t) == .stale(confirmedAt: nil))
    }

    @Test func unknownProtectionIsAttention() {
        #expect(OverallStatus.evaluate(objects: [object(.unknown)], collector: healthy).level == .attention)
    }

    @Test func incompleteRevisionIsAttention() {
        let s = OverallStatus.evaluate(objects: [object(revision: .oldInstancesAlive(residual: [], newInstanceRunning: true))], collector: healthy)
        #expect(s.level == .attention)
    }

    @Test func failedVerificationIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object(revision: .verificationFailed)], collector: healthy).level == .problem)
    }

    @Test func pendingItemsAndLearningAreAttention() {
        #expect(OverallStatus.evaluate(objects: [object(pending: 3)], collector: healthy).level == .attention)
        #expect(OverallStatus.evaluate(objects: [object(.restrictedLearning)], collector: healthy).level == .attention)
    }

    @Test func worstLevelWinsAndReasonsAreCollected() {
        let s = OverallStatus.evaluate(objects: [object(pending: 1), object(unmanaged: 2)], collector: healthy)
        #expect(s.level == .problem)
        #expect(s.reasons.count == 2)
    }
}
