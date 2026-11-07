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
        #expect(s.reasons == ["knodo：启动入口已退出，程序异常后可能不会自动重启"])
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

    @Test func unknownProtectionIsExplainedByItsRevision() {
        let s = OverallStatus.evaluate(objects: [object(.unknown, revision: .awaitingVerification)], collector: healthy)
        #expect(s.level == .attention)
        #expect(s.reasons == ["knodo：正在确认保护"])
    }

    @Test func untrackedCopiesNeedAttention() {
        var o = object()
        o.untrackedInstances = 1
        #expect(OverallStatus.evaluate(objects: [o], collector: healthy).reasons == ["knodo：子进程跟踪记录不完整"])
    }

    @Test func incompleteRevisionIsAttention() {
        let s = OverallStatus.evaluate(objects: [object(revision: .oldInstancesAlive(residual: [], newInstanceRunning: true))], collector: healthy)
        #expect(s.level == .attention)
    }

    @Test func failedVerificationIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object(revision: .verificationFailed)], collector: healthy).level == .problem)
    }

    @Test func pendingItemsAreAttentionButRecordingMoreIsNot() {
        #expect(OverallStatus.evaluate(objects: [object(pending: 3)], collector: healthy).level == .attention)
        // Recording more activity still blocks whatever is not allowed.
        #expect(OverallStatus.evaluate(objects: [object(.restrictedLearning)], collector: healthy) == .allGood)
    }

    @Test func worstLevelWinsAndReasonsAreCollected() {
        let s = OverallStatus.evaluate(objects: [object(pending: 1), object(unmanaged: 2)], collector: healthy)
        #expect(s.level == .problem)
        #expect(s.reasons.count == 2)
    }
}
