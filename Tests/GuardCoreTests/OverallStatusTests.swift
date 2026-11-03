import Foundation
import Testing
@testable import GuardCore

@Suite struct OverallStatusTests {
    let healthy = CollectorHealth(problems: [])

    func object(_ protection: ProtectionState = .enforced, revision: RevisionState = .applied(running: true), pending: Int = 0, unmanaged: Int = 0) -> ObjectStatus {
        ObjectStatus(profileID: "knodo", protection: protection, revision: revision, pendingItems: pending, unmanagedInstances: unmanaged)
    }

    @Test func allGoodRequiresEveryConditionToHold() {
        #expect(OverallStatus.evaluate(objects: [object()], collector: healthy, capabilityCheckPassed: true) == .allGood)
    }

    @Test func collectorProblemPreventsAllGood() {
        let s = OverallStatus.evaluate(objects: [object()], collector: CollectorHealth(problems: [.droppedEvents(count: 1)]), capabilityCheckPassed: true)
        #expect(s.level == .attention)
    }

    @Test func unprotectedObserveIsAProblem() {
        let s = OverallStatus.evaluate(objects: [object(.unprotectedObserve(until: Date(timeIntervalSince1970: 0)))], collector: healthy, capabilityCheckPassed: true)
        #expect(s.level == .problem)
    }

    @Test func unmanagedInstanceIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object(unmanaged: 1)], collector: healthy, capabilityCheckPassed: true).level == .problem)
    }

    @Test func capabilityFailureIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object()], collector: healthy, capabilityCheckPassed: false).level == .problem)
    }

    @Test func unknownProtectionIsAttention() {
        #expect(OverallStatus.evaluate(objects: [object(.unknown)], collector: healthy, capabilityCheckPassed: true).level == .attention)
    }

    @Test func incompleteRevisionIsAttention() {
        let s = OverallStatus.evaluate(objects: [object(revision: .oldInstancesAlive(residual: [], newInstanceRunning: true))], collector: healthy, capabilityCheckPassed: true)
        #expect(s.level == .attention)
    }

    @Test func failedVerificationIsAProblem() {
        #expect(OverallStatus.evaluate(objects: [object(revision: .verificationFailed)], collector: healthy, capabilityCheckPassed: true).level == .problem)
    }

    @Test func pendingItemsAndLearningAreAttention() {
        #expect(OverallStatus.evaluate(objects: [object(pending: 3)], collector: healthy, capabilityCheckPassed: true).level == .attention)
        #expect(OverallStatus.evaluate(objects: [object(.restrictedLearning)], collector: healthy, capabilityCheckPassed: true).level == .attention)
    }

    @Test func worstLevelWinsAndReasonsAreCollected() {
        let s = OverallStatus.evaluate(objects: [object(pending: 1), object(unmanaged: 2)], collector: healthy, capabilityCheckPassed: true)
        #expect(s.level == .problem)
        #expect(s.reasons.count == 2)
    }
}
