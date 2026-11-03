import Testing
@testable import GuardCore

@Suite struct RevisionStateTests {
    let p1 = ProcessKey(pid: 100, version: 1)
    let p2 = ProcessKey(pid: 101, version: 1)
    let p3 = ProcessKey(pid: 200, version: 1)

    func snap(_ id: Int, rev: Int, live: Set<ProcessKey>, confirmed: Bool = true) -> InstanceSnapshot {
        InstanceSnapshot(id: id, profileID: "knodo", revision: rev, liveProcesses: live, lifecycleConfirmed: confirmed)
    }

    @Test func stoppedObjectIsApplied() {
        let s = RevisionState.evaluate(savedRevision: 5, instances: [snap(1, rev: 4, live: [])], verified: [:])
        #expect(s == .applied(running: false))
        #expect(s.isComplete)
    }

    @Test func oldInstanceStillRunningWithoutNewInstanceIsPending() {
        let s = RevisionState.evaluate(savedRevision: 5, instances: [snap(1, rev: 4, live: [p1])], verified: [:])
        #expect(s == .oldInstancesAlive(residual: [p1], newInstanceRunning: false))
        #expect(!s.isComplete)
    }

    @Test func oldDescendantsBlockCompletionEvenWhenNewInstanceRuns() {
        let s = RevisionState.evaluate(
            savedRevision: 5,
            instances: [snap(1, rev: 4, live: [p2]), snap(2, rev: 5, live: [p3])],
            verified: [2: true]
        )
        #expect(s == .oldInstancesAlive(residual: [p2], newInstanceRunning: true))
        #expect(!s.isComplete)
    }

    @Test func unconfirmedOldLifecycleBlocksCompletion() {
        let s = RevisionState.evaluate(
            savedRevision: 5,
            instances: [snap(1, rev: 4, live: [], confirmed: false), snap(2, rev: 5, live: [p3])],
            verified: [2: true]
        )
        #expect(s == .unconfirmed(instances: [1]))
    }

    @Test func newInstanceMustPassVerification() {
        let instances = [snap(1, rev: 4, live: []), snap(2, rev: 5, live: [p3])]
        #expect(RevisionState.evaluate(savedRevision: 5, instances: instances, verified: [:]) == .awaitingVerification)
        #expect(RevisionState.evaluate(savedRevision: 5, instances: instances, verified: [2: false]) == .verificationFailed)
        #expect(RevisionState.evaluate(savedRevision: 5, instances: instances, verified: [2: true]) == .applied(running: true))
    }

    @Test func instanceRunningANewerRevisionThanSavedIsInconsistent() {
        let s = RevisionState.evaluate(savedRevision: 5, instances: [snap(2, rev: 6, live: [p3])], verified: [2: true])
        #expect(s == .inconsistent)
    }
}
