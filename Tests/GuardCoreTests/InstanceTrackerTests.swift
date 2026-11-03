import Testing
@testable import GuardCore

@Suite struct InstanceTrackerTests {
    let root = ProcessKey(pid: 100, version: 1)
    let a = ProcessKey(pid: 101, version: 1)
    let b = ProcessKey(pid: 102, version: 1)

    func tracker() -> InstanceTracker {
        var t = InstanceTracker()
        t.register(instance: 1, profileID: "knodo", revision: 3, root: root)
        return t
    }

    @Test func registeredRootIsLive() {
        let t = tracker()
        #expect(t.liveProcesses(of: 1) == [root])
        #expect(t.isRunning(1))
        #expect(t.owner(of: root) == 1)
        #expect(t.snapshot(of: 1)?.revision == 3)
    }

    @Test func forkedDescendantsBelongToInstance() {
        var t = tracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.fork(parent: a, child: b))
        #expect(t.liveProcesses(of: 1) == [root, a, b])
        #expect(t.owner(of: b) == 1)
    }

    @Test func doubleForkSurvivesIntermediateExit() {
        var t = tracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.fork(parent: a, child: b))
        t.handle(.exit(a))
        t.handle(.exit(root))
        #expect(t.liveProcesses(of: 1) == [b])
        #expect(t.isRunning(1))
    }

    @Test func execReplacesProcessKey() {
        var t = tracker()
        let afterExec = ProcessKey(pid: 100, version: 2)
        t.handle(.exec(from: root, to: afterExec))
        #expect(t.liveProcesses(of: 1) == [afterExec])
        #expect(t.owner(of: root) == nil)
    }

    @Test func pidReuseIsNotAttributed() {
        var t = tracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.exit(a))
        let stranger = ProcessKey(pid: 500, version: 1)
        let reused = ProcessKey(pid: 101, version: 2)
        t.handle(.fork(parent: stranger, child: reused))
        #expect(t.owner(of: reused) == nil)
        #expect(t.liveProcesses(of: 1) == [root])
        t.handle(.exit(reused))
        #expect(t.liveProcesses(of: 1) == [root])
    }

    @Test func exitWithStaleVersionDoesNotRemoveLiveProcess() {
        var t = tracker()
        t.handle(.exit(ProcessKey(pid: 100, version: 0)))
        #expect(t.liveProcesses(of: 1) == [root])
    }

    @Test func forkFromUnknownParentIsIgnored() {
        var t = tracker()
        t.handle(.fork(parent: ProcessKey(pid: 999, version: 1), child: a))
        #expect(t.owner(of: a) == nil)
    }

    @Test func instanceEndsWhenAllProcessesExit() {
        var t = tracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.exit(root))
        #expect(t.isRunning(1))
        t.handle(.exit(a))
        #expect(!t.isRunning(1))
        #expect(t.snapshot(of: 1)?.lifecycleConfirmed == true)
    }

    @Test func eventGapMarksOnlyRunningInstancesUnconfirmed() {
        var t = tracker()
        t.register(instance: 2, profileID: "claude-work", revision: 1, root: a)
        t.handle(.exit(a))
        t.handle(.gap)
        #expect(t.snapshot(of: 1)?.lifecycleConfirmed == false)
        #expect(t.snapshot(of: 2)?.lifecycleConfirmed == true)
    }

    @Test func instancesOfProfile() {
        var t = tracker()
        t.register(instance: 2, profileID: "knodo", revision: 4, root: a)
        t.register(instance: 3, profileID: "claude-work", revision: 1, root: b)
        #expect(t.instances(ofProfile: "knodo").map(\.id).sorted() == [1, 2])
    }
}
