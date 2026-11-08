import Testing
@testable import GuardCore

@Suite struct InstanceTrackerTests {
    @Test func observedRecoveryKeySuppliesMigrationAndSurvivesNextPlatformReconciliation() throws {
        var t = InstanceTracker()
        let born: UInt64 = 1_700_000_000_123_456
        let placeholder = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: born))
        let observed = ProcessKey(pid: 20, version: 7)
        t.register(instance: 4, profileID: "knodo", revision: 47, root: placeholder, restored: true,
            runUUID: "same-run", instanceOrigin: "previous-helper", bootSessionID: "same-boot", rootStartTime: born)
        var platformBirths = [placeholder: born]
        _ = t.adoptDescendants(of: [], knownBirths: platformBirths, birth: { $0 == 20 ? born : nil })
        t.handle(.gap)
        let resolved = t.resolveObservedProcess(observed, startTime: born)
        let result = try #require(resolved)
        #expect(result.instance == 4 && result.previousKey == placeholder)
        platformBirths.removeValue(forKey: try #require(result.previousKey))
        platformBirths[observed] = born
        _ = t.adoptDescendants(of: [], knownBirths: platformBirths, birth: { $0 == 20 ? born : nil })
        let snapshot = try #require(t.snapshot(of: 4))
        #expect(snapshot.liveProcesses == [observed] && snapshot.entry == observed)
        #expect(snapshot.runUUID == "same-run" && snapshot.revision == 47 && snapshot.bootSessionID == "same-boot")
        #expect(snapshot.trackingIncomplete && !snapshot.lifecycleConfirmed)
        t.handle(.exit(observed))
        let reused = t.resolveObservedProcess(.init(pid: 20, version: 8), startTime: born + 1)
        #expect(reused == nil)
        #expect(!t.isRunning(4))
    }

    @Test func adoptedChildBirthMigrationStaysWithinItsInstanceAndSurvivesReconciliation() throws {
        var t = InstanceTracker()
        let rootBorn: UInt64 = 1_700_000_000_123_456
        let childBorn = rootBorn + 1_000
        let placeholder = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: rootBorn))
        let parent = ProcessKey(pid: 20, version: 7)
        let child = ProcessKey(pid: 21, version: 8)
        t.register(instance: 4, profileID: "knodo", revision: 47, root: placeholder, restored: true,
            runUUID: "same-run", bootSessionID: "same-boot", rootStartTime: rootBorn)
        var platformBirths = [placeholder: rootBorn]
        let birth: (Int32) -> UInt64? = { $0 == 20 ? rootBorn : $0 == 21 ? childBorn : nil }
        let adopted = t.adoptDescendants(
            of: [.init(key: child, executablePath: "/child", parentPID: 20, startTime: childBorn)],
            knownBirths: platformBirths, birth: birth)
        platformBirths.merge(adopted) { _, new in new }
        let rootResolution = t.resolveObservedProcess(parent, startTime: rootBorn)
        let rootMigration = try #require(rootResolution)
        platformBirths.removeValue(forKey: try #require(rootMigration.previousKey))
        platformBirths[parent] = rootBorn
        let wrongInstance = t.resolveObservedProcess(child, startTime: childBorn, expectedInstance: 99)
        #expect(wrongInstance == nil)
        let childResolution = t.resolveObservedProcess(child, startTime: childBorn, expectedInstance: 4)
        let childMigration = try #require(childResolution)
        platformBirths.removeValue(forKey: try #require(childMigration.previousKey))
        platformBirths[child] = childBorn
        t.handle(.fork(parent: parent, child: child))
        _ = t.adoptDescendants(of: [], knownBirths: platformBirths, birth: birth)
        #expect(t.liveProcesses(of: 4) == [parent, child])
        #expect(Set(platformBirths.keys) == [parent, child])
        let stillWrongInstance = t.resolveObservedProcess(child, startTime: childBorn, expectedInstance: 99)
        #expect(stillWrongInstance == nil)
        #expect(t.snapshot(of: 4)?.runUUID == "same-run" && t.snapshot(of: 4)?.trackingIncomplete == true)
    }

    let root = ProcessKey(pid: 100, version: 1)
    let a = ProcessKey(pid: 101, version: 1)
    let b = ProcessKey(pid: 102, version: 1)

    func tracker() -> InstanceTracker {
        var t = InstanceTracker()
        t.register(instance: 1, profileID: "knodo", revision: 3, root: root)
        return t
    }

    func launchdTracker() -> InstanceTracker {
        var t = InstanceTracker()
        t.register(instance: 1, profileID: "knodo", revision: 3, root: root, supervisedByLaunchd: true)
        return t
    }

    @Test func entryThatBackgroundsItsWorkAndExitsLeavesTheInstanceDetached() {
        var t = launchdTracker()
        t.handle(.fork(parent: root, child: a))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == false)
        t.handle(.exit(root))
        #expect(t.isRunning(1))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == true)
    }

    @Test func entryThatExecsTheDaemonStaysSupervised() {
        var t = launchdTracker()
        let daemon = ProcessKey(pid: 100, version: 2)
        t.handle(.exec(from: root, to: daemon))
        t.handle(.fork(parent: daemon, child: a))
        t.handle(.exit(a))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == false)
        t.handle(.exit(daemon))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == false)
    }

    @Test func instanceIsNoLongerDetachedOnceEveryProcessHasExited() {
        var t = launchdTracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.exit(root))
        t.handle(.exit(a))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == false)
    }

    @Test func interactiveRunsAreNeverReportedAsDetached() {
        var t = tracker()
        t.handle(.fork(parent: root, child: a))
        t.handle(.exit(root))
        #expect(t.snapshot(of: 1)?.detachedFromLaunchd == false)
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
