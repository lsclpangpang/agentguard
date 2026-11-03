import Foundation
import Testing
@testable import GuardCore

@Suite struct ReviewFollowUpTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let launcherProcess = ProcessKey(pid: 20, version: 1)
    let token = Data("ok".utf8)

    func service(_ store: ProfileStore = ProfileStore(root: "/store", files: InMemoryFileStore())) -> HelperService {
        var counter = 0
        return HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                             verifier: FakeVerifier(accept: true), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                             makeID: { counter += 1; return "c\(counter)" })
    }

    func create(_ s: HelperService, _ profile: Profile) {
        guard case let .pending(info) = s.handle(.proposeChange(profile: profile), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return
        }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: token), caller: F.appCaller, process: appProcess)
    }

    func launch(label: String?) -> LaunchSettings {
        LaunchSettings(executable: "/opt/knodo/knodo-agentd", arguments: [], workingDirectory: nil, originalLabel: label, restartOnCleanExit: false)
    }

    // MARK: Original launch labels

    @Test(arguments: ["../../../Library/Preferences/x", "a/b", "..", "", " com.example", "com.example agent",
                      "com.lsclpangpang.agentguard.managed.other", "com.lsclpangpang.agentguard.helper"])
    func unsafeOriginalLabelsAreRejected(_ label: String) {
        var profile = F.profile()
        profile.launch = launch(label: label)
        #expect(throws: CompileError.invalidLaunchLabel(label)) { try F.compile(profile) }
    }

    @Test func reverseDNSOriginalLabelsAreAccepted() throws {
        var profile = F.profile()
        profile.launch = launch(label: "com.knodo.restricted-agent_2")
        #expect(try F.compile(profile).launch?.originalLabel == "com.knodo.restricted-agent_2")
    }

    @Test func theSummaryNamesTheReplacedLaunchItem() throws {
        var profile = F.profile(revision: 2)
        profile.launch = launch(label: "com.knodo.restricted-agent")
        let diff = PolicyDiff(from: try F.compile(F.profile()), to: try F.compile(profile))
        #expect(diff.summaryLines.contains("~ 启动程序：/opt/knodo/knodo-agentd（替换原启动项 com.knodo.restricted-agent）"))
    }

    // MARK: Unmanaged detection

    @Test func childrenOfARestoredRootAreManagedEvenWhenLineageWasNotObserved() {
        // After a Helper restart only the instance's root is restored; its children were never seen forking.
        var tracker = InstanceTracker()
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: ProcessKey(pid: 100, version: 77), restored: true)
        let running = [
            RunningProcess(key: ProcessKey(pid: 100, version: 0), executablePath: "/bin/sh", parentPID: 1),
            RunningProcess(key: ProcessKey(pid: 101, version: 0), executablePath: "/opt/knodo/knodo-agentd", parentPID: 100),
            RunningProcess(key: ProcessKey(pid: 102, version: 0), executablePath: "/opt/knodo/knodo-agentd", parentPID: 101),
            RunningProcess(key: ProcessKey(pid: 200, version: 0), executablePath: "/opt/knodo/knodo-agentd", parentPID: 1),
        ]
        let found = UnmanagedDetector.detect(running: running, tracker: tracker, targets: ["knodo": ["/opt/knodo/knodo-agentd"]],
                                             resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(found == ["knodo": [ProcessKey(pid: 200, version: 0)]])
    }

    @Test func aParentCycleInTheListingDoesNotHang() {
        let running = [
            RunningProcess(key: ProcessKey(pid: 300, version: 0), executablePath: "/opt/tool", parentPID: 301),
            RunningProcess(key: ProcessKey(pid: 301, version: 0), executablePath: "/opt/tool", parentPID: 300),
        ]
        let found = UnmanagedDetector.detect(running: running, tracker: InstanceTracker(), targets: ["t": ["/opt/tool"]],
                                             resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(found["t"]?.count == 2)
    }

    // MARK: Deletion

    @Test func deletingCanRestoreTheOriginalLaunchItem() {
        let s = service()
        var profile = F.profile()
        profile.launch = launch(label: "com.knodo.restricted-agent")
        create(s, profile)
        #expect(s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: true, authorization: token), caller: F.appCaller, process: appProcess)
            == .deleted(profileID: "knodo", restoreOriginalLabel: "com.knodo.restricted-agent"))
    }

    @Test func deletingWithoutRestoreLeavesTheOriginalAlone() {
        let s = service()
        var profile = F.profile()
        profile.launch = launch(label: "com.knodo.restricted-agent")
        create(s, profile)
        #expect(s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: appProcess)
            == .deleted(profileID: "knodo", restoreOriginalLabel: nil))
    }

    @Test func aManagedProcessCannotDeleteAProfile() {
        let s = service()
        create(s, F.profile())
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: launcherProcess)
        let child = ProcessKey(pid: 21, version: 1)
        s.ingest(.fork(parent: launcherProcess, child: child))
        #expect(s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: child)
            == .failure(code: "managed_caller"))
    }

    @Test func aProposalMadeBeforeDeletionCannotBeApprovedAfterARecreate() {
        let s = service()
        create(s, F.profile())
        guard case let .pending(stale) = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/x")], revision: 2)), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return
        }
        _ = s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: appProcess)
        create(s, F.profile())
        #expect(s.handle(.approveChange(changeID: stale.id, digest: stale.digest, authorization: token), caller: F.appCaller, process: appProcess)
            == .failure(code: "unknown_change"))
    }

    @Test func aRecreatedProfileDoesNotInheritOldInstances() {
        let s = service()
        create(s, F.profile())
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: launcherProcess)
        s.ingest(.gap)
        s.ingest(.exit(launcherProcess))
        _ = s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: appProcess)
        create(s, F.profile())
        #expect(s.instances(ofProfile: "knodo").isEmpty)
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else { Issue.record("status"); return }
        #expect(report.profiles.first?.revisionState == .applied(running: false))
    }

    @Test func archivingTwiceInTheSameSecondKeepsBothCopies() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let s = service(store)
        create(s, F.profile())
        _ = s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: appProcess)
        create(s, F.profile())
        #expect(s.handle(.deleteProfile(profileID: "knodo", restoreOriginal: false, authorization: token), caller: F.appCaller, process: appProcess)
            == .deleted(profileID: "knodo", restoreOriginalLabel: nil))
        #expect(try store.archivedProfiles().count == 2)
    }

    @Test func movingOntoAnExistingPathFails() throws {
        let files = InMemoryFileStore()
        try files.writeAtomically(Data("a".utf8), to: "/a/x")
        try files.writeAtomically(Data("b".utf8), to: "/b/x")
        #expect(throws: (any Error).self) { try files.move("/a", to: "/b") }
        #expect(try files.read("/b/x") == Data("b".utf8))
    }

    // MARK: LaunchAgent labels

    @Test func managedLabelsMatchOnlyTheirOwnProfile() {
        let prefix = "com.example.agentguard.managed"
        #expect(LaunchAgentDefinition.isManagedLabel("com.example.agentguard.managed.knodo", profileID: "knodo", labelPrefix: prefix))
        #expect(LaunchAgentDefinition.isManagedLabel("com.example.agentguard.managed.knodo.1a2b3c4d", profileID: "knodo", labelPrefix: prefix))
        #expect(!LaunchAgentDefinition.isManagedLabel("com.example.agentguard.managed.knodo-work", profileID: "knodo", labelPrefix: prefix))
        #expect(!LaunchAgentDefinition.isManagedLabel("com.example.agentguard.managed.knodo-work.1a2b3c4d", profileID: "knodo", labelPrefix: prefix))
        #expect(!LaunchAgentDefinition.isManagedLabel("com.knodo.restricted-agent", profileID: "knodo", labelPrefix: prefix))
    }

    @Test func onlyRestoredRootsVouchForUnobservedDescendants() {
        // A stale owner entry whose PID was reused by a terminal must not hide everything started from it.
        var tracker = InstanceTracker()
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: ProcessKey(pid: 500, version: 3))
        let running = [
            RunningProcess(key: ProcessKey(pid: 500, version: 0), executablePath: "/bin/zsh", parentPID: 1),
            RunningProcess(key: ProcessKey(pid: 501, version: 0), executablePath: "/opt/tool", parentPID: 500),
        ]
        let found = UnmanagedDetector.detect(running: running, tracker: tracker, targets: ["t": ["/opt/tool"]],
                                             resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(found == ["t": [ProcessKey(pid: 501, version: 0)]])
    }

    // MARK: Profiles that no longer compile

    func storeWithUncompilableProfile() throws -> ProfileStore {
        let files = InMemoryFileStore()
        let store = ProfileStore(root: "/store", files: files)
        var broken = F.profile()
        broken.launch = launch(label: "bad label")
        try files.writeAtomically(try ProfileCodec.encode(broken), to: "/store/profiles/knodo/1.json")
        var other = F.profile()
        other.id = "other"
        try files.writeAtomically(try ProfileCodec.encode(other), to: "/store/profiles/other/1.json")
        return store
    }

    @Test func oneUncompilableProfileDoesNotHideTheStatusOfTheOthers() throws {
        let s = service(try storeWithUncompilableProfile())
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else {
            Issue.record("expected status"); return
        }
        #expect(report.profiles.map(\.profileID) == ["knodo", "other"])
    }

    @Test func anUncompilableProfileCanBeRepairedWithAuthorization() throws {
        let s = service(try storeWithUncompilableProfile())
        var fixed = F.profile(revision: 2)
        fixed.launch = launch(label: "com.knodo.restricted-agent")
        guard case let .pending(info) = s.handle(.proposeChange(profile: fixed), caller: F.appCaller, process: appProcess) else {
            Issue.record("expected a proposal"); return
        }
        // Compared against an empty policy, so everything the repaired revision grants needs authorization.
        #expect(info.requiresAuthorization)
    }

    @Test func deletingWithRestoreUsesItsOwnAuthorizationScope() {
        #expect(HelperService.authorizationScope(forDeletion: "knodo", restoreOriginal: true) == "delete.restore.knodo")
        #expect(HelperService.authorizationScope(forDeletion: "knodo", restoreOriginal: false) == "delete.knodo")
    }
}
