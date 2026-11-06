import Foundation
import Testing
@testable import GuardCore

@Suite struct HelperActivityTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let cliProcess = ProcessKey(pid: 20, version: 1)
    let store = ProfileStore(root: "/store", files: InMemoryFileStore())
    let activity = ActivityStore(root: "/store", files: InMemoryFileStore())

    func service(accept: Bool = true) throws -> HelperService {
        var counter = 0
        let s = HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                              verifier: FakeVerifier(accept: accept), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                              makeID: { counter += 1; return "c\(counter)" }, activity: activity)
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/work")])), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return s
        }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        return s
    }

    func pending(_ s: HelperService) -> [PendingItem] {
        guard case let .pendingItems(items) = s.handle(.pendingItems(profileID: "knodo"), caller: F.appCaller, process: appProcess) else { return [] }
        return items
    }

    func log(_ s: HelperService) -> ActivityLog? {
        guard case let .activity(log) = s.handle(.activity(profileID: "knodo"), caller: F.appCaller, process: appProcess) else { return nil }
        return log
    }

    @Test func blockedAndObservedAccessesAreToldApart() throws {
        let s = try service()
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) file-read-data /Users/me/secret.txt")))
        s.observe(line: ESLine(globalSequence: 1, process: cliProcess, executablePath: nil, kind: .open(path: "/Users/me/notes.txt", write: false)))
        let items = pending(s)
        let blocked = items.first { $0.suggestion == .file(path: "/Users/me/secret.txt", kind: .file, access: .readOnly) }
        let observed = items.first { $0.suggestion == .file(path: "/Users/me/notes.txt", kind: .file, access: .readOnly) }
        #expect(blocked?.wasBlocked == true)
        #expect(observed?.wasBlocked == false)
        #expect(blocked?.lastSeen == Date(timeIntervalSince1970: 1_800_000_000))
    }

    @Test func keepBlockedArchivesOnlyRefusedItems() throws {
        let s = try service()
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) file-read-data /Users/me/secret.txt")))
        s.observe(line: ESLine(globalSequence: 1, process: cliProcess, executablePath: nil, kind: .open(path: "/Users/me/notes.txt", write: false)))
        let blocked = Suggestion.file(path: "/Users/me/secret.txt", kind: .file, access: .readOnly)
        let observed = Suggestion.file(path: "/Users/me/notes.txt", kind: .file, access: .readOnly)

        #expect(s.handle(.decide(profileID: "knodo", suggestion: observed, decision: .keepBlocked), caller: F.appCaller, process: appProcess)
            == .failure(code: "not_blocked"))
        #expect(s.handle(.decide(profileID: "knodo", suggestion: blocked, decision: .keepBlocked), caller: F.appCaller, process: appProcess) == .ok)
        #expect(s.handle(.decide(profileID: "knodo", suggestion: observed, decision: .dismissed), caller: F.appCaller, process: appProcess) == .ok)
        #expect(pending(s).isEmpty)

        // The same refusal again is merged into the archived item, not raised anew.
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) file-read-data /Users/me/secret.txt")))
        #expect(pending(s).isEmpty)
        let archived = log(s)?.archived.first { $0.decision.suggestion == blocked }
        #expect(archived?.decision.decision == .keepBlocked)
        #expect(archived?.current?.evidence == 2)
        #expect(log(s)?.history.first?.title == "不再提示：读取文件 /Users/me/notes.txt（权限没有改变）")

        #expect(s.handle(.decide(profileID: "knodo", suggestion: blocked, decision: .reopened), caller: F.appCaller, process: appProcess) == .ok)
        #expect(pending(s).map(\.suggestion) == [blocked])
    }

    @Test func historyRecordsChangesAndStarts() throws {
        let s = try service()
        let titles = log(s)?.history.map(\.title) ?? []
        #expect(titles == ["运行副本 #1 已启动", "权限已保存为修订 1"])
        #expect(log(s)?.history.last?.details == ["+ 读写目录 /Users/me/work"])
    }

    @Test func stopAndLoginSettingGoToThePlatform() throws {
        let s = try service()
        #expect(s.handle(.stopManaged(profileID: "knodo"), caller: F.appCaller, process: appProcess) == .stopManaged(profileID: "knodo"))
        #expect(s.handle(.applyLoginSetting(profileID: "knodo"), caller: F.appCaller, process: appProcess) == .failure(code: "no_launch_settings"))
        #expect(s.handle(.stopManaged(profileID: "knodo"), caller: F.cliCaller, process: appProcess) == .failure(code: "not_trusted"))
    }

    @Test func disablingAnotherLaunchItemNeedsAuthorizationAndASafeLabel() throws {
        let s = try service()
        let token = Data("ok".utf8)
        #expect(s.handle(.disableLaunchItem(profileID: "knodo", label: "../evil", path: "/x", authorization: token), caller: F.appCaller, process: appProcess)
            == .failure(code: "invalid_launch_item"))
        #expect(s.handle(.disableLaunchItem(profileID: "knodo", label: "com.example.agent", path: "/Users/me/Library/LaunchAgents/a.plist", authorization: nil),
                         caller: F.appCaller, process: appProcess) == .failure(code: "authorization_missing"))
        #expect(s.handle(.disableLaunchItem(profileID: "knodo", label: "com.example.agent", path: "/Users/me/Library/LaunchAgents/a.plist", authorization: token),
                         caller: F.appCaller, process: appProcess) == .disableLaunchItem(label: "com.example.agent", path: "/Users/me/Library/LaunchAgents/a.plist"))
    }

    @Test func uninstallListsEveryProfile() throws {
        let s = try service()
        #expect(s.handle(.uninstall(restoreOriginals: false, authorization: nil), caller: F.appCaller, process: appProcess) == .failure(code: "authorization_missing"))
        #expect(s.handle(.uninstall(restoreOriginals: true, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
            == .uninstall(targets: [UninstallTarget(profileID: "knodo", hasLaunchSettings: false, restoreOriginalLabel: nil)]))
    }

    @Test func statusCarriesProtocolVersion() throws {
        let s = try service()
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else { Issue.record("no status"); return }
        #expect(report.helperProtocol == HelperProtocol.version)
        let old = try JSONDecoder().decode(StatusReport.self, from: Data(#"{"profiles":[],"collectorProblems":[]}"#.utf8))
        #expect(old.helperProtocol == 0)
    }
}

@Suite struct TrackingCompletenessTests {
    @Test func restoredInstanceAdoptsDescendantsButStaysIncomplete() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 100, version: 7)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root, restored: true)
        let processes = [
            RunningProcess(key: ProcessKey(pid: 101, version: 0), executablePath: "/bin/sh", parentPID: 100),
            RunningProcess(key: ProcessKey(pid: 102, version: 0), executablePath: "/bin/cat", parentPID: 101),
            RunningProcess(key: ProcessKey(pid: 200, version: 0), executablePath: "/bin/zsh", parentPID: 1),
        ]
        let adopted = tracker.adoptDescendants(of: processes, birth: { UInt64($0) * 10 })
        #expect(Set(adopted.keys.map(\.pid)) == [101, 102])
        #expect(tracker.owner(ofPID: 102) == 1)
        #expect(tracker.owner(ofPID: 200) == nil)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == true)
        // A second scan adds nothing new.
        #expect(tracker.adoptDescendants(of: processes, birth: { UInt64($0) * 10 }).isEmpty)
    }

    @Test func observedInstancesAreNotAdoptedInto() {
        var tracker = InstanceTracker()
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: ProcessKey(pid: 100, version: 1))
        let child = RunningProcess(key: ProcessKey(pid: 101, version: 0), executablePath: "/bin/sh", parentPID: 100)
        #expect(tracker.adoptDescendants(of: [child], birth: { _ in 1 }).isEmpty)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == false)
        tracker.handle(.gap)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == true)
    }

    @Test func stopOutcomeSaysWhatIsUnconfirmed() {
        let complete = StopOutcome(stopped: [3, 1], forced: [2])
        #expect(complete.isComplete)
        #expect(complete.confirmed == ["已停止 3 个受管进程（PID 1、2、3）", "其中 PID 2 没有及时退出，已强制结束"])
        let partial = StopOutcome(stopped: [1], survivors: [4], skipped: [5], untrackedInstances: [2])
        #expect(!partial.isComplete)
        #expect(partial.unconfirmed.count == 3)
        #expect(StopOutcome().confirmed == ["没有需要停止的受管进程"])
    }
}
