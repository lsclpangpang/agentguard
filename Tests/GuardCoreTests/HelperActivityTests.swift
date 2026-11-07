import Foundation
import Testing
@testable import GuardCore

@Suite struct HelperActivityTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let cliProcess = ProcessKey(pid: 20, version: 1)
    let store = ProfileStore(root: "/store", files: InMemoryFileStore())
    let activity = ActivityStore(root: "/store", files: InMemoryFileStore())

    func service(accept: Bool = true, probe: (any SandboxProbe)? = nil) throws -> HelperService {
        var counter = 0
        let s = HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                              verifier: FakeVerifier(accept: accept), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                              makeID: { counter += 1; return "c\(counter)" }, probe: probe, activity: activity)
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

    @Test func networkDestinationSurvivesActivityResponseAndPendingSamples() throws {
        let s = try service()
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) network-outbound 203.0.113.10:443")))
        let activityLog = try #require(log(s))
        let data = try JSONEncoder().encode(activityLog)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let recent = try #require(object["recent"] as? [[String: Any]])
        #expect(recent.first?["networkTarget"] as? String == "203.0.113.10:443")
        #expect(recent.first?["processName"] as? String == "agent")
        #expect(recent.first?["pid"] as? Int == 20)
        #expect(pending(s).first { $0.suggestion == .outboundTCP }?.samples == ["203.0.113.10:443"])
    }

    @Test func distinctNetworkTargetsSurviveResponseRoundTrip() throws {
        let s = try service()
        for target in ["remote:*:7897", "remote:[2001:db8::7]:8443", "/private/var/run/mDNSResponder"] {
            s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) network-outbound \(target)")))
        }
        // An unrelated process must not have its destinations attached to this profile.
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: other(999) deny(1) network-outbound 203.0.113.20:443")))
        let original = try #require(log(s))
        let decoded = try JSONDecoder().decode(ActivityLog.self, from: JSONEncoder().encode(original))
        #expect(decoded == original)
        #expect(decoded.recent.map(\.networkTarget) == ["/private/var/run/mDNSResponder", "remote:[2001:db8::7]:8443", "remote:*:7897"])
        #expect(decoded.recent.map(\.networkPort) == [nil, 8443, 7897])
        #expect(pending(s).first { $0.suggestion == .outboundTCP }?.samples == ["remote:*:7897", "remote:[2001:db8::7]:8443"])
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

    @Test func stoppedHistoryDoesNotClaimUnobservedChildrenExited() throws {
        let probe = FakeProbe()
        probe.writable = ["/Users/me/work"]
        let s = try service(probe: probe)
        s.ingest(.gap)
        s.ingest(.exit(cliProcess))
        s.verifyInstances()
        let entry = try #require(log(s)?.history.first { $0.kind == .stopped })
        #expect(entry.title == "副本 #1 的已跟踪进程已退出")
        #expect(entry.details.contains { $0.contains("不能据此确认所有子进程") })
        #expect(s.instances(ofProfile: "knodo").first?.trackingIncomplete == true)
        s.verifyInstances()
        #expect(log(s)?.history.filter { $0.kind == .stopped }.count == 1)
    }

    @Test func loginSettingNeedsNoRevision() throws {
        let s = try service()
        var p = F.profile(files: [F.rw("/Users/me/work")], revision: 2)
        p.launch = LaunchSettings(executable: "/bin/x", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: false, runAtLogin: true)
        guard case let .pending(info) = s.handle(.proposeChange(profile: p), caller: F.appCaller, process: appProcess) else { Issue.record("no proposal"); return }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        #expect(s.handle(.setRunAtLogin(profileID: "knodo", enabled: false), caller: F.appCaller, process: appProcess)
            == .relocateLaunchAgent(profileID: "knodo", runAtLogin: false))
        #expect(try store.latest("knodo")?.revision == 2)
        #expect(s.handle(.applyLoginSetting(profileID: "knodo"), caller: F.appCaller, process: appProcess)
            == .relocateLaunchAgent(profileID: "knodo", runAtLogin: false))
    }

    @Test func olderHelperItemsAreNotCalledUnblocked() throws {
        let item = try JSONDecoder().decode(PendingItem.self, from: Data(#"{"suggestion":{"outboundTCP":{}},"sensitive":false,"evidence":3,"samples":[]}"#.utf8))
        #expect(!item.refusalKnown && !item.isSuggestionOnly && !item.wasBlocked)
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
                         caller: F.appCaller, process: appProcess) == .disableLaunchItem(profileID: "knodo", label: "com.example.agent", path: "/Users/me/Library/LaunchAgents/a.plist"))
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
            RunningProcess(key: ProcessKey(pid: 101, version: 0), executablePath: "/bin/sh", parentPID: 100, startTime: 1010),
            RunningProcess(key: ProcessKey(pid: 102, version: 0), executablePath: "/bin/cat", parentPID: 101, startTime: 1020),
            RunningProcess(key: ProcessKey(pid: 200, version: 0), executablePath: "/bin/zsh", parentPID: 1),
        ]
        let adopted = tracker.adoptDescendants(of: processes, knownBirths: [root: 1000], birth: { UInt64($0) * 10 })
        #expect(Set(adopted.keys.map(\.pid)) == [101, 102])
        #expect(tracker.owner(ofPID: 102) == 1)
        #expect(tracker.owner(ofPID: 200) == nil)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == true)
        // A second scan adds nothing new.
        #expect(tracker.adoptDescendants(of: processes, knownBirths: adopted.merging([root: 1000]) { a, _ in a }, birth: { UInt64($0) * 10 }).isEmpty)
    }

    @Test func observedInstancesAreNotAdoptedInto() {
        var tracker = InstanceTracker()
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: ProcessKey(pid: 100, version: 1))
        let child = RunningProcess(key: ProcessKey(pid: 101, version: 0), executablePath: "/bin/sh", parentPID: 100)
        #expect(tracker.adoptDescendants(of: [child], knownBirths: [:], birth: { _ in 1 }).isEmpty)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == false)
        tracker.handle(.gap)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == true)
    }

    @Test func stopOutcomeSaysWhatIsUnconfirmed() {
        let complete = StopOutcome(stopped: [3, 1], forced: [2])
        #expect(complete.isComplete)
        #expect(complete.confirmed == ["已停止本次跟踪到的 3 个进程（PID 1、2、3）", "其中 PID 2 没有及时退出，已强制结束"])
        let partial = StopOutcome(stopped: [1], survivors: [4], skipped: [5], untrackedInstances: [2])
        #expect(!partial.isComplete)
        #expect(partial.unconfirmed.count == 3)
        #expect(StopOutcome().confirmed == ["没有需要停止的受管进程"])
    }
}
