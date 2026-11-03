import Foundation
import Testing
@testable import GuardCore

struct FakeVerifier: AuthorizationVerifier {
    let accept: Bool
    func verify(token: Data?, scope: String, summary: [String]) -> Bool {
        accept && token == Data("ok".utf8)
    }
}

@Suite struct HelperServiceTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let cliProcess = ProcessKey(pid: 20, version: 1)
    let store = ProfileStore(root: "/store", files: InMemoryFileStore())

    func service(accept: Bool = true) -> HelperService {
        var counter = 0
        return HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                             verifier: FakeVerifier(accept: accept), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                             makeID: { counter += 1; return "c\(counter)" })
    }

    func create(_ s: HelperService, _ profile: Profile) throws {
        guard case let .pending(info) = s.handle(.proposeChange(profile: profile), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return
        }
        let result = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        #expect(result == .applied(revision: profile.revision))
    }

    @Test func appCreatesProfileThroughApprovedChange() throws {
        let s = service()
        try create(s, F.profile(files: [F.rw("/Users/me/easyops")], revision: 1))
        #expect(try store.latest("knodo")?.files == [F.rw("/Users/me/easyops")])
        #expect(try store.approval("knodo", revision: 1)?.baseRevision == 0)
    }

    @Test func proposalCarriesExactSummary() {
        let s = service()
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/easyops")])), caller: F.appCaller, process: appProcess) else {
            Issue.record("expected pending"); return
        }
        #expect(info.summary == ["+ 读写目录 /Users/me/easyops"])
        #expect(info.requiresAuthorization)
        #expect(info.baseRevision == 0)
    }

    @Test func approvalWithoutUserAuthorizationChangesNothing() throws {
        let s = service(accept: false)
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/easyops")])), caller: F.appCaller, process: appProcess) else {
            Issue.record("expected pending"); return
        }
        let result = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        #expect(result == .failure(code: "authorization_missing"))
        #expect(try store.latest("knodo") == nil)
    }

    @Test func cliCannotChangePermissions() {
        let s = service()
        #expect(s.handle(.proposeChange(profile: F.profile()), caller: F.cliCaller, process: cliProcess) == .failure(code: "not_trusted"))
        #expect(s.handle(.applyTightening(profile: F.profile()), caller: F.cliCaller, process: cliProcess) == .failure(code: "not_trusted"))
    }

    @Test func managedProcessCannotChangePermissionsEvenWithAppSignature() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        guard case .registered = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess) else {
            Issue.record("register failed"); return
        }
        let descendant = ProcessKey(pid: 21, version: 1)
        s.ingest(.fork(parent: cliProcess, child: descendant))
        let result = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/easyops")], revision: 2)), caller: F.appCaller, process: descendant)
        #expect(result == .failure(code: "managed_caller"))
    }

    @Test func managedProcessCannotStartNestedInstance() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        let child = ProcessKey(pid: 22, version: 1)
        s.ingest(.fork(parent: cliProcess, child: child))
        #expect(s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: child) == .failure(code: "managed_caller"))
    }

    @Test func registeringReturnsCompiledRulesForTheApprovedRevision() throws {
        let s = service()
        try create(s, F.profile(files: [F.rw("/Users/me/easyops")], revision: 1))
        guard case let .registered(instance, sbpl) = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess) else {
            Issue.record("expected registration"); return
        }
        #expect(instance == 1)
        #expect(sbpl.contains("(deny default)"))
        #expect(sbpl.contains("(allow file-read* file-write* (subpath \"/Users/me/easyops\"))"))
    }

    @Test func statusReportsLauncherInstancesWhoseEntryExitedWhileChildrenRun() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        guard case let .registered(instance, _) = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: cliProcess) else {
            Issue.record("expected registration"); return
        }
        let daemon = ProcessKey(pid: 21, version: 1)
        s.ingest(.fork(parent: cliProcess, child: daemon))
        s.ingest(.exit(cliProcess))
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else {
            Issue.record("expected status"); return
        }
        #expect(report.profiles.first?.runningInstances == [instance])
        #expect(report.profiles.first?.detachedInstances == [instance])
    }

    @Test func cliRunsAreNotReportedAsDetached() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        s.ingest(.fork(parent: cliProcess, child: ProcessKey(pid: 21, version: 1)))
        s.ingest(.exit(cliProcess))
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else {
            Issue.record("expected status"); return
        }
        #expect(report.profiles.first?.detachedInstances == [])
    }

    @Test func registeringStaleOrUnknownRevisionFails() throws {
        let s = service()
        #expect(s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: cliProcess) == .failure(code: "unknown_profile"))
        try create(s, F.profile(revision: 1))
        #expect(s.handle(.registerInstance(profileID: "knodo", revision: 2), caller: F.launcherCaller, process: cliProcess) == .failure(code: "stale_revision"))
    }

    @Test func tighteningNeedsNoAuthorization() throws {
        let s = service()
        try create(s, F.profile(files: [F.rw("/Users/me/easyops"), F.ro("/Users/me/docs")], revision: 1))
        #expect(s.handle(.applyTightening(profile: F.profile(files: [F.rw("/Users/me/easyops")], revision: 2)), caller: F.appCaller, process: appProcess) == .applied(revision: 2))
    }

    @Test func tighteningPathRefusesExpansion() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        #expect(s.handle(.applyTightening(profile: F.profile(files: [F.ro("/Users/me/docs")], revision: 2)), caller: F.appCaller, process: appProcess) == .failure(code: "authorization_required"))
    }

    @Test func proposalMustTargetNextRevision() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        #expect(s.handle(.proposeChange(profile: F.profile(revision: 5)), caller: F.appCaller, process: appProcess) == .failure(code: "revision_conflict"))
    }

    @Test func invalidProfileIsRejectedAtProposal() {
        let s = service()
        #expect(s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me")])), caller: F.appCaller, process: appProcess) == .failure(code: "compile_error"))
    }

    @Test func statusReportsRevisionStateOfRunningInstances() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        #expect(s.handle(.reportVerification(instance: 1, passed: true), caller: F.appCaller, process: appProcess) == .ok)
        try create(s, F.profile(files: [F.ro("/Users/me/docs")], revision: 2))
        // The registering process is now part of the instance, so status comes from a fresh CLI invocation.
        let statusProcess = ProcessKey(pid: 30, version: 1)
        let statusResponse = s.handle(.status, caller: F.cliCaller, process: statusProcess)
        guard case let .status(report) = statusResponse else {
            Issue.record("expected status, got \(statusResponse)"); return
        }
        #expect(report.profiles.map(\.profileID) == ["knodo"])
        #expect(report.profiles.first?.savedRevision == 2)
        #expect(report.profiles.first?.revisionState == .oldInstancesAlive(residual: [cliProcess], newInstanceRunning: false))
        s.ingest(.exit(cliProcess))
        guard case let .status(after) = s.handle(.status, caller: F.cliCaller, process: statusProcess) else {
            Issue.record("expected status"); return
        }
        #expect(after.profiles.first?.revisionState == .applied(running: false))
    }

    @Test func untrustedCallerGetsNothing() {
        let s = service()
        let stranger = CallerIdentity(uid: 501, signingIdentifier: "com.evil", teamIdentifier: nil, cdhash: nil, managedInstance: nil)
        #expect(s.handle(.status, caller: stranger, process: ProcessKey(pid: 99, version: 1)) == .failure(code: "not_trusted"))
    }

    @Test func requestsAndResponsesRoundTripAsJSON() throws {
        let requests: [HelperRequest] = [
            .status, .proposeChange(profile: F.profile(files: [F.rw("/Users/me/easyops")])),
            .approveChange(changeID: "c1", digest: "d", authorization: Data("ok".utf8)),
            .registerInstance(profileID: "knodo", revision: 3), .reportVerification(instance: 2, passed: false),
        ]
        for request in requests {
            #expect(try HelperWire.decodeRequest(HelperWire.encode(request)) == request)
        }
        let response = HelperResponse.registered(instance: 4, sbpl: "(version 1)\n")
        #expect(try HelperWire.decodeResponse(HelperWire.encode(response)) == response)
    }

    func agentProfile(revision: Int) -> Profile {
        var p = F.profile(revision: revision)
        p.launch = LaunchSettings(executable: "/opt/knodo/knodo-agentd", arguments: [], workingDirectory: nil, originalLabel: "com.knodo.local-agent", restartOnCleanExit: false)
        return p
    }

    @Test func installingLaunchAgentReturnsDefinitionForApprovedLaunchSettings() throws {
        let s = service()
        try create(s, agentProfile(revision: 1))
        guard case let .launchAgent(label, originalLabel, plist) = s.handle(.installLaunchAgent(profileID: "knodo"), caller: F.appCaller, process: appProcess) else {
            Issue.record("expected launch agent"); return
        }
        #expect(label == "com.example.agentguard.managed.knodo")
        #expect(originalLabel == "com.knodo.local-agent")
        let dict = try #require(try PropertyListSerialization.propertyList(from: plist, format: nil) as? [String: Any])
        #expect(dict["ProgramArguments"] as? [String] == ["/Applications/AgentGuard.app/Contents/MacOS/agentguard-launcher", "launch", "knodo"])
    }

    @Test func installingRequiresLaunchSettingsAndApp() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        #expect(s.handle(.installLaunchAgent(profileID: "knodo"), caller: F.appCaller, process: appProcess) == .failure(code: "no_launch_settings"))
        #expect(s.handle(.installLaunchAgent(profileID: "knodo"), caller: F.cliCaller, process: cliProcess) == .failure(code: "not_trusted"))
    }

    @Test func removingManagementNeedsAuthorizationBoundToTheRemoval() throws {
        let s = service()
        try create(s, agentProfile(revision: 1))
        let denied = service(accept: false)
        try create(denied, agentProfile(revision: 2))
        #expect(denied.handle(.removeManagement(profileID: "knodo", restoreOriginal: true, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
            == .failure(code: "authorization_missing"))
        #expect(s.handle(.removeManagement(profileID: "knodo", restoreOriginal: true, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
            == .removal(label: "com.example.agentguard.managed.knodo", restoreOriginalLabel: "com.knodo.local-agent"))
        #expect(s.handle(.removeManagement(profileID: "knodo", restoreOriginal: false, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
            == .removal(label: "com.example.agentguard.managed.knodo", restoreOriginalLabel: nil))
    }

    @Test func authorizationScopeNamesAreStable() {
        #expect(HelperService.authorizationScope(forChange: "c1") == "change.c1")
        #expect(HelperService.authorizationScope(forRemoval: "knodo") == "remove.knodo")
    }

    @Test func deniedAccessesOfManagedProcessesBecomePendingItems() throws {
        let s = service()
        try create(s, F.profile(files: [F.rw("/Users/me/easyops")], revision: 1))
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: claude(20) deny(1) file-write-create /tmp/claude-501/x")))
        s.observe(denial: try #require(SandboxLogParser.parse("Sandbox: other(999) deny(1) file-read-data /Users/me/secret")))
        let fresh = ProcessKey(pid: 31, version: 1)
        guard case let .pendingItems(items) = s.handle(.pendingItems(profileID: "knodo"), caller: F.appCaller, process: fresh) else {
            Issue.record("expected pending items"); return
        }
        #expect(items.map(\.suggestion) == [.file(path: "/private/tmp/claude-501/x", kind: .file, access: .readWrite)])
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: fresh) else {
            Issue.record("expected status"); return
        }
        #expect(report.profiles.first?.pendingCount == 1)
    }

    @Test func esloggerLinesFeedLifecycleAndObservations() throws {
        let s = service()
        try create(s, F.profile(revision: 1))
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: cliProcess)
        let fork = #"{"global_seq_num":1,"process":{"audit_token":{"pid":20,"pidversion":1}},"event":{"fork":{"child":{"audit_token":{"pid":40,"pidversion":1}}}}}"#
        let open = #"{"global_seq_num":2,"process":{"audit_token":{"pid":40,"pidversion":1}},"event":{"open":{"fflag":1,"file":{"path":"/Users/me/notes.txt"}}}}"#
        s.observe(line: try ESLoggerParser.parse(fork))
        s.observe(line: try ESLoggerParser.parse(open))
        #expect(s.managedInstance(of: ProcessKey(pid: 40, version: 1)) == 1)
        guard case let .pendingItems(items) = s.handle(.pendingItems(profileID: "knodo"), caller: F.appCaller, process: appProcess) else {
            Issue.record("expected pending items"); return
        }
        #expect(items.map(\.suggestion) == [.file(path: "/Users/me/notes.txt", kind: .file, access: .readOnly)])
    }

    @Test func collectorHealthIsReportedInStatus() throws {
        let s = service()
        s.updateCollectorHealth(CollectorHealth(problems: [.droppedEvents(count: 3), .unauthorized]))
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else {
            Issue.record("expected status"); return
        }
        #expect(report.collectorProblems == ["丢失 3 个事件", "未授权（需要完全磁盘访问）"])
    }

    @Test func pendingItemsRequireTheApp() {
        #expect(service().handle(.pendingItems(profileID: "knodo"), caller: F.cliCaller, process: cliProcess) == .failure(code: "not_trusted"))
    }

    @Test func appCanAcknowledgeCollectorProblems() {
        let s = service()
        var acknowledged = 0
        s.onAcknowledgeCollectorProblems = { acknowledged += 1 }
        #expect(s.handle(.acknowledgeCollectorProblems, caller: F.cliCaller, process: cliProcess) == .failure(code: "not_trusted"))
        #expect(s.handle(.acknowledgeCollectorProblems, caller: F.appCaller, process: appProcess) == .ok)
        #expect(acknowledged == 1)
    }
}
