import Foundation
import Testing
@testable import GuardCore

@Suite struct ProgramsTests {
    typealias F = Fixtures

    @Test func profilesWithoutProgramsStillDecode() throws {
        var profile = F.profile()
        profile.programs = []
        var object = try JSONSerialization.jsonObject(with: ProfileCodec.encode(profile)) as! [String: Any]
        object.removeValue(forKey: "programs")
        let data = try JSONSerialization.data(withJSONObject: object)
        #expect(try ProfileCodec.decode(data).programs == [])
    }

    @Test func programsRoundTrip() throws {
        var profile = F.profile()
        profile.programs = ["/opt/homebrew/bin/claude"]
        #expect(try ProfileCodec.decode(ProfileCodec.encode(profile)).programs == ["/opt/homebrew/bin/claude"])
    }

    @Test func programsAreCanonicalAndGetExecAndReadGrants() throws {
        var profile = F.profile()
        profile.programs = ["/tmp/tool", "/tmp/tool"]
        let policy = try F.compile(profile)
        #expect(policy.programs == ["/private/tmp/tool"])
        #expect(policy.exec.contains { $0.path == "/private/tmp/tool" })
        #expect(policy.files.contains { $0.path == "/private/tmp/tool" && $0.kind == .file && $0.access == .readOnly })
    }

    @Test func addingAProgramIsShownAndNeedsAuthorizationThroughItsExecGrant() throws {
        let before = try F.compile(F.profile())
        var profile = F.profile(revision: 2)
        profile.programs = ["/usr/local/bin/tool"]
        let diff = PolicyDiff(from: before, to: try F.compile(profile))
        #expect(diff.changes.contains(.programAdded("/usr/local/bin/tool")))
        #expect(!PolicyChange.programAdded("/usr/local/bin/tool").expands)
        #expect(diff.requiresAuthorization)
        #expect(diff.summaryLines.contains("+ 受管程序 /usr/local/bin/tool"))
    }

    @Test func removingAProgramDoesNotNeedAuthorization() throws {
        var before = F.profile()
        before.programs = ["/usr/local/bin/tool"]
        let diff = PolicyDiff(from: try F.compile(before), to: try F.compile(F.profile(revision: 2)))
        #expect(diff.changes.contains(.programRemoved("/usr/local/bin/tool")))
        #expect(!diff.requiresAuthorization)
        #expect(diff.summaryLines.contains("- 受管程序 /usr/local/bin/tool"))
    }

    @Test func detectionTargetsCombineProgramsAndTheLaunchExecutable() throws {
        var profile = F.profile()
        profile.programs = ["/opt/knodo/knodo-agentd", "/tmp/tool"]
        profile.launch = LaunchSettings(executable: "/opt/knodo/knodo-agentd", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: false)
        #expect(try F.compile(profile).detectionTargets == ["/opt/knodo/knodo-agentd", "/private/tmp/tool"])
    }
}

@Suite struct UnmanagedDetectionWiringTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let launcherProcess = ProcessKey(pid: 20, version: 1)

    func service() -> HelperService {
        var counter = 0
        return HelperService(store: ProfileStore(root: "/store", files: InMemoryFileStore()), environment: F.environment, catalog: TemplateCatalog([]),
                             trust: F.trust, verifier: FakeVerifier(accept: true), settings: F.helperSettings,
                             clock: { Date(timeIntervalSince1970: 1_800_000_000) }, makeID: { counter += 1; return "c\(counter)" })
    }

    func create(_ s: HelperService, _ profile: Profile) {
        guard case let .pending(info) = s.handle(.proposeChange(profile: profile), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return
        }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
    }

    func status(_ s: HelperService) -> ProfileStatusReport? {
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else { return nil }
        return report.profiles.first
    }

    @Test func reportsProgramsRunningOutsideAnyInstance() {
        let s = service()
        var profile = F.profile()
        profile.programs = ["/usr/local/bin/tool"]
        create(s, profile)
        s.updateRunningProcesses([
            RunningProcess(key: ProcessKey(pid: 300, version: 0), executablePath: "/usr/local/bin/tool"),
            RunningProcess(key: ProcessKey(pid: 301, version: 0), executablePath: "/bin/zsh"),
        ])
        #expect(status(s)?.unmanagedProcesses == [300])
    }

    @Test func processesOfAManagedInstanceAreNotUnmanagedEvenWhenListedWithoutVersion() {
        let s = service()
        var profile = F.profile()
        profile.programs = ["/usr/local/bin/tool"]
        create(s, profile)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: launcherProcess)
        // A process listing has no audit-token version, so ownership is matched by PID.
        s.updateRunningProcesses([RunningProcess(key: ProcessKey(pid: 20, version: 0), executablePath: "/usr/local/bin/tool")])
        #expect(status(s)?.unmanagedProcesses == [])
    }

    @Test func statusFromAnOlderHelperDecodesWithoutUnmanagedProcesses() throws {
        let report = ProfileStatusReport(profileID: "knodo", savedRevision: 2, mode: .enforce, revisionState: .applied(running: true),
                                         runningInstances: [1], pendingCount: 0)
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as! [String: Any]
        object.removeValue(forKey: "unmanagedProcesses")
        let data = try JSONSerialization.data(withJSONObject: object)
        #expect(try JSONDecoder().decode(ProfileStatusReport.self, from: data).unmanagedProcesses == [])
    }
}

@Suite struct ProfileDeletionTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let launcherProcess = ProcessKey(pid: 20, version: 1)
    let token = Data("ok".utf8)

    func service(_ store: ProfileStore, accept: Bool = true) -> HelperService {
        var counter = 0
        return HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                             verifier: FakeVerifier(accept: accept), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                             makeID: { counter += 1; return "c\(counter)" })
    }

    func create(_ s: HelperService, _ profile: Profile) {
        guard case let .pending(info) = s.handle(.proposeChange(profile: profile), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return
        }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
    }

    @Test func deletingArchivesTheProfileAndRemovesItFromTheList() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let s = service(store)
        create(s, F.profile())
        #expect(s.handle(.deleteProfile(profileID: "knodo", authorization: token), caller: F.appCaller, process: appProcess) == .deleted(profileID: "knodo"))
        #expect(try store.profileIDs() == [])
        #expect(try store.latest("knodo") == nil)
        #expect(try store.archivedProfiles().count == 1)
    }

    @Test func aDeletedNameCanBeCreatedAgainFromRevisionOne() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let s = service(store)
        create(s, F.profile())
        _ = s.handle(.deleteProfile(profileID: "knodo", authorization: token), caller: F.appCaller, process: appProcess)
        create(s, F.profile(files: [F.ro("/Users/me/notes")]))
        #expect(try store.latest("knodo")?.revision == 1)
        #expect(try store.latest("knodo")?.files == [F.ro("/Users/me/notes")])
    }

    @Test func deletingNeedsTheAppAndAuthorization() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let s = service(store)
        create(s, F.profile())
        #expect(s.handle(.deleteProfile(profileID: "knodo", authorization: token), caller: F.cliCaller, process: launcherProcess) == .failure(code: "not_trusted"))
        let denied = service(store, accept: false)
        #expect(denied.handle(.deleteProfile(profileID: "knodo", authorization: token), caller: F.appCaller, process: appProcess) == .failure(code: "authorization_missing"))
        #expect(try store.profileIDs() == ["knodo"])
    }

    @Test func aProfileWithARunningInstanceCannotBeDeleted() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let s = service(store)
        create(s, F.profile())
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: launcherProcess)
        #expect(s.handle(.deleteProfile(profileID: "knodo", authorization: token), caller: F.appCaller, process: appProcess) == .failure(code: "profile_running"))
        #expect(try store.profileIDs() == ["knodo"])
    }

    @Test func deletingAnUnknownProfileFails() {
        let s = service(ProfileStore(root: "/store", files: InMemoryFileStore()))
        #expect(s.handle(.deleteProfile(profileID: "nope", authorization: token), caller: F.appCaller, process: appProcess) == .failure(code: "unknown_profile"))
    }

    @Test func scopeAndMessagesAreStable() {
        #expect(HelperService.authorizationScope(forDeletion: "knodo") == "delete.knodo")
        #expect(HelperFailure.message(for: "profile_running") != HelperFailure.message(for: "something_else"))
    }
}
