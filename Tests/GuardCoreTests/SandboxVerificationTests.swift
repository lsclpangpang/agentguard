import Foundation
import Testing
@testable import GuardCore

/// Answers like a kernel that enforces exactly `writable`/`readable` path prefixes.
final class FakeProbe: SandboxProbe, @unchecked Sendable {
    var sandboxed: Bool? = true
    var readable: [String] = []
    var writable: [String] = []
    var machAllowed: Set<String> = []
    var unavailable = false
    var missing: Set<String> = []
    private(set) var probedPIDs: [Int32] = []

    func isSandboxed(pid: Int32) -> Bool? {
        probedPIDs.append(pid)
        return sandboxed
    }

    func check(pid: Int32, operation: SandboxOperation, target: String) -> SandboxCheckResult {
        if unavailable { return .unavailable }
        if missing.contains(target) { return .missing }
        func under(_ roots: [String]) -> Bool { roots.contains { target == $0 || target.hasPrefix($0 + "/") } }
        switch operation {
        case .machLookup: return machAllowed.contains(target) ? .allowed : .denied
        case .fileRead: return under(readable + writable) ? .allowed : .denied
        case .fileWrite: return under(writable) ? .allowed : .denied
        }
    }
}

@Suite struct SandboxVerificationTests {
    typealias F = Fixtures

    @Test func matchingSandboxPasses() throws {
        let policy = try F.compile(F.profile(files: [F.rw("/Users/me/work"), F.ro("/Users/me/docs")]))
        let probe = FakeProbe()
        probe.writable = ["/Users/me/work"]
        probe.readable = ["/Users/me/docs"]
        let verdict = SandboxVerification.verify(pid: 7, expectations: SandboxVerification.expectations(for: policy, environment: F.environment), probe: probe)
        #expect(verdict == .passed)
    }

    @Test func readOnlyThatStillWritesFails() throws {
        // What a legacy write rule rendered after the structured grants does to a downgraded path.
        let policy = try F.compile(F.profile(files: [F.ro("/Users/me/docs")], extraRules: [#"(allow file-write* (subpath "/Users/me/docs"))"#]))
        let probe = FakeProbe()
        probe.writable = ["/Users/me/docs"]
        guard case let .failed(issues) = SandboxVerification.verify(pid: 7, expectations: SandboxVerification.expectations(for: policy, environment: F.environment), probe: probe) else {
            Issue.record("expected failure"); return
        }
        #expect(issues == ["设为仅查看的 /Users/me/docs 仍可写入，可能来自旧规则或其他重叠授权"])
    }

    @Test func openDefaultAndHelperAccessFail() throws {
        let policy = try F.compile(F.profile())
        let probe = FakeProbe()
        probe.readable = ["/private/var/empty"]
        probe.machAllowed = [F.environment.helperServiceName]
        guard case let .failed(issues) = SandboxVerification.verify(pid: 7, expectations: SandboxVerification.expectations(for: policy, environment: F.environment), probe: probe) else {
            Issue.record("expected failure"); return
        }
        #expect(issues.contains("受管进程可以连接 AgentGuard Helper"))
        #expect(issues.contains { $0.hasPrefix("未授权的位置 /private/var/empty 可以读取") })
    }

    @Test func unprotectedObservationOnlyChecksBuiltInDenials() throws {
        let policy = try F.compile(F.profile(files: [F.ro("/Users/me/docs")], mode: .unprotectedObserve))
        let operations = SandboxVerification.expectations(for: policy, environment: F.environment)
        #expect(operations.allSatisfy { !$0.allowed })
        #expect(!operations.contains { $0.target.hasPrefix("/Users/me/docs") })
    }

    @Test func unsandboxedAndUnavailableAreNotVerdicts() throws {
        let policy = try F.compile(F.profile())
        let probe = FakeProbe()
        probe.sandboxed = false
        #expect(SandboxVerification.verify(pid: 7, expectations: SandboxVerification.expectations(for: policy, environment: F.environment), probe: probe) == .notSandboxed)
        probe.sandboxed = true
        probe.unavailable = true
        guard case .inconclusive = SandboxVerification.verify(pid: 7, expectations: SandboxVerification.expectations(for: policy, environment: F.environment), probe: probe)
        else { Issue.record("unavailable checks must not pass or fail"); return }
    }

    @Test func directoryAndProtectedChecksUseTheRealObjects() throws {
        let policy = try F.compile(F.profile(files: [F.rw("/Users/me/work")]))
        let expectations = SandboxVerification.expectations(for: policy, environment: F.environment)
        #expect(expectations.contains { $0.target == "/Users/me/work" && $0.operation == .fileWrite && $0.allowed })
        for path in F.environment.protectedPaths + F.environment.writeProtectedPaths {
            #expect(expectations.contains { $0.target == path && $0.operation == .fileWrite && !$0.allowed })
        }
        #expect(!expectations.contains { $0.target.hasSuffix("/.agentguard-probe") })
    }

    @Test func missingPathsProveNeitherAccessNorDenial() {
        let probe = FakeProbe()
        probe.missing = ["/missing"]
        for allowed in [true, false] {
            let expected = [SandboxExpectation(operation: .fileRead, target: "/missing", allowed: allowed, failure: "mismatch"),
                            SandboxExpectation(operation: .fileWrite, target: "/missing", allowed: allowed, failure: "mismatch")]
            #expect(SandboxVerification.verify(pid: 7, expectations: expected, probe: probe)
                    == .inconclusive(["路径暂不存在，尚未核验：/missing"]))
        }
    }

    @Test func missingPathDoesNotConcealARealMismatch() {
        let probe = FakeProbe()
        probe.missing = ["/missing"]
        probe.writable = ["/protected"]
        let expected = [SandboxExpectation(operation: .fileRead, target: "/missing", allowed: true, failure: "missing"),
                        SandboxExpectation(operation: .fileWrite, target: "/protected", allowed: false, failure: "protected writable")]
        #expect(SandboxVerification.verify(pid: 7, expectations: expected, probe: probe) == .failed(["protected writable"]))
    }
}

@Suite struct HelperVerificationTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let store = ProfileStore(root: "/store", files: InMemoryFileStore())

    final class Clock: @unchecked Sendable { var now = Date(timeIntervalSince1970: 1_800_000_000) }

    func service(probe: FakeProbe, clock: Clock = Clock()) throws -> HelperService {
        var counter = 0
        let s = HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                              verifier: FakeVerifier(accept: true), settings: F.helperSettings, clock: { clock.now },
                              makeID: { counter += 1; return "c\(counter)" }, probe: probe)
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile(files: [F.rw("/Users/me/work")])), caller: F.appCaller, process: appProcess) else {
            Issue.record("proposal failed"); return s
        }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        return s
    }

    func status(_ s: HelperService) -> ProfileStatusReport? {
        guard case let .status(report) = s.handle(.status, caller: F.appCaller, process: appProcess) else { return nil }
        return report.profiles.first
    }

    @Test func helperConfirmsOnlyWhatTheKernelEnforces() throws {
        let probe = FakeProbe()
        probe.writable = ["/Users/me/work"]
        probe.sandboxed = false
        let clock = Clock()
        let s = try service(probe: probe, clock: clock)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: ProcessKey(pid: 20, version: 1))
        // Registered, sandbox not yet applied: waiting, not failed and not applied.
        #expect(status(s)?.revisionState == .awaitingVerification)
        probe.sandboxed = true
        #expect(status(s)?.revisionState == .applied(running: true))
        #expect(probe.probedPIDs.last == 20)
    }

    @Test func processThatNeverEntersTheSandboxFailsAfterGrace() throws {
        let probe = FakeProbe()
        probe.sandboxed = false
        let clock = Clock()
        let s = try service(probe: probe, clock: clock)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: ProcessKey(pid: 20, version: 1))
        #expect(status(s)?.revisionState == .awaitingVerification)
        clock.now = clock.now.addingTimeInterval(HelperService.sandboxGracePeriod)
        let report = status(s)
        #expect(report?.revisionState == .verificationFailed)
        #expect(report?.verificationIssues == ["进程没有进入沙箱，它不受这份权限限制"])
    }

    @Test func withoutProbeNothingIsConfirmed() throws {
        var counter = 0
        let s = HelperService(store: store, environment: F.environment, catalog: TemplateCatalog([]), trust: F.trust,
                              verifier: FakeVerifier(accept: true), settings: F.helperSettings, clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                              makeID: { counter += 1; return "c\(counter)" })
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile()), caller: F.appCaller, process: appProcess) else { return }
        _ = s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: F.appCaller, process: appProcess)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: ProcessKey(pid: 20, version: 1))
        #expect(status(s)?.revisionState == .awaitingVerification)
    }

    @Test func managedProcessCannotReachTheHelper() throws {
        let s = try service(probe: FakeProbe())
        let root = ProcessKey(pid: 20, version: 1)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.launcherCaller, process: root)
        #expect(s.handle(.status, caller: F.launcherCaller, process: root) == .failure(code: "managed_caller"))
    }

    @Test func restoredInstanceIsCheckedAgainAndKeepsItsNumber() throws {
        let probe = FakeProbe()
        probe.writable = ["/Users/me/work"]
        let s = try service(probe: probe)
        s.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: ProcessKey(pid: 30, version: 9), supervisedByLaunchd: true)
        #expect(status(s)?.revisionState == .unconfirmed(instances: [4]))
        #expect(status(s)?.verificationIssues.isEmpty == true)
        guard case let .registered(instance, _) = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller,
                                                           process: ProcessKey(pid: 40, version: 1)) else {
            Issue.record("expected registration"); return
        }
        #expect(instance == 5)
        #expect(s.instances(ofProfile: "knodo").map(\.id) == [4, 5])
    }

    @Test func restoredInstanceOutsideTheSandboxFailsAtOnce() throws {
        let probe = FakeProbe()
        probe.sandboxed = false
        let s = try service(probe: probe)
        s.restoreInstance(id: 1, profileID: "knodo", revision: 1, root: ProcessKey(pid: 30, version: 9), supervisedByLaunchd: true)
        #expect(status(s)?.revisionState == .verificationFailed)
    }

    @Test func newTemporaryGrantsAreRefused() throws {
        let s = try service(probe: FakeProbe())
        var temporary = F.ro("/Users/me/docs")
        temporary.expiresAt = Date(timeIntervalSince1970: 1_900_000_000)
        let profile = F.profile(files: [F.rw("/Users/me/work"), temporary], revision: 2)
        #expect(s.handle(.proposeChange(profile: profile), caller: F.appCaller, process: appProcess) == .failure(code: "temporary_grants_unavailable"))
        #expect(s.handle(.applyTightening(profile: profile), caller: F.appCaller, process: appProcess) == .failure(code: "temporary_grants_unavailable"))
    }

    @Test func failedVerificationRecoversAndConfirmedAccessIsRechecked() throws {
        let probe = FakeProbe()
        let clock = Clock()
        let s = try service(probe: probe, clock: clock)
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: F.cliCaller, process: ProcessKey(pid: 20, version: 1))
        #expect(status(s)?.revisionState == .verificationFailed)
        probe.writable = ["/Users/me/work"]
        clock.now = clock.now.addingTimeInterval(HelperService.verificationRetryInterval)
        #expect(status(s)?.revisionState == .applied(running: true))
        #expect(status(s)?.verificationIssues.isEmpty == true)
        probe.missing = ["/Users/me/work"]
        clock.now = clock.now.addingTimeInterval(HelperService.verificationRetryInterval)
        #expect(status(s)?.revisionState == .awaitingVerification)
        #expect(status(s)?.verificationIssues.isEmpty == true)
        #expect(status(s)?.verificationPending == ["路径暂不存在，尚未核验：/Users/me/work"])
        probe.missing = []
        clock.now = clock.now.addingTimeInterval(HelperService.verificationRetryInterval)
        #expect(status(s)?.revisionState == .applied(running: true))
        #expect(status(s)?.verificationPending.isEmpty == true)
        probe.writable = []
        clock.now = clock.now.addingTimeInterval(HelperService.verificationRetryInterval)
        #expect(status(s)?.revisionState == .verificationFailed)
    }

    @Test func oldReportsWithoutPendingChecksStillDecode() throws {
        let report = ProfileStatusReport(profileID: "knodo", savedRevision: 1, mode: .enforce, revisionState: .awaitingVerification,
                                         runningInstances: [1], pendingCount: 0)
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        object.removeValue(forKey: "verificationPending")
        let decoded = try JSONDecoder().decode(ProfileStatusReport.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.verificationPending.isEmpty)
    }
}

@Suite struct InstanceRecordStoreTests {
    @Test func keepsOneRecordPerInstance() throws {
        let store = InstanceRecordStore(root: "/cfg", files: InMemoryFileStore())
        let a = InstanceRecord(instance: 1, profileID: "knodo", revision: 2, pid: 10, startTime: 100, supervisedByLaunchd: true)
        let b = InstanceRecord(instance: 2, profileID: "knodo", revision: 2, pid: 11, startTime: 101, supervisedByLaunchd: false)
        try store.save(a)
        try store.save(b)
        #expect(try store.all() == [a, b])
        try store.remove(profileID: "knodo", instance: 1)
        #expect(try store.all() == [b])
        try store.removeAll(profileID: "knodo")
        #expect(try store.all().isEmpty)
    }

    @Test func ignoresRecordsFiledUnderAnotherName() throws {
        let files = InMemoryFileStore()
        let store = InstanceRecordStore(root: "/cfg", files: files)
        let record = InstanceRecord(instance: 1, profileID: "other", revision: 1, pid: 10, startTime: 100, supervisedByLaunchd: false)
        try files.writeAtomically(try JSONEncoder().encode(record), to: "/cfg/instances/knodo/1.json")
        #expect(try store.all().isEmpty)
    }
}
