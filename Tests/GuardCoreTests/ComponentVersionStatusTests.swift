import Foundation
import Testing
@testable import GuardCore

@Suite struct ComponentVersionStatusTests {
    private let bundled = String(repeating: "a1", count: 20)
    private let previous = String(repeating: "b2", count: 20)

    @Test func sameProtocolDoesNotMakeAnOlderRunningHelperCurrent() {
        #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                               runtimeCodeHash: previous, bundledCodeHash: bundled) == .updateRequired)
    }

    @Test func oldResponseWithoutRuntimeIdentityRequiresAnUpdate() {
        #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                               runtimeCodeHash: nil, bundledCodeHash: bundled) == .updateRequired)
    }

    @Test func aMissingBundledIdentityCannotConfirmOrRepairTheHelper() {
        #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                               runtimeCodeHash: bundled, bundledCodeHash: nil) == .identityUnavailable)
    }

    @Test func matchingVerifiedIdentityAcceptsHexLetterCase() {
        #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                               runtimeCodeHash: bundled.uppercased(), bundledCodeHash: bundled) == .current)
    }

    @Test func anOlderProtocolStillRequiresAnUpdateWhenIdentityMatches() {
        #expect(ComponentVersionStatus.helper(protocolVersion: 8, requiredProtocol: 9,
                                               runtimeCodeHash: bundled, bundledCodeHash: bundled) == .updateRequired)
    }

    @Test func malformedOrEmptyIdentitiesAreNeverCurrent() {
        for value in ["", " ", "unreadable", String(repeating: "z", count: 40)] {
            #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                                   runtimeCodeHash: value, bundledCodeHash: bundled) == .updateRequired)
            #expect(ComponentVersionStatus.helper(protocolVersion: 9, requiredProtocol: 9,
                                                   runtimeCodeHash: bundled, bundledCodeHash: value) == .identityUnavailable)
        }
    }

    @Test func collectorInstallationOutcomeDoesNotHideRetainedOldCode() throws {
        let report = StatusReport(profiles: [], collectorProblems: [], helperRuntimeCodeHash: bundled,
                                  collectorInstallation: .keptOutdated)
        let decoded = try JSONDecoder().decode(StatusReport.self, from: JSONEncoder().encode(report))
        #expect(decoded.helperRuntimeCodeHash == bundled)
        #expect(decoded.collectorInstallation == .keptOutdated)
        #expect(decoded.collectorInstallation?.requiresMaintenance == true)
        #expect(CollectorInstallationStatus.keptExisting.requiresMaintenance == false)
    }

    @Test func oldStatusResponseKeepsMissingComponentIdentityUnknown() throws {
        let data = Data(#"{"profiles":[],"collectorProblems":[],"helperProtocol":9}"#.utf8)
        let decoded = try JSONDecoder().decode(StatusReport.self, from: data)
        #expect(decoded.helperRuntimeCodeHash == nil)
        #expect(decoded.collectorInstallation == nil)
    }

    @Test func oldRuntimeReportDoesNotInventAFullProcessBirth() throws {
        let data = Data(#"{"id":1,"revision":2,"entryPID":20,"knownPIDs":[20],"checkedPID":20,"verified":true}"#.utf8)
        let decoded = try JSONDecoder().decode(RuntimeInstanceReport.self, from: data)
        #expect(decoded.checkedProcessStartTime == nil)
    }

    @Test func installationSuccessDoesNotMarkAnUnstartedSourceHealthy() {
        let s = HelperService(
            store: ProfileStore(root: "/store", files: InMemoryFileStore()), environment: Fixtures.environment,
            catalog: TemplateCatalog([]), trust: Fixtures.trust, verifier: FakeVerifier(accept: true),
            settings: Fixtures.helperSettings, clock: Date.init, makeID: { "unused" },
            helperRuntimeCodeHash: previous
        )
        s.updateCollectorInstallation(.installedBundled)
        guard case let .status(report) = s.handle(.status, caller: Fixtures.appCaller, process: ProcessKey(pid: 10, version: 1)) else {
            Issue.record("expected status"); return
        }
        #expect(report.helperRuntimeCodeHash == previous)
        #expect(report.collectorInstallation == .installedBundled)
        #expect(!report.collectorProblems.isEmpty)
    }

    @Test func checkedBirthIsForTheRepresentativeChildAndSurvivesTheWire() throws {
        let root = ProcessKey(pid: 20, version: 1), child = ProcessKey(pid: 21, version: 5)
        let s = try service(checkedBirth: { $0 == child ? 9_123_456_789 : 123 })
        _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: Fixtures.cliCaller, process: root)
        s.ingest(.fork(parent: root, child: child))
        s.ingest(.exit(root))
        guard case let .status(report) = s.handle(.status, caller: Fixtures.appCaller, process: ProcessKey(pid: 10, version: 1)) else {
            Issue.record("expected status"); return
        }
        let decoded = try JSONDecoder().decode(StatusReport.self, from: JSONEncoder().encode(report))
        let runtime = decoded.profiles.first?.runtimeInstances.first
        #expect(runtime?.checkedPID == child.pid)
        #expect(runtime?.checkedProcessStartTime == 9_123_456_789)
    }

    @Test func changingOrMissingProcessBirthNeverConfirmsIdentity() throws {
        for sequence: [UInt64?] in [[nil, nil], [123, nil], [123, 456]] {
            var remaining = sequence
            let s = try service(checkedBirth: { _ in remaining.isEmpty ? nil : remaining.removeFirst() })
            _ = s.handle(.registerInstance(profileID: "knodo", revision: 1), caller: Fixtures.cliCaller,
                         process: ProcessKey(pid: 20, version: 1))
            guard case let .status(report) = s.handle(.status, caller: Fixtures.appCaller, process: ProcessKey(pid: 10, version: 1)) else {
                Issue.record("expected status"); return
            }
            #expect(report.profiles.first?.runtimeInstances.first?.checkedProcessStartTime == nil)
        }
    }

    private func service(checkedBirth: @escaping (ProcessKey) -> UInt64?) throws -> HelperService {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let probe = FakeProbe()
        probe.writable = ["/Users/me/work"]
        var counter = 0
        let service = HelperService(
            store: store, environment: Fixtures.environment, catalog: TemplateCatalog([]), trust: Fixtures.trust,
            verifier: FakeVerifier(accept: true), settings: Fixtures.helperSettings,
            clock: { Date(timeIntervalSince1970: 1_800_000_000) },
            makeID: { counter += 1; return "c\(counter)" }, probe: probe,
            checkedProcessBirth: checkedBirth
        )
        let app = ProcessKey(pid: 10, version: 1)
        guard case let .pending(info) = service.handle(
            .proposeChange(profile: Fixtures.profile(files: [Fixtures.rw("/Users/me/work")], revision: 1)),
            caller: Fixtures.appCaller, process: app
        ) else { throw TestError.profileCreation }
        _ = service.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)),
                           caller: Fixtures.appCaller, process: app)
        return service
    }

    private enum TestError: Error { case profileCreation }
}
