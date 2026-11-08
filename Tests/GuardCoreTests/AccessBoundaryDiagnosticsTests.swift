import Foundation
import Testing
@testable import GuardCore

private final class BoundaryProbe: SandboxProbe, @unchecked Sendable {
    var sandboxed: Bool? = true
    var results: [SandboxOperation: SandboxCheckResult] = [
        .fileRead: .denied, .fileMetadata: .allowed, .fileWrite: .denied,
    ]
    var checks: [SandboxOperation] = []

    func isSandboxed(pid: Int32) -> Bool? { sandboxed }
    func check(pid: Int32, operation: SandboxOperation, target: String) -> SandboxCheckResult {
        checks.append(operation)
        return results[operation] ?? .unavailable
    }
}

@Suite struct AccessBoundaryDiagnosticsTests {
    private let target = "/Library/Application Support/AgentGuard/owner.json"

    private func diagnose(probe: BoundaryProbe, expected: UInt64? = 900,
                          birth: (Int32) -> UInt64? = { _ in 900 }) -> AccessBoundaryDiagnostic {
        AccessBoundaryDiagnostics.check(instanceID: 1, revision: 47, pid: 7,
                                        expectedStartTime: expected, path: target,
                                        processStartTime: birth, probe: probe)
    }

    @Test func metadataAccessDoesNotEstablishContentReadAccess() throws {
        let report = diagnose(probe: BoundaryProbe())
        #expect(report.identity == .verified)
        #expect(report.contentRead == .denied)
        #expect(report.metadataRead == .allowed)
        #expect(report.contentWrite == .denied)
        #expect(report.processStartTime == 900)
        let data = try JSONEncoder().encode(report)
        #expect(try JSONDecoder().decode(AccessBoundaryDiagnostic.self, from: data) == report)
    }

    @Test func missingExpectedBirthNeverQueriesAReusedOrUnknownProcess() {
        let probe = BoundaryProbe()
        var birthQueries = 0
        let report = diagnose(probe: probe, expected: nil, birth: { _ in birthQueries += 1; return 900 })
        #expect(report.identity == .missingExpectedIdentity)
        #expect(probe.checks.isEmpty)
        #expect(birthQueries == 0)
        #expect(report.contentRead == nil && report.metadataRead == nil && report.contentWrite == nil)
    }

    @Test func processReuseBeforeProbeNeverYieldsProfileVerdicts() {
        let probe = BoundaryProbe()
        let report = diagnose(probe: probe, birth: { _ in 901 })
        #expect(report.identity == .processChanged)
        #expect(probe.checks.isEmpty)
        #expect(report.contentRead == nil)
    }

    @Test func processReuseDuringProbeDiscardsAllAnswers() {
        let probe = BoundaryProbe()
        var queries = 0
        let report = diagnose(probe: probe, birth: { _ in
            queries += 1
            return queries == 1 ? 900 : 901
        })
        #expect(probe.checks.count == 3)
        #expect(report.identity == .processChanged)
        #expect(report.contentRead == nil && report.metadataRead == nil && report.contentWrite == nil)
    }

    @Test func exitDuringProbeDiscardsAllAnswers() {
        var queries = 0
        let report = diagnose(probe: BoundaryProbe(), birth: { _ in
            queries += 1
            return queries == 1 ? 900 : nil
        })
        #expect(report.identity == .processUnavailable)
        #expect(report.contentRead == nil)
    }

    @Test func absentPathsAndUnavailableQueriesAreNotConfirmedDenials() {
        let probe = BoundaryProbe()
        probe.results[.fileRead] = .missing
        probe.results[.fileWrite] = .unavailable
        let report = diagnose(probe: probe)
        #expect(report.identity == .verified)
        #expect(report.contentRead == .missing)
        #expect(report.contentWrite == .unavailable)
    }

    @Test func notSandboxedAndUnknownSandboxDoNotProduceBoundaryAnswers() {
        let probe = BoundaryProbe()
        probe.sandboxed = false
        #expect(diagnose(probe: probe).identity == .notSandboxed)
        #expect(probe.checks.isEmpty)
        probe.sandboxed = nil
        #expect(diagnose(probe: probe).identity == .sandboxUnavailable)
        #expect(probe.checks.isEmpty)
    }

    @Test func unavailableInitialProcessDoesNotQuerySandbox() {
        let probe = BoundaryProbe()
        #expect(diagnose(probe: probe, birth: { _ in nil }).identity == .processUnavailable)
        #expect(probe.checks.isEmpty)
    }

    @Test func missingRepresentativePIDKeepsIdentityUnknown() {
        let probe = BoundaryProbe()
        let report = AccessBoundaryDiagnostics.check(instanceID: 1, revision: 47, pid: nil,
                                                     expectedStartTime: 900, path: target,
                                                     processStartTime: { _ in 900 }, probe: probe)
        #expect(report.identity == .missingExpectedIdentity)
        #expect(report.pid == nil && report.contentRead == nil)
        #expect(probe.checks.isEmpty)
    }
}
