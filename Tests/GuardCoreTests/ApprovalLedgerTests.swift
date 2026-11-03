import Foundation
import Testing
@testable import GuardCore

@Suite struct ApprovalLedgerTests {
    typealias F = Fixtures

    let trust = Fixtures.trust
    let app = Fixtures.appCaller
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func makeLedger() -> ApprovalLedger {
        var counter = 0
        return ApprovalLedger(trust: trust, lifetime: 300) {
            counter += 1
            return "change-\(counter)"
        }
    }

    func expandingDiff() throws -> PolicyDiff {
        PolicyDiff(from: try F.compile(F.profile()), to: try F.compile(F.profile(files: [F.ro("/Users/me/docs")])))
    }

    func tighteningDiff() throws -> PolicyDiff {
        PolicyDiff(from: try F.compile(F.profile(files: [F.ro("/Users/me/docs")])), to: try F.compile(F.profile()))
    }

    @Test func approvesMatchingChangeAndAdvancesRevision() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(pending.expiresAt == t0.addingTimeInterval(300))
        let approved = try ledger.approve(
            changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app,
            authorization: .verified(changeID: pending.id), now: t0.addingTimeInterval(10)
        )
        #expect(approved.newRevision == 4)
        #expect(approved.profileID == "knodo")
        #expect(approved.diffDigest == diff.digest)
    }

    @Test func rejectsMissingAuthorization() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.authorizationMissing) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .none, now: t0)
        }
    }

    @Test func rejectsAuthorizationBoundToAnotherChange() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.authorizationMissing) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .verified(changeID: "change-99"), now: t0)
        }
    }

    @Test func rejectsExpiredChange() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.expired) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .verified(changeID: pending.id), now: t0.addingTimeInterval(301))
        }
    }

    @Test func rejectsReplay() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        _ = try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .verified(changeID: pending.id), now: t0)
        #expect(throws: ApprovalError.alreadyUsed) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .verified(changeID: pending.id), now: t0)
        }
    }

    @Test func failedAttemptConsumesTheChange() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.digestMismatch) {
            try ledger.approve(changeID: pending.id, presentedDigest: String(repeating: "0", count: 64), currentRevision: 3, caller: app, authorization: .verified(changeID: pending.id), now: t0)
        }
        #expect(throws: ApprovalError.alreadyUsed) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: app, authorization: .verified(changeID: pending.id), now: t0)
        }
    }

    @Test func rejectsWhenBaseRevisionChanged() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.baseRevisionChanged(expected: 3, actual: 4)) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 4, caller: app, authorization: .verified(changeID: pending.id), now: t0)
        }
    }

    @Test func rejectsUnknownChange() {
        var ledger = makeLedger()
        #expect(throws: ApprovalError.unknownChange) {
            try ledger.approve(changeID: "nope", presentedDigest: "", currentRevision: 1, caller: app, authorization: .verified(changeID: "nope"), now: t0)
        }
    }

    @Test(arguments: [
        Fixtures.cliCaller,
        CallerIdentity(uid: 501, signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhash: String(repeating: "9", count: 40), managedInstance: nil),
        CallerIdentity(uid: 502, signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhash: Fixtures.appHash, managedInstance: nil),
        CallerIdentity(uid: 501, signingIdentifier: nil, teamIdentifier: nil, cdhash: nil, managedInstance: nil),
    ])
    func rejectsUntrustedCallers(caller: CallerIdentity) throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        #expect(throws: ApprovalError.callerNotTrusted) {
            try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: caller, now: t0)
        }
    }

    @Test func rejectsCallsFromManagedInstanceEvenWithValidSignature() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let managed = Fixtures.appCaller.managed(by: 24)
        #expect(throws: ApprovalError.callerIsManaged(instance: 24)) {
            try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: managed, now: t0)
        }
        let pending = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(throws: ApprovalError.callerIsManaged(instance: 24)) {
            try ledger.approve(changeID: pending.id, presentedDigest: diff.digest, currentRevision: 3, caller: managed, authorization: .verified(changeID: pending.id), now: t0)
        }
    }

    @Test func tighteningAppliesWithoutAuthorization() throws {
        let ledger = makeLedger()
        let approved = try ledger.applyTightening(profileID: "knodo", baseRevision: 3, currentRevision: 3, diff: try tighteningDiff(), caller: app)
        #expect(approved.newRevision == 4)
    }

    @Test func tighteningPathRefusesExpandingDiff() throws {
        let ledger = makeLedger()
        #expect(throws: ApprovalError.authorizationRequired) {
            try ledger.applyTightening(profileID: "knodo", baseRevision: 3, currentRevision: 3, diff: try expandingDiff(), caller: app)
        }
    }

    @Test func tighteningStillRequiresTrustedUnmanagedCaller() throws {
        let ledger = makeLedger()
        let managed = Fixtures.appCaller.managed(by: 3)
        #expect(throws: ApprovalError.callerIsManaged(instance: 3)) {
            try ledger.applyTightening(profileID: "knodo", baseRevision: 3, currentRevision: 3, diff: try tighteningDiff(), caller: managed)
        }
    }

    @Test func tighteningChecksBaseRevision() throws {
        let ledger = makeLedger()
        #expect(throws: ApprovalError.baseRevisionChanged(expected: 3, actual: 5)) {
            try ledger.applyTightening(profileID: "knodo", baseRevision: 3, currentRevision: 5, diff: try tighteningDiff(), caller: app)
        }
    }

    @Test func proposalsGetDistinctIDsAndCarrySummary() throws {
        var ledger = makeLedger()
        let diff = try expandingDiff()
        let a = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        let b = try ledger.propose(profileID: "knodo", baseRevision: 3, diff: diff, caller: app, now: t0)
        #expect(a.id != b.id)
        #expect(a.summaryLines == diff.summaryLines)
    }
}
