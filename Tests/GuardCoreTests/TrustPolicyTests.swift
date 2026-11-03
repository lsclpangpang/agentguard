import Testing
@testable import GuardCore

@Suite struct TrustPolicyTests {
    typealias F = Fixtures

    @Test func resolvesRolesByPinnedCodeHash() {
        #expect(F.trust.role(of: F.appCaller) == .app)
        #expect(F.trust.role(of: F.cliCaller) == .cli)
        #expect(F.trust.role(of: F.launcherCaller) == .launcher)
    }

    @Test func signingIdentifierAloneIsNotEnough() {
        var forged = F.appCaller
        forged.cdhash = String(repeating: "f", count: 40)
        #expect(F.trust.role(of: forged) == nil)
    }

    @Test func cdhashComparisonIgnoresCase() {
        var upper = F.appCaller
        upper.cdhash = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        let policy = CallerTrustPolicy(allowedUID: 501, identities: [
            .app: CodeIdentity(signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhashes: ["abcdef0123456789abcdef0123456789abcdef01"]),
        ])
        #expect(policy.role(of: upper) == .app)
    }

    @Test func wrongUIDIsRejected() {
        var other = F.appCaller
        other.uid = 0
        #expect(F.trust.role(of: other) == nil)
    }

    @Test func identityWithoutTeamOrHashNeverMatches() {
        let policy = CallerTrustPolicy(allowedUID: 501, identities: [
            .app: CodeIdentity(signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhashes: []),
        ])
        #expect(policy.role(of: F.appCaller) == nil)
    }

    @Test func teamIdentifierIdentityMatchesWithoutHash() {
        let policy = CallerTrustPolicy(allowedUID: 501, identities: [
            .app: CodeIdentity(signingIdentifier: "com.example.agentguard.app", teamIdentifier: "TEAM123456", cdhashes: []),
        ])
        var caller = F.appCaller
        caller.teamIdentifier = "TEAM123456"
        caller.cdhash = nil
        #expect(policy.role(of: caller) == .app)
        caller.teamIdentifier = "OTHER"
        #expect(policy.role(of: caller) == nil)
    }
}
