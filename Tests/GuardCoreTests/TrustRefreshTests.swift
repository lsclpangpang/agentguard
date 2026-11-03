import Foundation
import Testing
@testable import GuardCore

/// The Helper runs for days while the app is rebuilt (and re-signed) many times; every rebuilt app
/// must keep being able to change permissions without a Helper restart.
@Suite struct TrustRefreshTests {
    typealias F = Fixtures

    let appProcess = ProcessKey(pid: 10, version: 1)
    let rebuiltHash = String(repeating: "9", count: 40)

    var rebuiltApp: CallerIdentity {
        var caller = F.appCaller
        caller.cdhash = rebuiltHash
        return caller
    }

    func service() -> HelperService {
        var counter = 0
        return HelperService(store: ProfileStore(root: "/store", files: InMemoryFileStore()), environment: F.environment,
                             catalog: TemplateCatalog([]), trust: F.trust, verifier: FakeVerifier(accept: true), settings: F.helperSettings,
                             clock: { Date(timeIntervalSince1970: 1_800_000_000) }, makeID: { counter += 1; return "c\(counter)" })
    }

    func identitiesAfterRebuild() -> [CallerRole: CodeIdentity] {
        var identities = F.trust.identities
        identities[.app] = CodeIdentity(signingIdentifier: F.appCaller.signingIdentifier!, teamIdentifier: nil, cdhashes: [rebuiltHash])
        return identities
    }

    @Test func aRebuiltAppCanProposeAndApproveAfterTheIdentitiesAreRefreshed() {
        let s = service()
        s.updateIdentities(identitiesAfterRebuild())
        guard case let .pending(info) = s.handle(.proposeChange(profile: F.profile()), caller: rebuiltApp, process: appProcess) else {
            Issue.record("a rebuilt app could not propose"); return
        }
        #expect(s.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)), caller: rebuiltApp, process: appProcess)
            == .applied(revision: 1))
    }

    @Test func theOldAppIsNoLongerTrustedForChanges() {
        let s = service()
        s.updateIdentities(identitiesAfterRebuild())
        #expect(s.handle(.proposeChange(profile: F.profile()), caller: F.appCaller, process: appProcess) == .failure(code: "not_trusted"))
    }

    @Test func aBinaryThatCannotBeReadKeepsItsPreviousIdentity() {
        var fresh = identitiesAfterRebuild()
        fresh[.cli] = nil
        let merged = CallerTrustPolicy.refreshed(F.trust.identities, with: fresh)
        #expect(merged[.cli] == F.trust.identities[.cli])
        #expect(merged[.app] == fresh[.app])
    }
}
