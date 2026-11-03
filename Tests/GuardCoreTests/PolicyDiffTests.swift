import Testing
@testable import GuardCore

@Suite struct PolicyDiffTests {
    typealias F = Fixtures

    func diff(_ old: Profile, _ new: Profile) throws -> PolicyDiff {
        PolicyDiff(from: try F.compile(old), to: try F.compile(new))
    }

    @Test func identicalPoliciesProduceEmptyDiff() throws {
        let p = F.profile(files: [F.rw("/Users/me/easyops")])
        let d = try diff(p, p)
        #expect(d.changes.isEmpty)
        #expect(!d.requiresAuthorization)
    }

    @Test func addingPathExpands() throws {
        let d = try diff(F.profile(), F.profile(files: [F.ro("/Users/me/docs")]))
        #expect(d.changes == [.fileAdded(EffectiveFileGrant(path: "/Users/me/docs", kind: .directory, access: .readOnly, readsSecrets: false))])
        #expect(d.requiresAuthorization)
    }

    @Test func removingPathTightens() throws {
        let d = try diff(F.profile(files: [F.ro("/Users/me/docs")]), F.profile())
        #expect(d.changes.count == 1)
        #expect(!d.requiresAuthorization)
    }

    @Test func upgradingReadOnlyToReadWriteExpands() throws {
        let d = try diff(F.profile(files: [F.ro("/Users/me/docs")]), F.profile(files: [F.rw("/Users/me/docs")]))
        #expect(d.changes == [.fileAccessChanged(path: "/Users/me/docs", from: .readOnly, to: .readWrite)])
        #expect(d.requiresAuthorization)
    }

    @Test func downgradingReadWriteToReadOnlyTightens() throws {
        let d = try diff(F.profile(files: [F.rw("/Users/me/docs")]), F.profile(files: [F.ro("/Users/me/docs")]))
        #expect(!d.requiresAuthorization)
        #expect(d.changes.count == 1)
    }

    @Test func fileToDirectoryKindChangeExpands() throws {
        let d = try diff(F.profile(files: [F.roFile("/Users/me/notes")]), F.profile(files: [F.ro("/Users/me/notes")]))
        #expect(d.requiresAuthorization)
    }

    @Test func portChanges() throws {
        let added = try diff(F.profile(), F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910])))
        #expect(added.changes == [.loopbackPortAdded(9910)])
        #expect(added.requiresAuthorization)
        let removed = try diff(F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910])), F.profile())
        #expect(!removed.requiresAuthorization)
    }

    @Test func toggles() throws {
        let enable = try diff(F.profile(network: NetworkPolicy(outboundTCP: .denied)), F.profile(network: NetworkPolicy(outboundTCP: .allowed)))
        #expect(enable.requiresAuthorization)
        let disable = try diff(F.profile(network: NetworkPolicy(listen: .allowed)), F.profile(network: NetworkPolicy(listen: .denied)))
        #expect(!disable.requiresAuthorization)
    }

    @Test func modeChanges() throws {
        #expect(try diff(F.profile(mode: .enforce), F.profile(mode: .unprotectedObserve)).requiresAuthorization)
        #expect(!(try diff(F.profile(mode: .unprotectedObserve), F.profile(mode: .enforce)).requiresAuthorization))
        #expect(!(try diff(F.profile(mode: .enforce), F.profile(mode: .restrictedLearning)).requiresAuthorization))
        #expect(!(try diff(F.profile(mode: .restrictedLearning), F.profile(mode: .enforce)).requiresAuthorization))
    }

    @Test func execChanges() throws {
        let hash = String(repeating: "a", count: 64)
        #expect(try diff(F.profile(), F.profile(exec: [ExecGrant(path: "/usr/bin/git")])).requiresAuthorization)
        #expect(!(try diff(F.profile(exec: [ExecGrant(path: "/usr/bin/git")]), F.profile()).requiresAuthorization))
        #expect(try diff(F.profile(exec: [ExecGrant(path: "/usr/bin/git", sha256: hash)]), F.profile(exec: [ExecGrant(path: "/usr/bin/git")])).requiresAuthorization)
        #expect(!(try diff(F.profile(exec: [ExecGrant(path: "/usr/bin/git")]), F.profile(exec: [ExecGrant(path: "/usr/bin/git", sha256: hash)])).requiresAuthorization))
    }

    @Test func mixedDiffRequiresAuthorization() throws {
        let d = try diff(F.profile(files: [F.ro("/Users/me/a")]), F.profile(files: [F.ro("/Users/me/b")]))
        #expect(d.changes.count == 2)
        #expect(d.requiresAuthorization)
    }

    @Test func secretsFlagChangeExpandsOnlyWhenTurnedOn() throws {
        let plain = F.ro("/Users/me/.ssh")
        let secret = FileGrant(path: "/Users/me/.ssh", kind: .directory, access: .readOnly, readsSecrets: true)
        #expect(!(try diff(F.profile(files: [plain]), F.profile(files: [secret])).requiresAuthorization))
        #expect(try diff(F.profile(files: [plain]), F.profile(files: [secret])).changes.count == 1)
    }

    @Test func digestIsStableAndContentSensitive() throws {
        let a1 = try diff(F.profile(), F.profile(files: [F.ro("/Users/me/a"), F.ro("/Users/me/b")]))
        let a2 = try diff(F.profile(), F.profile(files: [F.ro("/Users/me/b"), F.ro("/Users/me/a")]))
        let b = try diff(F.profile(), F.profile(files: [F.ro("/Users/me/a")]))
        #expect(a1.digest == a2.digest)
        #expect(a1.digest != b.digest)
        #expect(a1.digest.count == 64)
    }

    @Test func summaryListsEveryChangeInOrder() throws {
        let d = try diff(F.profile(), F.profile(files: [F.rw("/Users/me/easyops")], network: NetworkPolicy(loopbackTCPConnect: [9910])))
        #expect(d.summaryLines == ["+ 读写目录 /Users/me/easyops", "+ 本机 TCP 端口 9910"])
    }
}
