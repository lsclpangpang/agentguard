import Foundation
import Testing
@testable import GuardCore

@Suite struct ProfileStoreTests {
    typealias F = Fixtures

    func approval(_ base: Int, _ new: Int, id: String = "knodo") -> ApprovedChange {
        ApprovedChange(profileID: id, baseRevision: base, newRevision: new, diffDigest: String(repeating: "d", count: 64))
    }

    @Test func emptyStoreHasNoProfiles() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        #expect(try store.latest("knodo") == nil)
        #expect(try store.profileIDs() == [])
    }

    @Test func savesFirstRevisionAndReadsItBack() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        let p = F.profile(files: [F.rw("/Users/me/easyops")], revision: 1)
        try store.save(p, approval: approval(0, 1))
        #expect(try store.latest("knodo") == p)
        #expect(try store.revisions("knodo") == [1])
        #expect(try store.profileIDs() == ["knodo"])
        #expect(try store.approval("knodo", revision: 1) == approval(0, 1))
    }

    @Test func revisionsAreOrderedNumerically() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        for rev in 1...11 { try store.save(F.profile(revision: rev), approval: approval(rev - 1, rev)) }
        #expect(try store.revisions("knodo") == Array(1...11))
        #expect(try store.latest("knodo")?.revision == 11)
        #expect(try store.revision("knodo", 3)?.revision == 3)
    }

    @Test func rejectsSaveWhenBaseIsNotLatest() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        try store.save(F.profile(revision: 1), approval: approval(0, 1))
        #expect(throws: StoreError.revisionConflict(expectedBase: 0, latest: 1)) {
            try store.save(F.profile(files: [F.ro("/Users/me/stale")], revision: 1), approval: approval(0, 1))
        }
    }

    @Test func rejectsProfileThatDoesNotMatchApproval() throws {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        #expect(throws: StoreError.approvalMismatch) { try store.save(F.profile(revision: 2), approval: approval(0, 1)) }
        #expect(throws: StoreError.approvalMismatch) { try store.save(F.profile(revision: 1), approval: approval(0, 1, id: "other")) }
    }

    @Test func rejectsUnsafeProfileIDs() {
        let store = ProfileStore(root: "/store", files: InMemoryFileStore())
        #expect(throws: StoreError.invalidProfileID("../etc")) { try store.latest("../etc") }
    }

    @Test func localFileStoreWritesAtomicallyAndLists() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("agentguard-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let files = LocalFileStore()
        try files.writeAtomically(Data("one".utf8), to: dir + "/a/b.json")
        try files.writeAtomically(Data("two".utf8), to: dir + "/a/b.json")
        #expect(try files.read(dir + "/a/b.json") == Data("two".utf8))
        #expect(try files.read(dir + "/missing") == nil)
        #expect(try files.list(dir + "/a") == ["b.json"])
        #expect(try files.list(dir + "/none") == [])
    }

    @Test func storeWorksOnRealFileSystem() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("agentguard-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let store = ProfileStore(root: dir, files: LocalFileStore())
        try store.save(F.profile(revision: 1), approval: approval(0, 1))
        try store.save(F.profile(files: [F.ro("/Users/me/docs")], revision: 2), approval: approval(1, 2))
        #expect(try store.latest("knodo")?.files == [F.ro("/Users/me/docs")])
    }
}
