import Foundation
import Testing
import GuardCore
@testable import GuardPlatform
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@Suite struct ProtectedAccessLogFileSystemTests {
    @Test func createsPrivateDirectoriesAndSupportsDurableSegmentOperations() throws {
        let fixture = try ProtectedLogFixture()
        defer { fixture.cleanup() }
        let fs = try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid())
        try fs.createProfile("knodo")
        try fs.append(profileID: "knodo", name: "segment-test.open.jsonl", data: Data("one\n".utf8))
        try fs.append(profileID: "knodo", name: "segment-test.open.jsonl", data: Data("two\n".utf8))
        #expect(try fs.read(profileID: "knodo", name: "segment-test.open.jsonl", offset: 4, limit: 4) == Data("two\n".utf8))
        try fs.truncate(profileID: "knodo", name: "segment-test.open.jsonl", size: 4)
        try fs.synchronize(profileID: "knodo", name: "segment-test.open.jsonl")
        try fs.rename(profileID: "knodo", from: "segment-test.open.jsonl", to: "segment-test.jsonl")
        #expect(try fs.files(profileID: "knodo").map(\.name) == ["segment-test.jsonl"])
        try fs.replace(profileID: "knodo", name: "state.json", data: Data("state".utf8))
        #expect(try fs.profiles() == ["knodo"])
        #expect(try fixture.mode(fixture.root) == 0o700)
        #expect(try fixture.mode(fixture.root + "/knodo") == 0o700)
        #expect(try fixture.mode(fixture.root + "/knodo/state.json") == 0o600)
        #expect(try fs.availableBytes() != nil)
        try fs.remove(profileID: "knodo", name: "segment-test.jsonl")
        #expect(try fs.files(profileID: "knodo").map(\.name) == ["state.json"])
    }

    @Test func rejectsTraversalAndSymlinksWithoutChangingTheOutsideTarget() throws {
        let fixture = try ProtectedLogFixture()
        defer { fixture.cleanup() }
        let outside = fixture.parent + "/outside"
        try Data("keep".utf8).write(to: URL(fileURLWithPath: outside))
        let fs = try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid())
        try fs.createProfile("knodo")
        #expect(throws: (any Error).self) { try fs.createProfile("../escape") }
        #expect(throws: (any Error).self) { try fs.append(profileID: "knodo", name: "../outside", data: Data()) }
        let link = fixture.root + "/knodo/segment-link.jsonl"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: outside)
        #expect(throws: (any Error).self) { try fs.read(profileID: "knodo", name: "segment-link.jsonl", offset: 0, limit: 100) }
        #expect(throws: (any Error).self) { try fs.append(profileID: "knodo", name: "segment-link.jsonl", data: Data("bad".utf8)) }
        #expect(throws: (any Error).self) { try fs.replace(profileID: "knodo", name: "segment-link.jsonl", data: Data("bad".utf8)) }
        #expect(throws: (any Error).self) { try fs.remove(profileID: "knodo", name: "segment-link.jsonl") }
        #expect(throws: (any Error).self) { try fs.files(profileID: "knodo") }
        #expect(try Data(contentsOf: URL(fileURLWithPath: outside)) == Data("keep".utf8))
        try FileManager.default.createSymbolicLink(atPath: fixture.root + "/alias", withDestinationPath: fixture.root + "/knodo")
        #expect(throws: (any Error).self) { try fs.createProfile("alias") }
        #expect(throws: (any Error).self) { try fs.files(profileID: "alias") }
    }

    @Test func rejectsHardLinksWrongModesAndRootAliases() throws {
        let fixture = try ProtectedLogFixture()
        defer { fixture.cleanup() }
        let fs = try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid())
        try fs.createProfile("knodo")
        try fs.append(profileID: "knodo", name: "original.jsonl", data: Data("keep".utf8))
        try FileManager.default.linkItem(atPath: fixture.root + "/knodo/original.jsonl", toPath: fixture.parent + "/hard-link")
        #expect(throws: (any Error).self) { try fs.append(profileID: "knodo", name: "original.jsonl", data: Data("bad".utf8)) }
        try FileManager.default.removeItem(atPath: fixture.parent + "/hard-link")
        #expect(chmod(fixture.root + "/knodo/original.jsonl", 0o644) == 0)
        #expect(throws: (any Error).self) { try fs.read(profileID: "knodo", name: "original.jsonl", offset: 0, limit: 100) }
        #expect(chmod(fixture.root + "/knodo", 0o755) == 0)
        #expect(throws: (any Error).self) { try fs.files(profileID: "knodo") }
        let alias = fixture.parent + "/root-alias"
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: fixture.root)
        #expect(throws: (any Error).self) { try ProtectedAccessLogFileSystem(root: alias, ownerUID: getuid()) }
        #expect(throws: (any Error).self) { try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid() &+ 1) }
    }

    @Test func enumerationIsBoundedAndRenameNeverOverwritesAnotherSegment() throws {
        let fixture = try ProtectedLogFixture()
        defer { fixture.cleanup() }
        let fs = try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid(), maxDirectoryEntries: 2)
        try fs.createProfile("knodo")
        for name in ["a.jsonl", "b.jsonl"] { try fs.append(profileID: "knodo", name: name, data: Data(name.utf8)) }
        #expect(throws: (any Error).self) { try fs.rename(profileID: "knodo", from: "a.jsonl", to: "b.jsonl") }
        #expect(try fs.read(profileID: "knodo", name: "b.jsonl", offset: 0, limit: 100) == Data("b.jsonl".utf8))
        try fs.append(profileID: "knodo", name: "c.jsonl", data: Data())
        #expect(throws: (any Error).self) { try fs.files(profileID: "knodo") }
    }

    @Test func realDiskStoreClosesAndReopensWithEveryRepeatedAccessIntact() async throws {
        let fixture = try ProtectedLogFixture()
        defer { fixture.cleanup() }
        let fs = try ProtectedAccessLogFileSystem(root: fixture.root, ownerUID: getuid())
        var policy = AccessLogPolicy.default
        policy.minimumFreeBytes = 0
        let budget = EventQueueBudget()
        let store = AccessLogStore(fileSystem: fs, scheduler: DispatchAccessLogScheduler(),
            clock: { Date(timeIntervalSince1970: 1_800_000_000.123456) },
            makeID: { UUID().uuidString }, writerID: "disk-test", budget: budget, policy: policy)
        let clock = ContinuousClock()
        let start = clock.now
        for number in 0..<1000 {
            let receipt = store.append(.init(profileID: "isolated-test", operation: "open", outcome: .allowedObserved,
                receivedAt: Date(timeIntervalSince1970: 1_800_000_000.123456), source: .eslogger,
                target: "/isolated/repeated", evidence: "test-\(number)"))
            #expect(receipt.accepted)
            #expect(budget.snapshot.bytes <= budget.maxBytes)
        }
        let offerDuration = start.duration(to: clock.now)
        await store.close()
        let completeDuration = start.duration(to: clock.now)
        #expect(budget.snapshot.count == 0)
        let restarted = AccessLogStore(fileSystem: fs, scheduler: DispatchAccessLogScheduler(),
            clock: { Date(timeIntervalSince1970: 1_800_000_001) },
            makeID: { UUID().uuidString }, writerID: "disk-restart", budget: .init(), policy: policy)
        var query = AccessLogQuery(profileID: "isolated-test", limit: 500)
        var records: [AccessLogRecord] = []
        repeat {
            let page = try await restarted.query(query)
            records.append(contentsOf: page.records)
            query.cursor = page.nextCursor
        } while query.cursor != nil
        #expect(records.count == 1000)
        #expect(Set(records.map(\.eventID)).count == 1000)
        #expect(records.allSatisfy { $0.target == "/isolated/repeated" })
        #expect((await restarted.status(profileID: "isolated-test")).errors.isEmpty)
        await restarted.close()
        print("AccessLog isolated disk 1000 records: offer=\(offerDuration), close+sync=\(completeDuration)")
    }
}

private struct ProtectedLogFixture {
    let parent: String
    let root: String
    init() throws {
        guard let temporary = realpath(FileManager.default.temporaryDirectory.path, nil) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { free(temporary) }
        parent = String(cString: temporary) + "/agentguard-access-log-test-" + UUID().uuidString
        root = parent + "/logs"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
    }
    func mode(_ path: String) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        return (attributes[.posixPermissions] as! NSNumber).intValue
    }
    func cleanup() { try? FileManager.default.removeItem(atPath: parent) }
}
