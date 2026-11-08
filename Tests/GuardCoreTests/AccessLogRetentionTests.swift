import Foundation
import Testing
@testable import GuardCore

@Suite struct AccessLogRetentionTests {
    @Test func sevenDayMaintenanceRemovesExpiredClosedSegmentsAndKeepsRecentOnes() async throws {
        let fixture = RetentionFixture()
        let start = fixture.clock.now()
        _ = fixture.store.append(fixture.event(profile: "knodo", target: "expired"))
        try await fixture.store.flush()

        fixture.clock.set(start.addingTimeInterval(6 * 24 * 60 * 60))
        _ = fixture.store.append(fixture.event(profile: "knodo", target: "recent"))
        try await fixture.store.flush()
        let before = fixture.fs.snapshot("knodo")
        let expired = try #require(before.keys.first { $0.hasSuffix(".jsonl") && !$0.hasSuffix(".open.jsonl") })
        #expect(before[expired] != nil)
        #expect(before[RetentionMemoryFS.metaName(expired)] != nil)
        let generation = (await fixture.store.status(profileID: "knodo")).generation

        await fixture.advance(to: start.addingTimeInterval(7 * 24 * 60 * 60 + 1))
        let after = fixture.fs.snapshot("knodo")
        #expect(after[expired] == nil)
        #expect(after[RetentionMemoryFS.metaName(expired)] == nil)
        #expect(try await fixture.store.query(.init(profileID: "knodo")).records.map(\.target) == ["recent"])
        let status = await fixture.store.status(profileID: "knodo")
        #expect(status.generation > generation)
        #expect(status.bytes == fixture.fs.bytes("knodo"))
        #expect(status.errors.isEmpty)
        await fixture.store.close()
    }

    @Test func globalCapacityAcrossProfilesReclaimsToEightyPercentAndCountsActiveFilesAndMetadata() async throws {
        var policy = AccessLogPolicy.default
        policy.minimumFreeBytes = 0
        policy.globalByteLimit = 12_000
        policy.profileByteLimit = 30_000
        policy.segmentByteLimit = 20_000
        let fixture = RetentionFixture(policy: policy)
        var observedCleanup = false
        var removedProfiles: Set<String> = []
        let profiles = ["alpha", "beta", "gamma"]

        for index in 0..<15 {
            let previous = fixture.fs.allSnapshots()
            fixture.clock.set(fixture.clock.now().addingTimeInterval(1))
            _ = fixture.store.append(fixture.event(profile: profiles[index % profiles.count],
                target: "\(index)-" + String(repeating: "x", count: 1100)))
            try await fixture.store.flush()
            let current = fixture.fs.allSnapshots()
            for (profile, files) in previous {
                let oldSegments = Set(files.keys.filter { $0.hasSuffix(".jsonl") })
                let newBases = Set((current[profile] ?? [:]).keys.filter { $0.hasSuffix(".jsonl") }.map(RetentionMemoryFS.baseName))
                if oldSegments.contains(where: { !newBases.contains(RetentionMemoryFS.baseName($0)) }) {
                    observedCleanup = true
                    removedProfiles.insert(profile)
                    // The target includes the pending record and reserved metadata overhead.
                    #expect(fixture.fs.totalBytes <= Int(Double(policy.globalByteLimit) * policy.cleanupLowWatermark))
                }
            }
            let status = await fixture.store.status()
            #expect(status.bytes == fixture.fs.totalBytes)
            #expect(status.bytes <= policy.globalByteLimit)
            #expect(status.errors.isEmpty)
        }
        #expect(observedCleanup)
        #expect(removedProfiles.count >= 2)
        #expect(fixture.fs.allSnapshots().values.contains { files in files.keys.contains { $0.hasSuffix(".open.jsonl") } })
        #expect(fixture.fs.allSnapshots().values.contains { files in files.keys.contains { $0.hasSuffix(".meta.json") } })
        await fixture.store.close()
    }

    @Test func lowDiskCleanupThatCannotRecoverEnoughSpaceStopsWritingAndReportsTheLoss() async throws {
        var policy = AccessLogPolicy.default
        policy.minimumFreeBytes = 1_000_000
        let fixture = RetentionFixture(policy: policy)
        _ = fixture.store.append(fixture.event(profile: "knodo", target: "old"))
        try await fixture.store.flush()
        #expect(fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".open.jsonl") })

        // Another disk user can consume every byte reclaimed by this store.
        fixture.fs.setAvailableBytes(0)
        _ = fixture.store.append(fixture.event(profile: "knodo", target: "cannot-save"))
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        let status = await fixture.store.status(profileID: "knodo")
        #expect(status.errors.contains { $0.contains("capacity unavailable") })
        #expect(status.droppedCount >= 1)
        #expect(status.queuedCount == 0)
        #expect(fixture.budget.snapshot.count == 0)
        #expect(!fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".jsonl") })
        #expect(status.bytes == fixture.fs.bytes("knodo"))
        #expect(try await fixture.store.query(.init(profileID: "knodo")).records.isEmpty)

        _ = fixture.store.append(fixture.event(profile: "knodo", target: "still-full"))
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        #expect(!fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".jsonl") })
        #expect(fixture.budget.snapshot.count == 0)
        await fixture.store.close()
    }

    @Test func clockRollbackDoesNotDisableCapacityLimits() async throws {
        var policy = AccessLogPolicy.default
        policy.minimumFreeBytes = 0
        policy.profileByteLimit = 6_000
        policy.globalByteLimit = 8_000
        policy.segmentByteLimit = 2_300
        let fixture = RetentionFixture(policy: policy)
        var sawRemoval = false
        for index in 0..<40 {
            let previous = Set(fixture.fs.snapshot("knodo").keys.filter { $0.hasSuffix(".jsonl") }.map(RetentionMemoryFS.baseName))
            fixture.clock.set(fixture.clock.now().addingTimeInterval(-60 * 60))
            _ = fixture.store.append(fixture.event(profile: "knodo",
                target: "\(index)-" + String(repeating: "r", count: 650)))
            try await fixture.store.flush()
            let current = Set(fixture.fs.snapshot("knodo").keys.filter { $0.hasSuffix(".jsonl") }.map(RetentionMemoryFS.baseName))
            if !previous.isSubset(of: current) { sawRemoval = true }
            let status = await fixture.store.status(profileID: "knodo")
            #expect(status.bytes == fixture.fs.bytes("knodo"))
            #expect(status.bytes <= policy.profileByteLimit)
            #expect(fixture.fs.totalBytes <= policy.globalByteLimit)
            #expect(status.errors.isEmpty)
        }
        #expect(sawRemoval)
        await fixture.store.close()
    }
}

private final class RetentionClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_800_000_000)
    func now() -> Date { lock.withLock { value } }
    func set(_ value: Date) { lock.withLock { self.value = value } }
}

private final class RetentionIDSource: @unchecked Sendable {
    private let lock = NSLock()
    private var sequence = 0
    func next() -> String { lock.withLock { sequence += 1; return "retention-\(sequence)" } }
}

private final class RetentionScheduler: AccessLogScheduling, @unchecked Sendable {
    private struct Delayed {
        var date: Date
        var work: @Sendable () -> Void
    }
    private let writer = DispatchQueue(label: "access-log-retention-writer")
    private let reader = DispatchQueue(label: "access-log-retention-reader")
    private let lock = NSLock()
    private var delayed: [Delayed] = []
    private let clock: RetentionClock
    init(clock: RetentionClock) { self.clock = clock }
    func write(after delay: TimeInterval, _ work: @escaping @Sendable () -> Void) {
        if delay <= 0 { writer.async(execute: work) }
        else { lock.withLock { delayed.append(.init(date: clock.now().addingTimeInterval(delay), work: work)) } }
    }
    func read(_ work: @escaping @Sendable () -> Void) { reader.async(execute: work) }
    func runDue() async {
        await withCheckedContinuation { continuation in
            writer.async { [self] in
                let now = clock.now()
                let due = lock.withLock {
                    let ready = delayed.filter { $0.date <= now }.sorted { $0.date < $1.date }
                    delayed.removeAll { $0.date <= now }
                    return ready
                }
                for item in due { item.work() }
                continuation.resume()
            }
        }
    }
}

private final class RetentionMemoryFS: AccessLogFileSystem, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: [String: Data]] = [:]
    private var freeBytes: UInt64 = UInt64.max
    func snapshot(_ profile: String) -> [String: Data] { lock.withLock { storage[profile] ?? [:] } }
    func allSnapshots() -> [String: [String: Data]] { lock.withLock { storage } }
    func bytes(_ profile: String) -> Int { snapshot(profile).values.reduce(0) { $0 + $1.count } }
    var totalBytes: Int { allSnapshots().values.reduce(0) { $0 + $1.values.reduce(0) { $0 + $1.count } } }
    func setAvailableBytes(_ value: UInt64) { lock.withLock { freeBytes = value } }
    func profiles() throws -> [String] { lock.withLock { storage.keys.sorted() } }
    func files(profileID: String) throws -> [AccessLogFileInfo] {
        snapshot(profileID).map { .init(name: $0.key, size: UInt64($0.value.count)) }.sorted { $0.name < $1.name }
    }
    func createProfile(_ profileID: String) throws { lock.withLock { if storage[profileID] == nil { storage[profileID] = [:] } } }
    func read(profileID: String, name: String, offset: UInt64, limit: Int) throws -> Data {
        try lock.withLock {
            guard let data = storage[profileID]?[name] else { throw AccessLogError.historyExpired }
            let start = min(data.count, Int(offset))
            return data.subdata(in: start..<min(data.count, start + limit))
        }
    }
    func append(profileID: String, name: String, data: Data) throws {
        lock.withLock { storage[profileID, default: [:]][name, default: Data()].append(data) }
    }
    func replace(profileID: String, name: String, data: Data) throws {
        lock.withLock { storage[profileID, default: [:]][name] = data }
    }
    func truncate(profileID: String, name: String, size: UInt64) throws {
        try lock.withLock {
            guard let data = storage[profileID]?[name], size <= UInt64(data.count) else { throw AccessLogError.historyExpired }
            storage[profileID]?[name] = Data(data.prefix(Int(size)))
        }
    }
    func rename(profileID: String, from: String, to: String) throws {
        try lock.withLock {
            guard storage[profileID]?[to] == nil, let data = storage[profileID]?[from] else { throw AccessLogError.historyExpired }
            storage[profileID]?[from] = nil
            storage[profileID]?[to] = data
        }
    }
    func remove(profileID: String, name: String) throws {
        try lock.withLock {
            guard storage[profileID]?[name] != nil else { throw AccessLogError.historyExpired }
            storage[profileID]?[name] = nil
        }
    }
    func synchronize(profileID: String, name: String) throws {
        guard snapshot(profileID)[name] != nil else { throw AccessLogError.historyExpired }
    }
    func availableBytes() throws -> UInt64? { lock.withLock { freeBytes } }
    static func baseName(_ name: String) -> String {
        for suffix in [".open.jsonl", ".jsonl"] where name.hasSuffix(suffix) { return String(name.dropLast(suffix.count)) }
        return name
    }
    static func metaName(_ name: String) -> String { baseName(name) + ".meta.json" }
}

private struct RetentionFixture {
    let fs = RetentionMemoryFS()
    let clock = RetentionClock()
    let budget = EventQueueBudget()
    let scheduler: RetentionScheduler
    let store: AccessLogStore
    init(policy: AccessLogPolicy = .default) {
        let scheduler = RetentionScheduler(clock: clock)
        self.scheduler = scheduler
        let ids = RetentionIDSource()
        self.store = AccessLogStore(fileSystem: fs, scheduler: scheduler, clock: clock.now,
            makeID: ids.next, writerID: "retention-writer", budget: budget, policy: policy)
    }
    func event(profile: String, target: String) -> AccessLogRecord {
        .init(profileID: profile, operation: "open", outcome: .allowedObserved, receivedAt: clock.now(),
              source: .eslogger, target: target)
    }
    func advance(to date: Date) async {
        clock.set(date)
        await scheduler.runDue()
    }
}
