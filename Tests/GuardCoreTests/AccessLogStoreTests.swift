import Foundation
import Testing
@testable import GuardCore

@Suite struct AccessLogStoreTests {
    @Test func defaultsAreTheReviewedCapacityAndRetentionLimits() {
        let policy = AccessLogPolicy.default
        #expect(policy.retentionInterval == 7 * 24 * 60 * 60)
        #expect(policy.profileByteLimit == 256 * 1024 * 1024)
        #expect(policy.globalByteLimit == 512 * 1024 * 1024)
        #expect(policy.segmentByteLimit == 16 * 1024 * 1024)
        #expect(policy.segmentInterval == 60 * 60)
        #expect(policy.flushInterval == 1)
        #expect(policy.batchCount == 256)
    }

    @Test func repeatedEventsRoundTripWithExplicitSourceEvidenceAndSnakeCase() async throws {
        let fixture = LogFixture()
        var event = fixture.event(target: "a\nb")
        event.profileRevision = 47
        event.sourceEventID = "rename-1"
        event.sourceSubsequence = 1
        let first = fixture.store.append(event)
        let second = fixture.store.append(event)
        #expect(first.accepted && second.accepted)
        #expect(first.eventID != second.eventID)
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        #expect(page.records.count == 2)
        #expect(page.records.map(\.sequence) == [second.sequence!, first.sequence!])
        #expect(page.records.allSatisfy { $0.target == "a\nb" && $0.profileRevision == 47 })
        let files = fixture.fs.snapshot("knodo")
        let raw = files.filter { $0.key.hasSuffix(".jsonl") }.values.reduce(Data(), +)
        let text = String(decoding: raw, as: UTF8.self)
        #expect(text.contains("\"schema_version\":1"))
        #expect(text.contains("\"event_id\":"))
        #expect(!text.contains("\"eventID\":"))
        let status = await fixture.store.status(profileID: "knodo")
        #expect(status.writtenThroughSequence == second.sequence)
        #expect(status.syncedThroughSequence == second.sequence)
        #expect(status.queuedCount == 0)
        #expect(fixture.budget.snapshot.count == 0)
    }

    @Test func boundedOverflowReturnsReceiptsAndWritesGapBeforeNextAccess() async throws {
        let budget = EventQueueBudget(maxBytes: 12_000, maxCount: 3, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(budget: budget)
        let offers = (0..<10).map { fixture.store.append(fixture.event(target: "\($0)")) }
        #expect(offers.filter(\.accepted).count <= 3)
        #expect(offers.allSatisfy { $0.sequence != nil && $0.eventID != nil && $0.writerID == "writer-test" })
        #expect(budget.snapshot.count <= 3)
        #expect(budget.snapshot.bytes <= 12_000)
        try await fixture.store.flush()
        _ = fixture.store.append(fixture.event(target: "recovered"))
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo", outcome: .denied))
        let gaps = page.records.filter { $0.kind == .gap }
        #expect(gaps.count == 1)
        #expect(gaps.first?.gap?.droppedCount == UInt64(offers.filter { !$0.accepted }.count))
        #expect(page.records.filter { $0.kind == .access }.isEmpty)
        #expect((await fixture.store.status(profileID: "knodo")).droppedCount > 0)
    }

    @Test func clearInvalidatesCursorPersistsGenerationAndPreservesLaterOffers() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event(target: "old-1"))
        _ = fixture.store.append(fixture.event(target: "old-2"))
        try await fixture.store.flush()
        let first = try await fixture.store.query(.init(profileID: "knodo", limit: 1))
        #expect(first.nextCursor != nil)
        let cleared = try await fixture.store.clear(profileID: "knodo", expectedGeneration: first.generation)
        let newer = fixture.store.append(fixture.event(target: "new"))
        #expect(newer.sequence! > cleared.cutoffSequence)
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        #expect(page.generation == first.generation + 1)
        #expect(page.records.map(\.target) == ["new"])
        await #expect(throws: AccessLogError.historyExpired) {
            try await fixture.store.query(.init(profileID: "knodo", cursor: first.nextCursor))
        }
        let restarted = fixture.restarted(writerID: "writer-next")
        #expect((await restarted.status(profileID: "knodo")).generation == cleared.generation)
        #expect(try await restarted.query(.init(profileID: "knodo")).records.map(\.target) == ["new"])
    }

    @Test func failedClearDoesNotAdvanceGenerationOrDeleteAnything() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event(target: "keep"))
        try await fixture.store.flush()
        await #expect(throws: AccessLogError.generationConflict(expected: 9, actual: 1)) {
            try await fixture.store.clear(profileID: "knodo", expectedGeneration: 9)
        }
        #expect(try await fixture.store.query(.init(profileID: "knodo")).records.map(\.target) == ["keep"])
    }

    @Test func aPreviouslyScheduledDrainCannotWriteAndThenClearPostCutoffEvents() async throws {
        var policy = AccessLogPolicy.default
        policy.batchCount = 1
        let fixture = LogFixture(policy: policy)
        _ = await fixture.store.status(profileID: "knodo")
        fixture.scheduler.pause()
        let old = fixture.store.append(fixture.event(target: "before"))
        let baseline = fixture.scheduler.immediateCount
        let clearing = Task { try await fixture.store.clear(profileID: "knodo", expectedGeneration: 1) }
        while fixture.scheduler.immediateCount == baseline { await Task.yield() }
        let newer = fixture.store.append(fixture.event(target: "after"))
        fixture.scheduler.resume()
        let cleared = try await clearing.value
        #expect(cleared.cutoffSequence == old.sequence)
        #expect(newer.sequence! > cleared.cutoffSequence)
        try await fixture.store.flush()
        #expect(try await fixture.store.query(.init(profileID: "knodo")).records.map(\.target) == ["after"])
    }

    @Test func preparedClearFixesItsCutoffBeforeTheAsyncWaitBegins() async throws {
        let fixture = LogFixture()
        let old = fixture.store.append(fixture.event(target: "before-prepare"))
        let clearing = try fixture.store.prepareClear(profileID: "knodo", expectedGeneration: 1)
        let memoryOnly = fixture.store.reserveReceipt()
        let newer = fixture.store.append(fixture.event(target: "after-prepare"))
        #expect(clearing.cutoffSequence == old.sequence)
        #expect(memoryOnly.sequence! > clearing.cutoffSequence)
        let result = try await clearing.value()
        #expect(result.cutoffSequence == old.sequence)
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        #expect(page.records.map(\.eventID) == [newer.eventID!])
    }

    @Test func partialCrashTailIsRecoveredButMiddleCorruptionIsQuarantined() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event(target: "complete"))
        try await fixture.store.flush()
        let openName = try #require(fixture.fs.snapshot("knodo").keys.first { $0.hasSuffix(".open.jsonl") })
        try fixture.fs.append(profileID: "knodo", name: openName, data: Data("{\"incomplete".utf8))
        let restarted = fixture.restarted(writerID: "second")
        let page = try await restarted.query(.init(profileID: "knodo"))
        #expect(page.records.contains { $0.target == "complete" })
        #expect((await restarted.status(profileID: "knodo")).errors.contains { $0.contains("tail") })

        let corrupt = LogFixture()
        _ = corrupt.store.append(corrupt.event())
        try await corrupt.store.flush()
        let corruptName = try #require(corrupt.fs.snapshot("knodo").keys.first { $0.hasSuffix(".open.jsonl") })
        try corrupt.fs.append(profileID: "knodo", name: corruptName, data: Data("broken\n{}\n".utf8))
        let afterCorruption = corrupt.restarted(writerID: "third")
        let corruptStatus = await afterCorruption.status(profileID: "knodo")
        #expect(corruptStatus.quarantinedSegments == 1)
        #expect(corruptStatus.bytes > 0)
        #expect(corrupt.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".quarantine.jsonl") })
    }

    @Test func futureSchemaIsPreservedAndReported() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event())
        try await fixture.store.flush()
        let name = try #require(fixture.fs.snapshot("knodo").keys.first { $0.hasSuffix(".open.jsonl") })
        let original = try #require(fixture.fs.snapshot("knodo")[name])
        let changed = String(decoding: original, as: UTF8.self).replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":999")
        try fixture.fs.replace(profileID: "knodo", name: name, data: Data(changed.utf8))
        let restarted = fixture.restarted()
        let status = await restarted.status(profileID: "knodo")
        #expect(status.unsupportedSegments == 1)
        #expect(fixture.fs.snapshot("knodo")[name] == Data(changed.utf8))
        #expect(status.bytes >= changed.utf8.count)
    }

    @Test func corruptGenerationStateStillCountsAgainstGlobalCapacity() async throws {
        let fs = LogMemoryFS()
        try fs.createProfile("damaged")
        try fs.replace(profileID: "damaged", name: "state.json", data: Data("not json".utf8))
        try fs.replace(profileID: "damaged", name: "unknown.bin", data: Data(repeating: 1, count: 5500))
        var policy = AccessLogPolicy.default
        policy.globalByteLimit = 6000
        policy.profileByteLimit = 12_000
        let fixture = LogFixture(fileSystem: fs, policy: policy)
        #expect((await fixture.store.status()).bytes >= 5500)
        _ = fixture.store.append(fixture.event(target: "cannot-exceed-global-cap"))
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        #expect(fs.snapshot("damaged")["unknown.bin"]?.count == 5500)
        #expect((await fixture.store.status(profileID: "damaged")).isReady == false)
    }

    @Test func sevenDayRetentionRunsAtRotationAndExpiresOldCursorsExplicitly() async throws {
        let fixture = LogFixture()
        var old = fixture.event(target: "eight-days-old")
        old.receivedAt = old.receivedAt.addingTimeInterval(-8 * 24 * 60 * 60)
        _ = fixture.store.append(old)
        _ = fixture.store.append(old)
        try await fixture.store.flush()
        let before = try await fixture.store.query(.init(profileID: "knodo", limit: 1))
        #expect(before.nextCursor != nil)
        _ = fixture.store.append(fixture.event(target: "current"))
        try await fixture.store.flush()
        let after = try await fixture.store.query(.init(profileID: "knodo"))
        #expect(after.records.map(\.target) == ["current"])
        #expect(after.generation > before.generation)
        let summary = await fixture.store.status(profileID: "knodo").lastCleanupSummary
        #expect(summary?.reason == "retention")
        #expect(summary?.deletedSegments == 1)
        #expect((summary?.releasedBytes ?? 0) > 0)
        await #expect(throws: AccessLogError.historyExpired) {
            try await fixture.store.query(.init(profileID: "knodo", cursor: before.nextCursor))
        }
    }

    @Test func compactCursorContinuesAcrossRotationWithoutIncludingNewerWrites() async throws {
        var policy = AccessLogPolicy.default
        policy.segmentByteLimit = 1000
        let fixture = LogFixture(policy: policy)
        for number in 0..<12 {
            _ = fixture.store.append(fixture.event(target: "\(number)"))
            try await fixture.store.flush()
        }
        let first = try await fixture.store.query(.init(profileID: "knodo", limit: 1))
        #expect(first.records.first?.target == "11")
        #expect(first.nextCursor!.utf8.count < 4096)
        _ = fixture.store.append(fixture.event(target: "newer"))
        try await fixture.store.flush()
        var all = first.records
        var cursor = first.nextCursor
        while let next = cursor {
            let page = try await fixture.store.query(.init(profileID: "knodo", cursor: next, limit: 1))
            all.append(contentsOf: page.records); cursor = page.nextCursor
        }
        #expect(all.compactMap(\.target) == (0..<12).reversed().map(String.init))
    }

    @Test func queryScanAndExportAreBoundedAndCursorSurvivesNewWrites() async throws {
        var policy = AccessLogPolicy.default
        policy.scanByteLimit = 2500
        policy.responseByteLimit = 3000
        let fixture = LogFixture(policy: policy)
        for number in 0..<20 { _ = fixture.store.append(fixture.event(target: String(repeating: "x", count: 250) + "\(number)")) }
        try await fixture.store.flush()
        let first = try await fixture.store.query(.init(profileID: "knodo", outcome: .denied))
        #expect(first.records.isEmpty)
        #expect(first.incomplete)
        #expect(first.scannedBytes <= policy.scanByteLimit)
        #expect(first.nextCursor != nil)
        _ = fixture.store.append(fixture.event(target: "after-upper-bound"))
        try await fixture.store.flush()
        var cursor = first.nextCursor
        var scans = 0
        while let current = cursor, scans < 30 {
            let page = try await fixture.store.query(.init(profileID: "knodo", outcome: .denied, cursor: current))
            #expect(page.records.isEmpty)
            cursor = page.nextCursor; scans += 1
        }
        #expect(cursor == nil)
        let exported = try await fixture.store.exportPage(.init(profileID: "knodo"), byteLimit: 2400)
        #expect(exported.data.count <= 2400)
        #expect(String(decoding: exported.data, as: UTF8.self).contains("export_header"))
        #expect(exported.nextCursor != nil)
    }

    @Test func textTruncationIsExplicitAndNeverCreatesExtraLines() async throws {
        var policy = AccessLogPolicy.default
        policy.maxTextBytes = 64
        let fixture = LogFixture(policy: policy)
        let raw = String(repeating: "中文\n", count: 500)
        _ = fixture.store.append(fixture.event(target: raw))
        try await fixture.store.flush()
        let event = try #require(try await fixture.store.query(.init(profileID: "knodo")).records.first { $0.kind == .access })
        #expect(event.target!.utf8.count <= 64)
        #expect(event.truncatedFields["target"] == raw.utf8.count)
        #expect(event.schemaVersion == 1)
    }

    @Test func diskAndSyncFailuresRemainVisibleAndQueueMemoryIsReleased() async throws {
        let fixture = LogFixture()
        // A failed first header is deliberately paused for recovery. Exercise transient writes
        // against an already-valid active segment separately from the orphan-header test.
        _ = fixture.store.append(fixture.event(target: "valid-active-segment"))
        try await fixture.store.flush()
        _ = fixture.store.append(fixture.event())
        fixture.fs.setAppendFailure(true)
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        #expect((await fixture.store.status(profileID: "knodo")).errors.count > 0)
        #expect(fixture.budget.snapshot.count == 0)
        fixture.fs.setAppendFailure(false)
        _ = fixture.store.append(fixture.event(target: "retry"))
        fixture.fs.setSyncFailure(true)
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        let status = await fixture.store.status(profileID: "knodo")
        #expect(status.writtenThroughSequence > status.syncedThroughSequence)
        fixture.fs.setSyncFailure(false)
        try await fixture.store.flush()
        #expect((await fixture.store.status(profileID: "knodo")).lastSyncedAt != nil)
    }

    @Test func closeSealsAndRejectsFurtherWritesWithoutInventingLosses() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event(target: "last"))
        await fixture.store.close()
        #expect(!fixture.store.append(fixture.event(target: "too-late")).accepted)
        #expect(!fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".open.jsonl") })
        #expect(try await fixture.store.query(.init(profileID: "knodo")).records.map(\.target) == ["last"])
        #expect((await fixture.store.status(profileID: "knodo")).droppedCount == 0)
        #expect(fixture.budget.snapshot.count == 0)
    }

    @Test(arguments: [false, true])
    func flushAndCloseCommitMoreThanOneBoundedBatch(closing: Bool) async throws {
        let fixture = LogFixture()
        for number in 0..<600 { #expect(fixture.store.append(fixture.event(target: "\(number)")).accepted) }
        if closing { await fixture.store.close() } else { try await fixture.store.flush() }
        let first = try await fixture.store.query(.init(profileID: "knodo", limit: 500))
        let second = try await fixture.store.query(.init(profileID: "knodo", cursor: first.nextCursor, limit: 500))
        #expect(first.records.count + second.records.count == 600)
        #expect(fixture.budget.snapshot.count == 0)
        #expect((await fixture.store.status(profileID: "knodo")).syncedThroughSequence >= 600)
    }

    @Test func aClearUnlinkSyncFailureCannotRecreateTheDeletedActiveFileWithoutAHeader() async throws {
        let fixture = LogFixture()
        _ = fixture.store.append(fixture.event(target: "old"))
        try await fixture.store.flush()
        fixture.fs.setRemoveFailure(suffix: ".open.jsonl", afterUnlink: true)
        await #expect(throws: (any Error).self) {
            try await fixture.store.clear(profileID: "knodo", expectedGeneration: 1)
        }
        #expect(!fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".jsonl") })
        _ = fixture.store.append(fixture.event(target: "must-stay-visible-as-unsaved"))
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        #expect(!fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".jsonl") })
        #expect((await fixture.store.status(profileID: "knodo")).isReady == false)
    }

    @Test func aClearMetadataFailurePausesSavingAndKeepsActualCapacityAccounted() async throws {
        var policy = AccessLogPolicy.default
        policy.segmentByteLimit = 700
        let fixture = LogFixture(policy: policy)
        _ = fixture.store.append(fixture.event(target: "first"))
        try await fixture.store.flush()
        _ = fixture.store.append(fixture.event(target: "second"))
        try await fixture.store.flush()
        #expect(fixture.fs.snapshot("knodo").keys.contains { $0.hasSuffix(".meta.json") })
        fixture.fs.setRemoveFailure(suffix: ".meta.json")
        let generation = await fixture.store.status(profileID: "knodo").generation
        await #expect(throws: (any Error).self) {
            try await fixture.store.clear(profileID: "knodo", expectedGeneration: generation)
        }
        let bytes = fixture.fs.snapshot("knodo").values.reduce(0) { $0 + $1.count }
        #expect((await fixture.store.status(profileID: "knodo")).bytes == bytes)
        _ = fixture.store.append(fixture.event(target: "new"))
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        for data in fixture.fs.snapshot("knodo").filter({ $0.key.hasSuffix(".jsonl") }).values {
            #expect(String(decoding: data.split(separator: 10).first!, as: UTF8.self).contains("\"record_kind\":\"segment_start\""))
        }
    }

    @Test func partialHeaderFailuresAreAccountedAndCannotAccumulateNewOrphanFiles() async throws {
        let fixture = LogFixture()
        fixture.fs.setPartialHeaderFailure(true)
        _ = fixture.store.append(fixture.event())
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        let original = fixture.fs.snapshot("knodo")
        #expect(original.keys.filter { $0.hasSuffix(".open.jsonl") }.count == 1)
        #expect((await fixture.store.status(profileID: "knodo")).bytes == original.values.reduce(0) { $0 + $1.count })
        for number in 0..<20 { _ = fixture.store.append(fixture.event(target: "\(number)")) }
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        #expect(fixture.fs.snapshot("knodo").keys.filter { $0.hasSuffix(".open.jsonl") }.count == 1)
        #expect((await fixture.store.status(profileID: "knodo")).isReady == false)
    }

    @Test func capacityCleanupCountsActiveAndUnrecognizedFilesWithoutDeletingUnknown() async throws {
        var policy = AccessLogPolicy.default
        policy.segmentByteLimit = 1800
        policy.profileByteLimit = 7000
        policy.globalByteLimit = 12000
        policy.minimumFreeBytes = 0
        let fixture = LogFixture(policy: policy)
        for number in 0..<20 {
            _ = fixture.store.append(fixture.event(target: String(repeating: "\(number)", count: 100)))
            try await fixture.store.flush()
        }
        #expect((await fixture.store.status(profileID: "knodo")).bytes <= policy.profileByteLimit)
        try fixture.fs.replace(profileID: "knodo", name: "unrecognized.bin", data: Data(repeating: 1, count: 8000))
        let restarted = fixture.restarted()
        let status = await restarted.status(profileID: "knodo")
        #expect(status.bytes >= 8000)
        #expect(fixture.fs.snapshot("knodo")["unrecognized.bin"]?.count == 8000)
        #expect(!status.errors.isEmpty)
        _ = restarted.append(fixture.event(target: "cannot-fit"))
        await #expect(throws: (any Error).self) { try await restarted.flush() }
    }

    @Test func sustainedInputCannotExceedTheSharedEventBudget() async throws {
        var policy = AccessLogPolicy.default
        policy.batchCount = 100_000
        let budget = EventQueueBudget(maxBytes: 64 * 1024, maxCount: 128)
        let fixture = LogFixture(policy: policy, budget: budget)
        var accepted = 0
        for number in 0..<5000 {
            if fixture.store.append(fixture.event(target: "/repeat/\(number)")).accepted { accepted += 1 }
            #expect(budget.snapshot.bytes <= 64 * 1024)
            #expect(budget.snapshot.count <= 128)
        }
        #expect(accepted < 128)
        let underLoad = await fixture.store.status(profileID: "knodo")
        #expect(underLoad.queuedBytes >= underLoad.queuedCount * (MemoryLayout<AccessLogRecord>.stride * 3 + 256))
        try await fixture.store.flush()
        #expect(budget.snapshot.bytes == 0)
        #expect(budget.snapshot.count == 0)
        let status = await fixture.store.status(profileID: "knodo")
        #expect(status.droppedCount == UInt64(5000 - accepted))
        #expect(status.queuedCount == 0)
    }

    @Test func flushCommitsAnOverflowSummaryWhenItsAdmissionWasDelayedByTheBudget() async throws {
        var policy = AccessLogPolicy.default
        policy.batchCount = 100_000
        let budget = EventQueueBudget(maxBytes: 12_000, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(policy: policy, budget: budget)
        _ = await fixture.store.status(profileID: "knodo")
        #expect(fixture.store.append(fixture.event(target: "accepted")).accepted)
        let lost = fixture.store.append(fixture.event(target: "overflow"))
        #expect(!lost.accepted)
        // Hold any follow-up drain so it cannot hide a flush that returned too early.
        fixture.scheduler.pauseAfterNextWrite()
        defer { fixture.scheduler.resume() }
        try await fixture.store.flush()
        #expect(budget.snapshot.bytes == 0)
        #expect(budget.snapshot.count == 0)
        let written = fixture.fs.snapshot("knodo").filter { $0.key.hasSuffix(".jsonl") }.values
        #expect(written.contains { String(decoding: $0, as: UTF8.self).contains("\"record_kind\":\"gap\"") })
    }

    @Test func flushLeavesPostCutoffAccessQueuedWhileCommittingItsEarlierLoss() async throws {
        var policy = AccessLogPolicy.default
        policy.batchCount = 100_000
        let budget = EventQueueBudget(maxBytes: 24_000, maxCount: 2, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(policy: policy, budget: budget)
        _ = await fixture.store.status(profileID: "knodo")
        #expect(fixture.store.append(fixture.event(target: "before")).accepted)
        #expect(budget.tryReserve(bytes: 1))
        #expect(!fixture.store.append(fixture.event(target: "overflow")).accepted)
        fixture.scheduler.pause()
        fixture.scheduler.pauseAfterNextWrite()
        let baseline = fixture.scheduler.immediateCount
        let flushing = Task { try await fixture.store.flush() }
        while fixture.scheduler.immediateCount == baseline { await Task.yield() }
        budget.release(bytes: 1)
        var newer = fixture.event(target: "after")
        newer.profileID = "other"
        let postCutoff = fixture.store.append(newer)
        #expect(postCutoff.accepted)
        fixture.scheduler.resume()
        var held = true
        defer { if held { fixture.scheduler.resume() } }
        try await flushing.value
        #expect(budget.snapshot.count == 1)
        #expect(!fixture.fs.snapshot("other").keys.contains { $0.hasSuffix(".jsonl") })
        let written = fixture.fs.snapshot("knodo").filter { $0.key.hasSuffix(".jsonl") }.values
        #expect(written.contains { String(decoding: $0, as: UTF8.self).contains("\"record_kind\":\"gap\"") })
        fixture.scheduler.resume()
        held = false
        try await fixture.store.flush()
        #expect(try await fixture.store.query(.init(profileID: "other")).records.map(\.eventID) == [postCutoff.eventID!])
        let gap = try #require(try await fixture.store.query(.init(profileID: "knodo")).records.first { $0.kind == .gap })
        #expect(gap.sequence < postCutoff.sequence!)
        #expect(budget.snapshot.count == 0)
    }

    @Test func flushReportsAnUnadmittedLossWithoutWaitingForUnrelatedBudgetReservations() async throws {
        let budget = EventQueueBudget(maxBytes: 12_000, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(budget: budget)
        #expect(budget.tryReserve(bytes: 1))
        #expect(!fixture.store.append(fixture.event(target: "overflow")).accepted)
        await #expect(throws: (any Error).self) { try await fixture.store.flush() }
        budget.release(bytes: 1)
        try await fixture.store.flush()
        #expect(budget.snapshot.bytes == 0)
        #expect(budget.snapshot.count == 0)
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        #expect(page.records.filter { $0.kind == .gap }.count == 1)
        #expect(page.records.first?.gap?.droppedCount == 1)
    }

    @Test(arguments: [false, true])
    func clearGivesASurvivingLossSuffixANewPostCutoffIdentity(releaseDuringClear: Bool) async throws {
        let budget = EventQueueBudget(maxBytes: 12_000, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(budget: budget)
        #expect(budget.tryReserve(bytes: 1))
        #expect(!fixture.store.append(fixture.event(target: "before-1")).accepted)
        #expect(!fixture.store.append(fixture.event(target: "before-2")).accepted)
        fixture.scheduler.pause()
        let clearing = try fixture.store.prepareClear(profileID: "knodo", expectedGeneration: 1)
        let newer = fixture.store.append(fixture.event(target: "after"))
        if releaseDuringClear {
            budget.release(bytes: 1)
            #expect(fixture.store.append(fixture.event(target: "after-capacity-recovers")).accepted)
        }
        fixture.scheduler.resume()
        let cleared = try await clearing.value()
        #expect(newer.sequence! > cleared.cutoffSequence)
        if !releaseDuringClear { budget.release(bytes: 1) }
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        let gap = try #require(page.records.first { $0.kind == .gap })
        #expect(page.records.count == (releaseDuringClear ? 2 : 1))
        #expect(gap.kind == .gap)
        #expect(gap.sequence > cleared.cutoffSequence)
        #expect(gap.gap?.firstSequence == newer.sequence)
        #expect(gap.gap?.lastSequence == newer.sequence)
        #expect(gap.gap?.droppedCount == nil)
        #expect((await fixture.store.status(profileID: "knodo")).droppedCount == 1)
        #expect(budget.snapshot.count == 0)
    }

    @Test func flushDoesNotClaimASurvivingClearSuffixWasWrittenAfterItsIdentityChanges() async throws {
        let budget = EventQueueBudget(maxBytes: 12_000, maxCount: 1, priorityReserveBytes: 0, priorityReserveCount: 0)
        let fixture = LogFixture(budget: budget)
        #expect(budget.tryReserve(bytes: 1))
        #expect(!fixture.store.append(fixture.event(target: "before-1")).accepted)
        #expect(!fixture.store.append(fixture.event(target: "before-2")).accepted)
        fixture.scheduler.pause()
        let clearing = try fixture.store.prepareClear(profileID: "knodo", expectedGeneration: 1)
        let newer = fixture.store.append(fixture.event(target: "after"))
        let baseline = fixture.scheduler.immediateCount
        let flushing = Task { try await fixture.store.flush() }
        while fixture.scheduler.immediateCount == baseline { await Task.yield() }
        budget.release(bytes: 1)
        fixture.scheduler.resume()
        let cleared = try await clearing.value()
        await #expect(throws: (any Error).self) { try await flushing.value }
        try await fixture.store.flush()
        let page = try await fixture.store.query(.init(profileID: "knodo"))
        let gap = try #require(page.records.first)
        #expect(page.records.count == 1)
        #expect(gap.kind == .gap)
        #expect(gap.sequence > cleared.cutoffSequence)
        #expect(gap.gap?.firstSequence == newer.sequence)
        #expect(gap.gap?.lastSequence == newer.sequence)
        #expect(budget.snapshot.count == 0)
    }

    @Test func sourceMicrosecondsSurvivePersistence() async throws {
        let fixture = LogFixture()
        var event = fixture.event()
        event.receivedAt = Date(timeIntervalSince1970: 1_800_000_000.123456)
        event.sourceAt = Date(timeIntervalSince1970: 1_799_999_999.987654)
        _ = fixture.store.append(event)
        try await fixture.store.flush()
        let saved = try #require(try await fixture.store.query(.init(profileID: "knodo")).records.first)
        #expect(abs(saved.receivedAt.timeIntervalSince(event.receivedAt)) < 0.000001)
        #expect(abs(saved.sourceAt!.timeIntervalSince(event.sourceAt!)) < 0.000001)
    }
}

private final class LogMemoryFS: AccessLogFileSystem, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: [String: Data]] = [:]
    private var appendFailure = false
    private var syncFailure = false
    private var removeFailureSuffix: String?
    private var removeAfterUnlink = false
    private var partialHeaderFailure = false
    func snapshot(_ profile: String) -> [String: Data] { lock.withLock { storage[profile] ?? [:] } }
    func setAppendFailure(_ value: Bool) { lock.withLock { appendFailure = value } }
    func setSyncFailure(_ value: Bool) { lock.withLock { syncFailure = value } }
    func setRemoveFailure(suffix: String, afterUnlink: Bool = false) {
        lock.withLock { removeFailureSuffix = suffix; removeAfterUnlink = afterUnlink }
    }
    func setPartialHeaderFailure(_ value: Bool) { lock.withLock { partialHeaderFailure = value } }
    func profiles() throws -> [String] { lock.withLock { Array(storage.keys) } }
    func files(profileID: String) throws -> [AccessLogFileInfo] {
        lock.withLock { (storage[profileID] ?? [:]).map { .init(name: $0.key, size: UInt64($0.value.count), isRegular: true) } }
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
        try lock.withLock {
            if appendFailure { throw AccessLogError.storageUnavailable("disk full") }
            if partialHeaderFailure && String(decoding: data, as: UTF8.self).contains("\"record_kind\":\"segment_start\"") {
                storage[profileID, default: [:]][name, default: Data()].append(data.prefix(17))
                throw AccessLogError.storageUnavailable("interrupted header")
            }
            storage[profileID, default: [:]][name, default: Data()].append(data)
        }
    }
    func replace(profileID: String, name: String, data: Data) throws { lock.withLock { storage[profileID, default: [:]][name] = data } }
    func truncate(profileID: String, name: String, size: UInt64) throws {
        lock.withLock {
            let data = storage[profileID]?[name]?.prefix(Int(size))
            storage[profileID]?[name] = data
        }
    }
    func rename(profileID: String, from: String, to: String) throws {
        try lock.withLock {
            guard let data = storage[profileID]?.removeValue(forKey: from) else { throw AccessLogError.historyExpired }
            storage[profileID]?[to] = data
        }
    }
    func remove(profileID: String, name: String) throws {
        try lock.withLock {
            let fails = removeFailureSuffix.map(name.hasSuffix) ?? false
            if fails && !removeAfterUnlink { throw AccessLogError.storageUnavailable("metadata removal failed") }
            storage[profileID]?.removeValue(forKey: name)
            if fails { throw AccessLogError.storageUnavailable("directory sync failed after unlink") }
        }
    }
    func synchronize(profileID: String, name: String) throws {
        try lock.withLock { if syncFailure { throw AccessLogError.storageUnavailable("sync failed") } }
    }
    func availableBytes() throws -> UInt64? { UInt64.max }
}

private final class LogTestScheduler: AccessLogScheduling, @unchecked Sendable {
    private let writer = DispatchQueue(label: "access-log-test-writer")
    private let reader = DispatchQueue(label: "access-log-test-reader")
    private let lock = NSLock()
    private var count = 0
    private var pauseNext = false
    var immediateCount: Int { lock.withLock { count } }
    func pause() { writer.suspend() }
    func resume() { writer.resume() }
    func pauseAfterNextWrite() { lock.withLock { pauseNext = true } }
    func write(after delay: TimeInterval, _ work: @escaping @Sendable () -> Void) {
        // Explicit flush is the deterministic clock edge. Delayed tasks are deliberately held.
        if delay == 0 {
            let pause = lock.withLock {
                count += 1
                let pause = pauseNext
                pauseNext = false
                return pause
            }
            writer.async { [writer] in
                if pause { writer.suspend() }
                work()
            }
        }
    }
    func read(_ work: @escaping @Sendable () -> Void) { reader.async(execute: work) }
}

private final class LogIDSource: @unchecked Sendable {
    private let lock = NSLock()
    private var number = 0
    func next() -> String { lock.withLock { number += 1; return "id-\(number)" } }
}

private struct LogFixture {
    let fs: LogMemoryFS
    let budget: EventQueueBudget
    let policy: AccessLogPolicy
    let store: AccessLogStore
    let scheduler: LogTestScheduler
    init(fileSystem: LogMemoryFS = .init(), policy: AccessLogPolicy = .default, budget: EventQueueBudget = .init()) {
        self.fs = fileSystem; self.budget = budget; self.policy = policy
        self.scheduler = LogTestScheduler()
        let ids = LogIDSource()
        self.store = AccessLogStore(fileSystem: fs, scheduler: scheduler,
                                   clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                                   makeID: { ids.next() }, writerID: "writer-test", budget: budget, policy: policy)
    }
    func event(target: String = "path") -> AccessLogRecord {
        .init(profileID: "knodo", operation: "open", outcome: .allowedObserved,
              receivedAt: Date(timeIntervalSince1970: 1_800_000_000), source: .eslogger, target: target)
    }
    func restarted(writerID: String = "writer-restart") -> AccessLogStore {
        let ids = LogIDSource()
        return AccessLogStore(fileSystem: fs, scheduler: LogTestScheduler(),
                              clock: { Date(timeIntervalSince1970: 1_800_000_000) },
                              makeID: { ids.next() }, writerID: writerID, budget: .init(), policy: policy)
    }
}
