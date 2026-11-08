import Foundation

/// A bounded, nonblocking intake followed by one serial writer. The filesystem and scheduling
/// boundary is injected: this type never opens a path or starts a process.
public final class AccessLogStore: @unchecked Sendable {
    private struct Pending {
        var record: AccessLogRecord
        var data: Data
        var reservation: Int
    }
    private struct Loss {
        var count: UInt64?
        var first: UInt64
        var last: UInt64
        var from: Date
        var through: Date
        var reason: String
        var identity: AccessLogAppendResult? = nil
    }
    private struct Segment: Codable, Sendable {
        var name: String
        var bytes: Int
        var firstAt: Date
        var lastAt: Date
        var firstSequence: UInt64
        var lastSequence: UInt64
        var writerID: String
        var count: Int
        var sealed: Bool
        var unsupported = false
        var quarantined = false
        var sourceGaps: UInt64 = 0
        var storageGaps: UInt64 = 0
    }
    private struct State: Codable { var schemaVersion = 1; var generation: UInt64 = 1 }
    private struct ProfileState {
        var generation: UInt64 = 1
        var segments: [Segment] = []
        var active: String?
        var bytes = 0
        var unknownBytes = 0
        var errors: [String] = []
        var writable = true
        var lastWrittenAt: Date?
        var lastSyncedAt: Date?
        var writtenThrough: UInt64 = 0
        var syncedThrough: UInt64 = 0
        var sourceGaps: UInt64 = 0
        var storageGaps: UInt64 = 0
        var coverage: AccessLogCoverage = .init()
        var lastCleanupSummary: AccessLogCleanupSummary?
    }
    private struct Header: Codable {
        var schemaVersion = 1
        var recordKind = "segment_start"
        var profileID: String
        var writerID: String
        var segmentID: String
        var createdAt: Date
        enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version", recordKind = "record_kind", profileID = "profile_id"
            case writerID = "writer_id", segmentID = "segment_id", createdAt = "created_at"
        }
    }
    private struct Version: Decodable {
        var schemaVersion: Int
        enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version" }
    }
    private struct Cursor: Codable {
        var version = 1
        var profileID: String
        var generation: UInt64
        var segment: String
        var offset: Int
        var upperSequence: UInt64
        var writerID: String
        var from: Date?
        var through: Date?
        var outcome: AccessLogOutcome?
    }
    private struct ReadSnapshot: Sendable {
        var generation: UInt64
        var segments: [Segment]
        var upperSequence: UInt64
    }

    private let fs: any AccessLogFileSystem
    private let scheduler: any AccessLogScheduling
    private let clock: @Sendable () -> Date
    private let makeID: @Sendable () -> String
    public let writerID: String
    private let budget: EventQueueBudget
    private let policy: AccessLogPolicy
    // Only intake bookkeeping is locked. No filesystem operation runs under this lock.
    private let intake = NSLock()
    private var nextSequence: UInt64 = 0
    private var pending: [Pending] = []
    private var pendingBytes = 0
    private var losses: [String: Loss] = [:]
    private var dropped: [String: UInt64] = [:]
    private var wakeScheduled = false
    private var immediateScheduled = false
    private var reading = false
    private var closed = false
    private var clearBarriers: [String: UInt64] = [:]
    // The following state belongs exclusively to the injected serial writer.
    private var profiles: [String: ProfileState] = [:]
    private var initialized = false
    private var initializationError: String?
    private var lastFailure: String?
    private var lastCleanup: Date?
    private var lastCleanupSummary: AccessLogCleanupSummary?

    public init(fileSystem: any AccessLogFileSystem, scheduler: any AccessLogScheduling,
                clock: @escaping @Sendable () -> Date, makeID: @escaping @Sendable () -> String,
                writerID: String, budget: EventQueueBudget, policy: AccessLogPolicy = .default) {
        self.fs = fileSystem; self.scheduler = scheduler; self.clock = clock; self.makeID = makeID
        self.writerID = writerID; self.budget = budget; self.policy = policy
        scheduler.write(after: 0) { [weak self] in self?.initialize() }
        scheduleMaintenance()
    }
    deinit {
        for item in pending { budget.release(bytes: item.reservation) }
    }

    /// Reserves an identity for a memory-only observation. It neither writes nor reports a loss.
    public func reserveReceipt() -> AccessLogAppendResult {
        intake.lock(); defer { intake.unlock() }
        return receipt(accepted: false)
    }

    @discardableResult
    public func append(_ input: AccessLogRecord) -> AccessLogAppendResult {
        intake.lock()
        defer { intake.unlock() }
        guard !closed else { return receipt(accepted: false) }
        // A gap is ordered before the first subsequently accepted event for the same program.
        enqueueLoss(profileID: input.profileID)
        let result = receipt(accepted: false)
        guard !closed, Self.validComponent(input.profileID) else { return result }
        var record = bounded(input)
        record.schemaVersion = 1
        record.eventID = result.eventID!
        record.writerID = writerID
        record.sequence = result.sequence!
        guard let data = try? Self.encodedLine(record), data.count <= policy.maxRecordBytes else {
            recordLoss(record, reason: "record_too_large")
            scheduleWakeLocked(immediate: false)
            return result
        }
        let cost = Self.reservationBytes(for: data.count)
        guard budget.tryReserve(bytes: cost, priority: record.kind != .access || record.outcome == .denied) else {
            recordLoss(record, reason: "queue_overflow")
            scheduleWakeLocked(immediate: false)
            return result
        }
        pending.append(Pending(record: record, data: data, reservation: cost))
        pendingBytes += cost
        scheduleWakeLocked(immediate: pending.count >= max(1, policy.batchCount))
        return AccessLogAppendResult(accepted: true, eventID: result.eventID, sequence: result.sequence, writerID: writerID)
    }

    public func status(profileID: String? = nil) async -> AccessLogStatus {
        await withCheckedContinuation { continuation in
            scheduler.write(after: 0) { [self] in
                initialize()
                var status = AccessLogStatus(profileID: profileID, writerID: writerID)
                let selected = profileID.map { [$0] } ?? Array(profiles.keys)
                if profileID == nil { status.lastCleanupSummary = lastCleanupSummary }
                for key in selected {
                    guard let state = profiles[key] else { continue }
                    if profileID != nil { status.generation = state.generation }
                    status.bytes = Self.adding(status.bytes, state.bytes)
                    status.errors.append(contentsOf: state.errors)
                    status.unsupportedSegments += state.segments.filter(\.unsupported).count
                    status.quarantinedSegments += state.segments.filter(\.quarantined).count
                    status.sourceGapCount += state.sourceGaps
                    status.storageGapCount += state.storageGaps
                    if let earliest = state.segments.filter({ !$0.unsupported && !$0.quarantined && $0.count > 0 }).map(\.firstAt).min() {
                        status.earliestRetainedAt = min(status.earliestRetainedAt ?? earliest, earliest)
                    }
                    status.lastWrittenAt = Self.later(status.lastWrittenAt, state.lastWrittenAt)
                    status.lastSyncedAt = Self.later(status.lastSyncedAt, state.lastSyncedAt)
                    status.writtenThroughSequence = max(status.writtenThroughSequence, state.writtenThrough)
                    status.syncedThroughSequence = max(status.syncedThroughSequence, state.syncedThrough)
                    if profileID != nil { status.coverage = state.coverage }
                    if profileID != nil { status.lastCleanupSummary = state.lastCleanupSummary }
                }
                if let initializationError { status.errors.append(initializationError) }
                intake.lock()
                let queued = pending.filter { profileID == nil || $0.record.profileID == profileID }
                status.queuedCount = queued.count
                status.queuedBytes = queued.reduce(0) { $0 + $1.reservation }
                status.droppedCount = dropped.filter { profileID == nil || $0.key == profileID }.values.reduce(0, +)
                let accepting = !closed
                intake.unlock()
                status.errors = Array(Set(status.errors)).sorted()
                status.isReady = accepting && initializationError == nil && selected.allSatisfy { profiles[$0]?.writable ?? true }
                continuation.resume(returning: status)
            }
        }
    }

    public func flush() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            intake.lock()
            for key in losses.keys.sorted() { enqueueLoss(profileID: key) }
            let cutoff = nextSequence
            scheduler.write(after: 0) { [self] in
                initialize()
                lastFailure = nil
                drainAll(through: cutoff)
                if lastFailure == nil && intake.withLock({
                    pending.contains { item in
                        if item.record.sequence <= cutoff { return true }
                        // Clear can give a surviving loss suffix a later diagnostic identity.
                        guard item.record.kind == .gap, item.record.source == .storage,
                              let first = item.record.gap?.firstSequence else { return false }
                        return first <= cutoff
                    } || losses.values.contains { $0.first <= cutoff }
                }) {
                    lastFailure = "pre-cutoff records or loss summaries remain queued"
                }
                synchronizeAll()
                if let failure = lastFailure ?? initializationError {
                    continuation.resume(throwing: AccessLogError.storageUnavailable(failure))
                } else { continuation.resume() }
            }
            intake.unlock()
        }
    }

    /// Stops intake first, then drains and seals on the writer. A shutdown error is retained in
    /// status; closing does not stop, signal, or otherwise affect a managed program.
    public func close() async {
        await withCheckedContinuation { continuation in
            intake.lock()
            closed = true
            scheduler.write(after: 0) { [self] in
                drainAll(through: nil)
                for id in profiles.keys.sorted() {
                    do { try seal(id) }
                    catch { addError(id, "close: \(error)") }
                }
                continuation.resume()
            }
            intake.unlock()
        }
    }

    public func query(_ query: AccessLogQuery) async throws -> AccessLogPage {
        try await queryPage(query, responseLimit: policy.responseByteLimit)
    }

    public func exportPage(_ query: AccessLogQuery, byteLimit: Int) async throws -> AccessLogExportPage {
        // A header in each independently bounded chunk keeps partial exports self-describing.
        let maximum = min(policy.responseByteLimit, max(1, byteLimit))
        let header = Data(("{\"schema_version\":1,\"record_kind\":\"export_header\","
            + "\"notice\":\"Metadata only; successful network traffic is not covered. "
            + "Gap and storage_status records remain visible under outcome filters. "
            + "truncated_fields contains original UTF-8 lengths.\"}\n").utf8)
        guard header.count < maximum else { throw AccessLogError.storageUnavailable("export byte limit is too small") }
        let page = try await queryPage(query, responseLimit: maximum - header.count)
        var data = header
        for record in page.records { data.append(try Self.encodedLine(record)) }
        return AccessLogExportPage(data: data, nextCursor: page.nextCursor, generation: page.generation,
                                   incomplete: page.incomplete, recordCount: page.records.count)
    }

    public func clear(profileID: String, expectedGeneration: UInt64) async throws -> AccessLogClearResult {
        try await prepareClear(profileID: profileID, expectedGeneration: expectedGeneration).value()
    }

    public func prepareClear(profileID: String, expectedGeneration: UInt64) throws -> AccessLogClearOperation {
        guard Self.validComponent(profileID) else { throw AccessLogError.invalidProfileID }
        // Scheduling the barrier while holding intake makes all later offers post-cutoff.
        return try intake.withLock {
            let cutoff = nextSequence
            let droppedAtCutoff = dropped[profileID] ?? 0
            if clearBarriers[profileID] != nil {
                throw AccessLogError.queryBusy
            }
            let operation = AccessLogClearOperation(cutoffSequence: cutoff, writerID: writerID)
            clearBarriers[profileID] = cutoff
            scheduler.write(after: 0) { [self] in
                defer {
                    intake.lock()
                    clearBarriers.removeValue(forKey: profileID)
                    if !pending.isEmpty { scheduleWakeLocked(immediate: true) }
                    intake.unlock()
                }
                var mutationStarted = false
                do {
                    initialize()
                    try ensureProfile(profileID)
                    let old = profiles[profileID]!
                    guard old.writable else { throw AccessLogError.storageUnavailable("unsafe log state requires review before clearing") }
                    guard old.generation == expectedGeneration else {
                        throw AccessLogError.generationConflict(expected: expectedGeneration, actual: old.generation)
                    }
                    guard !old.segments.contains(where: \.unsupported) else {
                        throw AccessLogError.storageUnavailable("unsupported log version must be reviewed before clearing")
                    }
                    // Persist the new epoch before deleting. A failed deletion is visible and cannot
                    // make an already-issued cursor valid again after restart.
                    let newGeneration = old.generation + 1
                    mutationStarted = true
                    try persistGeneration(profileID, generation: newGeneration)
                    profiles[profileID]!.generation = newGeneration
                    var removed = 0
                    for segment in old.segments {
                        try fs.remove(profileID: profileID, name: segment.name)
                        removed = Self.adding(removed, segment.bytes)
                        try removeMeta(profileID, name: segment.name)
                    }
                    profiles[profileID]!.segments = []
                    profiles[profileID]!.active = nil
                    profiles[profileID]!.lastWrittenAt = nil
                    profiles[profileID]!.lastSyncedAt = nil
                    profiles[profileID]!.writtenThrough = 0
                    profiles[profileID]!.syncedThrough = 0
                    profiles[profileID]!.sourceGaps = 0
                    profiles[profileID]!.storageGaps = 0
                    intake.lock()
                    dropped[profileID] = (dropped[profileID] ?? 0) - min(dropped[profileID] ?? 0, droppedAtCutoff)
                    pending.removeAll {
                        if $0.record.profileID == profileID && $0.record.sequence <= cutoff {
                            budget.release(bytes: $0.reservation); pendingBytes -= $0.reservation
                            return true
                        }
                        return false
                    }
                    if var loss = losses[profileID] {
                        if loss.last <= cutoff { losses.removeValue(forKey: profileID) }
                        else if loss.first <= cutoff {
                            loss.first = cutoff + 1; loss.count = nil; loss.identity = nil
                            losses[profileID] = loss
                        }
                    }
                    intake.unlock()
                    try refreshBytes(profileID)
                    removed = max(0, old.bytes - profiles[profileID]!.bytes)
                    operation.finish(.success(AccessLogClearResult(profileID: profileID, generation: newGeneration,
                        cutoffSequence: cutoff, writerID: writerID, removedBytes: removed)))
                } catch {
                    if mutationStarted {
                        profiles[profileID]!.writable = false
                        profiles[profileID]!.active = nil
                        do { try refreshBytes(profileID) }
                        catch { initializationError = "cannot account for a partially cleared log directory" }
                    }
                    addError(profileID, "clear: \(error)")
                    operation.finish(.failure(error))
                }
            }
            return operation
        }
    }

    private func receipt(accepted: Bool) -> AccessLogAppendResult {
        nextSequence &+= 1
        return .init(accepted: accepted, eventID: "\(writerID):\(makeID())", sequence: nextSequence, writerID: writerID)
    }
    private func scheduleWakeLocked(immediate: Bool) {
        if immediate && !immediateScheduled {
            immediateScheduled = true
            scheduler.write(after: 0) { [weak self] in self?.drain() }
        } else if !wakeScheduled {
            wakeScheduled = true
            scheduler.write(after: max(0.01, policy.flushInterval)) { [weak self] in
                guard let self else { return }
                self.intake.lock(); self.wakeScheduled = false; self.intake.unlock()
                self.drain(); self.synchronizeAll()
            }
        }
    }
    private func recordLoss(_ record: AccessLogRecord, reason: String) {
        dropped[record.profileID, default: 0] &+= 1
        if var value = losses[record.profileID] {
            if let count = value.count { value.count = count &+ 1 }
            value.last = record.sequence; value.through = record.receivedAt
            if value.reason != reason { value.reason = "multiple_storage_losses" }
            losses[record.profileID] = value
        } else {
            losses[record.profileID] = Loss(count: 1, first: record.sequence, last: record.sequence,
                                           from: record.receivedAt, through: record.receivedAt, reason: reason)
        }
    }
    // Caller holds intake. No I/O, and at most one aggregate exists per profile.
    private func enqueueLoss(profileID: String) {
        guard Self.validComponent(profileID), clearBarriers[profileID] == nil,
              var loss = losses[profileID] else { return }
        // A full budget may postpone admission until a drain releases capacity. Fix the
        // diagnostic identity now so a flush cutoff includes this already-existing loss.
        if loss.identity == nil {
            loss.identity = receipt(accepted: true)
            losses[profileID] = loss
        }
        var record = AccessLogRecord(profileID: profileID, operation: "storage_gap", outcome: .unknown,
                                     receivedAt: clock(), source: .storage, evidence: loss.reason)
        let identity = loss.identity!
        record.kind = .gap; record.eventID = identity.eventID!; record.writerID = writerID
        record.sequence = identity.sequence!
        record.gap = .init(reason: loss.reason, droppedCount: loss.count, firstSequence: loss.first,
                           lastSequence: loss.last, from: loss.from, through: loss.through)
        guard let data = try? Self.encodedLine(record) else { return }
        let reservation = Self.reservationBytes(for: data.count)
        guard budget.tryReserve(bytes: reservation, priority: true) else { return }
        let item = Pending(record: record, data: data, reservation: reservation)
        // Other profiles may have accepted later records while this diagnostic lacked
        // capacity. Keep the queue in receipt order when the delayed admission succeeds.
        if let last = pending.last, last.record.sequence > record.sequence,
           let index = pending.firstIndex(where: { $0.record.sequence > record.sequence }) {
            pending.insert(item, at: index)
        } else { pending.append(item) }
        pendingBytes += reservation
        losses.removeValue(forKey: profileID)
    }

    private func drain(through cutoff: UInt64? = nil, reschedule: Bool = true) {
        initialize()
        lastFailure = nil
        intake.lock()
        immediateScheduled = false
        let batch = Array(pending.lazy.filter { item in
            (cutoff.map { item.record.sequence <= $0 } ?? true)
                && (self.clearBarriers[item.record.profileID].map { item.record.sequence <= $0 } ?? true)
        }.prefix(max(1, policy.batchCount)))
        let selected = Set(batch.map { $0.record.sequence })
        pending.removeAll { selected.contains($0.record.sequence) }
        pendingBytes -= batch.reduce(0) { $0 + $1.reservation }
        intake.unlock()
        for item in batch {
            do { try write(item) }
            catch {
                lastFailure = "\(error)"
                addError(item.record.profileID, "write: \(error)")
                repairPartialAppend(item.record.profileID)
                intake.lock(); recordLoss(item.record, reason: "write_failed"); intake.unlock()
            }
            budget.release(bytes: item.reservation)
        }
        // Coalesced gaps can now use the capacity just released. Do not retry a failed disk
        // operation in a tight loop; retain the aggregate for the next scheduled flush instead.
        if lastFailure == nil {
            intake.lock()
            for key in losses.keys.sorted() where clearBarriers[key] == nil { enqueueLoss(profileID: key) }
            // Never pull a later diagnostic ahead of an already-queued access record.
            let remaining = max(0, max(1, policy.batchCount) - batch.count)
            let gaps = Array(pending.prefix { item in
                item.record.kind == .gap && clearBarriers[item.record.profileID] == nil
                    && (cutoff.map { item.record.sequence <= $0 } ?? true)
            }.prefix(remaining))
            pending.removeFirst(gaps.count)
            pendingBytes -= gaps.reduce(0) { $0 + $1.reservation }
            intake.unlock()
            for item in gaps {
                do { try write(item) }
                catch {
                    lastFailure = "\(error)"; addError(item.record.profileID, "gap write: \(error)")
                    intake.lock()
                    if let gap = item.record.gap {
                        let restored = Loss(count: gap.droppedCount, first: gap.firstSequence ?? item.record.sequence,
                            last: gap.lastSequence ?? item.record.sequence, from: gap.from ?? item.record.receivedAt,
                            through: gap.through ?? item.record.receivedAt, reason: gap.reason)
                        if let existing = losses[item.record.profileID] {
                            losses[item.record.profileID] = Loss(
                                count: existing.count.flatMap { a in restored.count.map { a &+ $0 } },
                                first: min(existing.first, restored.first), last: max(existing.last, restored.last),
                                from: min(existing.from, restored.from), through: max(existing.through, restored.through),
                                reason: existing.reason == restored.reason ? existing.reason : "multiple_storage_losses")
                        } else { losses[item.record.profileID] = restored }
                    }
                    intake.unlock()
                }
                budget.release(bytes: item.reservation)
            }
        }
        synchronizeAll()
        if reschedule {
            intake.lock()
            if !closed {
                if lastFailure != nil { scheduleWakeLocked(immediate: false) }
                else if pending.contains(where: { clearBarriers[$0.record.profileID] == nil }) {
                    scheduleWakeLocked(immediate: true)
                }
            }
            intake.unlock()
        }
    }

    private func drainAll(through cutoff: UInt64?) {
        repeat {
            drain(through: cutoff, reschedule: false)
            if lastFailure != nil && cutoff != nil { break }
            let more = intake.withLock {
                pending.contains { item in
                    (cutoff.map { item.record.sequence <= $0 } ?? true) && clearBarriers[item.record.profileID] == nil
                }
            }
            if !more { break }
        } while true
        intake.lock()
        if !closed && !pending.isEmpty { scheduleWakeLocked(immediate: lastFailure == nil) }
        intake.unlock()
    }

    private func repairPartialAppend(_ id: String) {
        guard let state = profiles[id], let name = state.active,
              let segment = state.segments.first(where: { $0.name == name }) else { return }
        do {
            try fs.truncate(profileID: id, name: name, size: UInt64(segment.bytes))
        } catch {
            profiles[id]!.writable = false
            addError(id, "partial append could not be repaired; saving paused")
        }
    }

    private func write(_ item: Pending) throws {
        let id = item.record.profileID
        try ensureProfile(id)
        guard profiles[id]!.writable else { throw AccessLogError.storageUnavailable("profile log requires review") }
        if let name = profiles[id]!.active, let segment = profiles[id]!.segments.first(where: { $0.name == name }),
           segment.bytes + item.data.count >= policy.segmentByteLimit
            || item.record.receivedAt.timeIntervalSince(segment.firstAt) >= policy.segmentInterval {
            try seal(id)
        }
        // Keep room for the active header and its eventual sealed metadata as well as this line.
        try reclaim(projectedProfile: id, additionalBytes: item.data.count + (profiles[id]!.active == nil ? 1536 : 512))
        if profiles[id]!.active == nil { try startSegment(id, at: item.record.receivedAt) }
        let name = profiles[id]!.active!
        try fs.append(profileID: id, name: name, data: item.data)
        let index = profiles[id]!.segments.firstIndex { $0.name == name }!
        profiles[id]!.segments[index].bytes += item.data.count
        profiles[id]!.segments[index].count += 1
        if profiles[id]!.segments[index].count == 1 {
            profiles[id]!.segments[index].firstAt = item.record.receivedAt
            profiles[id]!.segments[index].firstSequence = item.record.sequence
        }
        profiles[id]!.segments[index].lastAt = item.record.receivedAt
        profiles[id]!.segments[index].lastSequence = item.record.sequence
        profiles[id]!.bytes += item.data.count
        profiles[id]!.lastWrittenAt = clock()
        profiles[id]!.writtenThrough = max(profiles[id]!.writtenThrough, item.record.sequence)
        profiles[id]!.coverage = item.record.coverage
        if item.record.kind == .gap && item.record.source != .storage {
            profiles[id]!.sourceGaps &+= 1; profiles[id]!.segments[index].sourceGaps &+= 1
        }
        if item.record.kind == .gap && item.record.source == .storage {
            profiles[id]!.storageGaps &+= 1; profiles[id]!.segments[index].storageGaps &+= 1
        }
    }

    private func initialize() {
        guard !initialized else { return }
        initialized = true
        do {
            let ids = try fs.profiles()
            guard ids.count <= policy.maxDirectoryEntries else {
                throw AccessLogError.storageUnavailable("too many access-log profile directories")
            }
            guard ids.allSatisfy(Self.validComponent) else { throw AccessLogError.storageUnavailable("unrecognized profile directory") }
            for id in ids {
                do { try recover(id) }
                catch {
                    let unmeasured = profiles[id] == nil
                    addError(id, "recovery: \(error)"); profiles[id]!.writable = false
                    if unmeasured { throw AccessLogError.storageUnavailable("log directory size could not be safely accounted for") }
                }
            }
            try reclaim(projectedProfile: nil, additionalBytes: 0)
            lastCleanup = clock()
        } catch { initializationError = "access log initialization: \(error)" }
    }
    private func ensureProfile(_ id: String) throws {
        guard Self.validComponent(id) else { throw AccessLogError.invalidProfileID }
        guard initializationError == nil else { throw AccessLogError.storageUnavailable(initializationError!) }
        if profiles[id] == nil {
            try fs.createProfile(id)
            profiles[id] = ProfileState()
            try persistGeneration(id, generation: 1)
            try refreshBytes(id)
        }
    }
    private func recover(_ id: String) throws {
        var state = ProfileState()
        let files = try fs.files(profileID: id)
        state.bytes = files.reduce(0) { Self.adding($0, Int(clamping: $1.size)) }
        // Generation decoding can fail. Capacity accounting must survive that failure.
        profiles[id] = state
        guard files.count <= policy.maxDirectoryEntries else {
            throw AccessLogError.storageUnavailable("too many files in access-log directory")
        }
        if let file = files.first(where: { $0.name == "state.json" }) {
            guard file.isRegular, file.size <= 4096 else { throw AccessLogError.storageUnavailable("invalid log generation state") }
            let stored = try Self.decoder().decode(State.self, from: fs.read(profileID: id, name: "state.json", offset: 0, limit: 4096))
            guard stored.schemaVersion == 1, stored.generation > 0 else { throw AccessLogError.unsupportedVersion(stored.schemaVersion) }
            state.generation = stored.generation
        }
        profiles[id] = state
        for file in files where Self.segmentName(file.name) {
            guard file.isRegular, file.size <= UInt64(Int.max) else {
                addError(id, "unsafe log entry requires review"); profiles[id]!.writable = false; continue
            }
            let quarantined = file.name.hasSuffix(".quarantine.jsonl")
            if quarantined {
                profiles[id]!.segments.append(Segment(name: file.name, bytes: Int(file.size), firstAt: clock(),
                    lastAt: clock(), firstSequence: 0, lastSequence: 0, writerID: "", count: 0,
                    sealed: true, quarantined: true))
                continue
            }
            try recoverSegment(id, file: file)
        }
        let known = Set(profiles[id]!.segments.map(\.name))
        let knownMeta = Set(profiles[id]!.segments.map { Self.baseName($0.name) + ".meta.json" })
        let unknown = files.filter {
            $0.name != "state.json" && !known.contains($0.name) && !knownMeta.contains($0.name)
                && !Self.segmentName($0.name)
        }
        profiles[id]!.unknownBytes = unknown.reduce(0) { Self.adding($0, Int(clamping: $1.size)) }
        if !unknown.isEmpty { addError(id, "unrecognized files are preserved and count toward the log capacity") }
        try refreshBytes(id)
    }
    private func recoverSegment(_ id: String, file: AccessLogFileInfo) throws {
        var segment: Segment?
        var buffer = Data()
        var offset = 0
        var completed = 0
        var corrupt = false
        var unsupported = false
        while offset < Int(file.size) && !corrupt && !unsupported {
            let bytes = try fs.read(profileID: id, name: file.name, offset: UInt64(offset), limit: min(64 * 1024, Int(file.size) - offset))
            guard !bytes.isEmpty else { throw AccessLogError.historyExpired }
            offset += bytes.count; buffer.append(bytes)
            while let end = buffer.firstIndex(of: 10) {
                let line = Data(buffer[..<end])
                buffer.removeSubrange(...end)
                completed += line.count + 1
                guard line.count <= policy.maxRecordBytes else { corrupt = true; break }
                if let version = try? Self.decoder().decode(Version.self, from: line), version.schemaVersion != 1 {
                    unsupported = true; break
                }
                if segment == nil {
                    guard let header = try? Self.decoder().decode(Header.self, from: line),
                          header.recordKind == "segment_start", header.profileID == id else { corrupt = true; break }
                    segment = Segment(name: file.name, bytes: Int(file.size), firstAt: header.createdAt,
                        lastAt: header.createdAt, firstSequence: 0, lastSequence: 0, writerID: header.writerID,
                        count: 0, sealed: !file.name.hasSuffix(".open.jsonl"))
                } else {
                    guard let record = try? Self.decoder().decode(AccessLogRecord.self, from: line),
                          record.profileID == id else { corrupt = true; break }
                    if segment!.count == 0 { segment!.firstAt = record.receivedAt; segment!.firstSequence = record.sequence }
                    segment!.count += 1; segment!.lastAt = record.receivedAt; segment!.lastSequence = record.sequence
                    if record.kind == .gap && record.source != .storage {
                        profiles[id]!.sourceGaps &+= 1; segment!.sourceGaps &+= 1
                    }
                    if record.kind == .gap && record.source == .storage {
                        profiles[id]!.storageGaps &+= 1; segment!.storageGaps &+= 1
                    }
                }
            }
            if buffer.count > policy.maxRecordBytes { corrupt = true }
        }
        if unsupported {
            profiles[id]!.segments.append(Segment(name: file.name, bytes: Int(file.size), firstAt: .distantPast,
                lastAt: .distantPast, firstSequence: 0, lastSequence: 0, writerID: "", count: 0,
                sealed: true, unsupported: true))
            addError(id, "unsupported schema version preserved: \(file.name)")
            recoveryDiagnostic(id, reason: "unsupported_schema_preserved", kind: .storageStatus)
            return
        }
        if !buffer.isEmpty && !corrupt && segment != nil && file.name.hasSuffix(".open.jsonl") {
            try fs.truncate(profileID: id, name: file.name, size: UInt64(completed))
            try fs.synchronize(profileID: id, name: file.name)
            segment!.bytes = completed
            addError(id, "recovered incomplete crash tail; the interrupted interval may contain missing events")
            recoveryDiagnostic(id, reason: "incomplete_crash_tail")
        } else if !buffer.isEmpty { corrupt = true }
        guard !corrupt, var recovered = segment else {
            let name = Self.baseName(file.name) + ".quarantine.jsonl"
            try fs.rename(profileID: id, from: file.name, to: name)
            profiles[id]!.segments.append(Segment(name: name, bytes: Int(file.size), firstAt: clock(),
                lastAt: clock(), firstSequence: 0, lastSequence: 0, writerID: "", count: 0,
                sealed: true, quarantined: true))
            addError(id, "corrupt segment quarantined; its records cannot be treated as complete")
            recoveryDiagnostic(id, reason: "corrupt_segment_quarantined")
            return
        }
        // A previous writer's open segment is never appended by a new writer.
        if !recovered.sealed {
            let sealed = Self.baseName(recovered.name) + ".jsonl"
            try fs.synchronize(profileID: id, name: recovered.name)
            try fs.rename(profileID: id, from: recovered.name, to: sealed)
            recovered.name = sealed; recovered.sealed = true
            addError(id, "recovered an unsealed segment; final unsynchronized events may be missing")
            if buffer.isEmpty { recoveryDiagnostic(id, reason: "unsealed_segment_recovered") }
        }
        profiles[id]!.segments.append(recovered)
        try writeMeta(id, segment: recovered)
    }

    private func startSegment(_ id: String, at date: Date) throws {
        let identifier: String = intake.withLock { "segment-\(Self.safeID(writerID))-\(Self.safeID(makeID()))" }
        let name = identifier + ".open.jsonl"
        // Never append a new header to a collision left by an older writer.
        let files = try fs.files(profileID: id)
        guard files.count + 2 <= policy.maxDirectoryEntries else {
            throw AccessLogError.storageUnavailable("log directory entry budget exceeded")
        }
        guard !files.contains(where: { $0.name == name }) else {
            throw AccessLogError.storageUnavailable("duplicate access-log segment identity")
        }
        let header = Header(profileID: id, writerID: writerID, segmentID: identifier, createdAt: date)
        let bytes = try Self.encodedLine(header)
        do { try fs.append(profileID: id, name: name, data: bytes) }
        catch {
            profiles[id]!.writable = false
            profiles[id]!.active = nil
            do { try refreshBytes(id) }
            catch { initializationError = "cannot account for an interrupted log header write" }
            throw error
        }
        profiles[id]!.segments.append(Segment(name: name, bytes: bytes.count, firstAt: date, lastAt: date,
            firstSequence: 0, lastSequence: 0, writerID: writerID, count: 0, sealed: false))
        profiles[id]!.active = name
        profiles[id]!.bytes += bytes.count
    }
    private func seal(_ id: String) throws {
        guard let name = profiles[id]!.active,
              let index = profiles[id]!.segments.firstIndex(where: { $0.name == name }) else { return }
        try fs.synchronize(profileID: id, name: name)
        profiles[id]!.lastSyncedAt = clock()
        profiles[id]!.syncedThrough = profiles[id]!.writtenThrough
        let sealed = Self.baseName(name) + ".jsonl"
        try fs.rename(profileID: id, from: name, to: sealed)
        profiles[id]!.segments[index].name = sealed
        profiles[id]!.segments[index].sealed = true
        profiles[id]!.active = nil
        lastCleanup = nil
        try writeMeta(id, segment: profiles[id]!.segments[index])
        try refreshBytes(id)
    }
    private func synchronizeAll() {
        for id in profiles.keys.sorted() {
            guard let name = profiles[id]!.active else { continue }
            do {
                try fs.synchronize(profileID: id, name: name)
                profiles[id]!.lastSyncedAt = clock()
                profiles[id]!.syncedThrough = profiles[id]!.writtenThrough
            } catch { lastFailure = "\(error)"; addError(id, "synchronize: \(error)") }
        }
    }
    private func persistGeneration(_ id: String, generation: UInt64) throws {
        try fs.replace(profileID: id, name: "state.json", data: Self.encoder().encode(State(generation: generation)))
        try fs.synchronize(profileID: id, name: "state.json")
    }
    private func writeMeta(_ id: String, segment: Segment) throws {
        let name = Self.baseName(segment.name) + ".meta.json"
        try fs.replace(profileID: id, name: name, data: Self.encoder().encode(segment))
        try fs.synchronize(profileID: id, name: name)
    }
    private func removeMeta(_ id: String, name: String) throws {
        let meta = Self.baseName(name) + ".meta.json"
        if try fs.files(profileID: id).contains(where: { $0.name == meta }) { try fs.remove(profileID: id, name: meta) }
    }
    private func refreshBytes(_ id: String) throws {
        let files = try fs.files(profileID: id)
        guard files.count <= policy.maxDirectoryEntries else { throw AccessLogError.storageUnavailable("log directory entry budget exceeded") }
        profiles[id]!.bytes = files.reduce(0) { Self.adding($0, Int(clamping: $1.size)) }
    }

    private func reclaim(projectedProfile: String?, additionalBytes: Int) throws {
        let now = clock()
        let beforeBytes = profiles.mapValues(\.bytes)
        let due = lastCleanup == nil || now.timeIntervalSince(lastCleanup!) >= policy.cleanupInterval
        var free = try fs.availableBytes()
        let (neededFree, freeOverflow) = policy.minimumFreeBytes.addingReportingOverflow(UInt64(max(0, additionalBytes)))
        let requiredFree = freeOverflow ? UInt64.max : neededFree
        let lowDisk = free.map { $0 < requiredFree } ?? false
        let globalOver = Self.adding(profiles.values.reduce(0) { Self.adding($0, $1.bytes) }, additionalBytes) > policy.globalByteLimit
        let overProfiles = Set(profiles.compactMap { id, state in
            Self.adding(state.bytes, id == projectedProfile ? additionalBytes : 0) > policy.profileByteLimit ? id : nil
        })
        let profileOver = !overProfiles.isEmpty
        if !due && !globalOver && !profileOver && !lowDisk { return }
        for id in overProfiles { try seal(id) }
        if globalOver || lowDisk { for id in profiles.keys.sorted() { try seal(id) } }
        let profileTarget = Int(Double(policy.profileByteLimit) * policy.cleanupLowWatermark)
        let globalTarget = Int(Double(policy.globalByteLimit) * policy.cleanupLowWatermark)
        let candidates = profiles.flatMap { id, state in state.segments.map { (id, $0) } }
            .filter { $0.1.sealed && !$0.1.unsupported }
            .sorted {
                if $0.1.lastAt != $1.1.lastAt { return $0.1.lastAt < $1.1.lastAt }
                return $0.1.name < $1.1.name
            }
        var changed: Set<String> = []
        var deleted: [String: Int] = [:]
        for (id, segment) in candidates {
            let expired = now.timeIntervalSince(segment.lastAt) > policy.retentionInterval
            let profileNeeds = overProfiles.contains(id)
                && Self.adding(profiles[id]!.bytes, id == projectedProfile ? additionalBytes : 0) > profileTarget
            let globalNeeds = globalOver && Self.adding(profiles.values.reduce(0) { Self.adding($0, $1.bytes) }, additionalBytes) > globalTarget
            let diskNeeds = free.map { $0 < requiredFree } ?? false
            guard expired || profileNeeds || globalNeeds || diskNeeds else { continue }
            do {
                if !changed.contains(id) {
                    profiles[id]!.generation &+= 1
                    try persistGeneration(id, generation: profiles[id]!.generation)
                    changed.insert(id)
                }
                try fs.remove(profileID: id, name: segment.name)
                deleted[id, default: 0] += 1
                profiles[id]!.segments.removeAll { $0.name == segment.name }
                profiles[id]!.sourceGaps -= min(profiles[id]!.sourceGaps, segment.sourceGaps)
                profiles[id]!.storageGaps -= min(profiles[id]!.storageGaps, segment.storageGaps)
                try removeMeta(id, name: segment.name)
                try refreshBytes(id)
            } catch {
                profiles[id]!.writable = false
                profiles[id]!.active = nil
                addError(id, "cleanup failed; saving paused until recovery")
                do { try refreshBytes(id) }
                catch { initializationError = "cannot account for a partially cleaned log directory" }
                throw error
            }
            changed.insert(id)
            free = try fs.availableBytes()
        }
        for id in changed {
            try refreshBytes(id)
        }
        lastCleanup = now
        let global = profiles.values.reduce(0) { Self.adding($0, $1.bytes) }
        let reason = lowDisk ? "low_disk" : (globalOver || profileOver ? "capacity" : "retention")
        for id in changed.union(projectedProfile.map { Set([$0]) } ?? []) {
            guard profiles[id] != nil else { continue }
            profiles[id]!.lastCleanupSummary = .init(occurredAt: now, reason: reason,
                releasedBytes: max(0, (beforeBytes[id] ?? 0) - profiles[id]!.bytes),
                deletedSegments: deleted[id] ?? 0,
                earliestRetainedAt: profiles[id]!.segments.filter { !$0.unsupported && !$0.quarantined && $0.count > 0 }.map(\.firstAt).min())
        }
        lastCleanupSummary = .init(occurredAt: now, reason: reason,
            releasedBytes: max(0, beforeBytes.values.reduce(0, Self.adding) - global),
            deletedSegments: deleted.values.reduce(0, +),
            earliestRetainedAt: profiles.values.flatMap(\.segments).filter { !$0.unsupported && !$0.quarantined && $0.count > 0 }.map(\.firstAt).min())
        guard Self.adding(global, additionalBytes) <= policy.globalByteLimit,
              projectedProfile.map({ Self.adding(profiles[$0, default: ProfileState()].bytes, additionalBytes) <= policy.profileByteLimit }) ?? true,
              free.map({ $0 >= requiredFree }) ?? true else {
            throw AccessLogError.storageUnavailable("capacity unavailable; unrecognized or unsupported files are preserved")
        }
    }
    private func scheduleMaintenance() {
        scheduler.write(after: max(1, policy.cleanupInterval)) { [weak self] in
            guard let self else { return }
            guard !self.intake.withLock({ self.closed }) else { return }
            self.initialize()
            do { try self.reclaim(projectedProfile: nil, additionalBytes: 0) }
            catch { self.lastFailure = "\(error)" }
            self.scheduleMaintenance()
        }
    }

    private func queryPage(_ query: AccessLogQuery, responseLimit: Int) async throws -> AccessLogPage {
        guard Self.validComponent(query.profileID) else { throw AccessLogError.invalidProfileID }
        let snapshot: ReadSnapshot = try await withCheckedThrowingContinuation { continuation in
            scheduler.write(after: 0) { [self] in
                initialize()
                if let initializationError { continuation.resume(throwing: AccessLogError.storageUnavailable(initializationError)); return }
                let state = profiles[query.profileID] ?? ProfileState()
                continuation.resume(returning: ReadSnapshot(generation: state.generation,
                    segments: state.segments.filter { !$0.unsupported && !$0.quarantined && $0.count > 0 },
                    upperSequence: state.writtenThrough))
            }
        }
        let admitted = intake.withLock {
            if reading { return false }
            reading = true; return true
        }
        guard admitted else { throw AccessLogError.queryBusy }
        defer { intake.withLock { reading = false } }
        do {
            let page: AccessLogPage = try await withCheckedThrowingContinuation { continuation in
                scheduler.read { [self] in
                    do { continuation.resume(returning: try scan(query, snapshot: snapshot, responseLimit: responseLimit)) }
                    catch { continuation.resume(throwing: error) }
                }
            }
            guard await currentGeneration(query.profileID) == snapshot.generation else { throw AccessLogError.historyExpired }
            return page
        } catch {
            guard await currentGeneration(query.profileID) == snapshot.generation else { throw AccessLogError.historyExpired }
            throw error
        }
    }
    private func currentGeneration(_ id: String) async -> UInt64 {
        await withCheckedContinuation { continuation in
            scheduler.write(after: 0) { [self] in continuation.resume(returning: profiles[id]?.generation ?? 1) }
        }
    }
    private func scan(_ query: AccessLogQuery, snapshot: ReadSnapshot, responseLimit: Int) throws -> AccessLogPage {
        // firstAt and the immutable segment identity form a stable traversal order even while
        // new records are appended. A cursor carries one position, never a directory-sized list.
        let segments = snapshot.segments.sorted {
            if $0.firstAt != $1.firstAt { return $0.firstAt > $1.firstAt }
            if $0.writerID == $1.writerID, $0.firstSequence != $1.firstSequence { return $0.firstSequence > $1.firstSequence }
            return Self.baseName($0.name) > Self.baseName($1.name)
        }
        guard !segments.isEmpty else {
            if query.cursor != nil { throw AccessLogError.historyExpired }
            return .init(records: [], nextCursor: nil, generation: snapshot.generation, incomplete: false, scannedBytes: 0)
        }
        var cursor: Cursor
        if let encoded = query.cursor {
            guard encoded.utf8.count <= 4096, let data = Data(base64Encoded: encoded),
                  let decoded = try? Self.decoder().decode(Cursor.self, from: data), decoded.version == 1,
                  decoded.profileID == query.profileID, Self.segmentName(decoded.segment + ".jsonl"),
                  decoded.from == query.from, decoded.through == query.through, decoded.outcome == query.outcome else {
                throw AccessLogError.invalidCursor
            }
            guard decoded.generation == snapshot.generation else { throw AccessLogError.historyExpired }
            guard decoded.writerID == writerID else { throw AccessLogError.historyExpired }
            cursor = decoded
            guard let current = segments.first(where: { Self.baseName($0.name) == cursor.segment }) else {
                throw AccessLogError.historyExpired
            }
            if cursor.offset < 0 || cursor.offset > current.bytes {
                throw AccessLogError.invalidCursor
            }
        } else {
            cursor = Cursor(profileID: query.profileID, generation: snapshot.generation,
                segment: Self.baseName(segments[0].name), offset: segments[0].bytes,
                upperSequence: snapshot.upperSequence, writerID: writerID,
                from: query.from, through: query.through, outcome: query.outcome)
        }
        var index = segments.firstIndex { Self.baseName($0.name) == cursor.segment }!
        var records: [AccessLogRecord] = []
        var scanned = 0
        var responseBytes = 0
        let limit = min(500, max(1, query.limit))
        // Reads overlap by at most one partial line, and every read is charged to the scan budget.
        while index < segments.count, records.count < limit, scanned < policy.scanByteLimit {
            if cursor.offset == 0 {
                index += 1
                if index < segments.count {
                    cursor.segment = Self.baseName(segments[index].name); cursor.offset = segments[index].bytes
                }
                continue
            }
            let available = policy.scanByteLimit - scanned
            let amount = min(cursor.offset, min(max(policy.maxRecordBytes + 1, 4096), available))
            guard amount > 0 else { break }
            let start = cursor.offset - amount
            let data: Data
            do {
                data = try fs.read(profileID: query.profileID, name: segments[index].name, offset: UInt64(start), limit: amount)
            } catch {
                // Rotation changes only the suffix. The stable cursor identity still points at
                // the same immutable bytes; a cleanup/clear is detected by the generation check.
                guard segments[index].name.hasSuffix(".open.jsonl") else { throw error }
                data = try fs.read(profileID: query.profileID, name: Self.baseName(segments[index].name) + ".jsonl",
                                   offset: UInt64(start), limit: amount)
            }
            scanned += data.count
            guard data.count == amount else { throw AccessLogError.historyExpired }
            let bytes = [UInt8](data)
            var end = bytes.count
            if end > 0 && bytes[end - 1] == 10 { end -= 1 }
            var consumed = false
            while end > 0 {
                var begin = end
                while begin > 0 && bytes[begin - 1] != 10 { begin -= 1 }
                // A partial first line remains at the cursor for the next larger-budget request.
                if begin == 0 && start > 0 { break }
                let line = Data(bytes[begin..<end])
                let oldOffset = cursor.offset
                cursor.offset = start + begin
                consumed = true
                if let record = try? Self.decoder().decode(AccessLogRecord.self, from: line) {
                    guard record.schemaVersion == 1, record.profileID == query.profileID else { throw AccessLogError.historyExpired }
                    let matches = (query.from.map { record.receivedAt >= $0 } ?? true)
                        && (query.through.map { record.receivedAt <= $0 } ?? true)
                        && (record.kind != .access || query.outcome.map { record.outcome == $0 } ?? true)
                        && (record.writerID != cursor.writerID || record.sequence <= cursor.upperSequence)
                    if matches {
                        let size = line.count + 1
                        if responseBytes + size > responseLimit {
                            cursor.offset = oldOffset
                            if records.isEmpty { throw AccessLogError.storageUnavailable("record exceeds requested response budget") }
                            return try page(records, cursor: cursor, segments: segments, index: index, scanned: scanned, incomplete: false)
                        }
                        records.append(record); responseBytes += size
                    }
                } else if (try? Self.decoder().decode(Header.self, from: line)) == nil {
                    throw AccessLogError.historyExpired
                }
                if records.count >= limit { break }
                if begin == 0 { end = 0 } else { end = begin - 1 }
            }
            if !consumed { break }
        }
        return try page(records, cursor: cursor, segments: segments, index: index, scanned: scanned,
                        incomplete: index < segments.count && scanned >= policy.scanByteLimit)
    }
    private func page(_ records: [AccessLogRecord], cursor input: Cursor, segments: [Segment], index inputIndex: Int,
                      scanned: Int, incomplete: Bool) throws -> AccessLogPage {
        var cursor = input
        var index = inputIndex
        while index < segments.count && cursor.offset == 0 {
            index += 1
            if index < segments.count {
                cursor.segment = Self.baseName(segments[index].name); cursor.offset = segments[index].bytes
            }
        }
        let next = index < segments.count ? try Self.encoder().encode(cursor).base64EncodedString() : nil
        return .init(records: records, nextCursor: next, generation: cursor.generation, incomplete: incomplete, scannedBytes: scanned)
    }

    private func addError(_ id: String, _ message: String) {
        var state = profiles[id] ?? ProfileState()
        let bounded = String(message.prefix(512))
        if !state.errors.contains(bounded) { state.errors.append(bounded) }
        if state.errors.count > 16 { state.errors.removeFirst(state.errors.count - 16) }
        profiles[id] = state
    }
    private func recoveryDiagnostic(_ id: String, reason: String, kind: AccessLogRecordKind = .gap) {
        var record = AccessLogRecord(profileID: id, operation: "storage_recovery", outcome: .unknown,
                                     receivedAt: clock(), source: .storage, evidence: reason,
                                     attributionStatus: .incomplete)
        record.kind = kind
        if kind == .gap { record.gap = .init(reason: reason) }
        append(record)
    }
    private func bounded(_ input: AccessLogRecord) -> AccessLogRecord {
        var record = input
        record.truncatedFields = [:]
        func trim(_ value: String?, _ field: String, limit: Int? = nil) -> String? {
            guard let value else { return nil }
            let length = value.utf8.count
            let bound = max(16, min(policy.maxTextBytes, limit ?? policy.maxTextBytes))
            guard length > bound else { return value }
            record.truncatedFields[field] = length
            return Self.utf8Prefix(value, bytes: bound)
        }
        // Bound every caller-controlled string, including metadata identifiers.
        record.operation = trim(record.operation, "operation", limit: 1024)!
        record.target = trim(record.target, "target")
        record.rawTarget = trim(record.rawTarget, "raw_target")
        record.evidence = trim(record.evidence, "evidence")
        record.processName = trim(record.processName, "process_name", limit: 1024)
        record.executablePath = trim(record.executablePath, "executable_path", limit: 4096)
        record.runUUID = trim(record.runUUID, "run_uuid", limit: 256)
        record.instanceOrigin = trim(record.instanceOrigin, "instance_origin", limit: 256)
        record.bootID = trim(record.bootID, "boot_id", limit: 256)
        record.sourceEventID = trim(record.sourceEventID, "source_event_id", limit: 256)
        if var endpoint = record.endpointFields {
            endpoint.host = trim(endpoint.host, "endpoint_fields.host", limit: 1024)
            endpoint.transport = trim(endpoint.transport, "endpoint_fields.transport", limit: 128)
            endpoint.socketPath = trim(endpoint.socketPath, "endpoint_fields.socket_path", limit: 4096)
            record.endpointFields = endpoint
        }
        if var gap = record.gap { gap.reason = trim(gap.reason, "gap.reason", limit: 1024)!; record.gap = gap }
        // JSON escaping can multiply control-character size. Reduce diagnostics until the
        // complete encoded record fits; each reduction keeps the original length marker.
        for _ in 0..<12 {
            guard let data = try? Self.encodedLine(record), data.count > policy.maxRecordBytes else { break }
            for field in ["target", "raw_target", "evidence"] {
                let original = field == "target" ? record.target : field == "raw_target" ? record.rawTarget : record.evidence
                guard let original, original.utf8.count > 16 else { continue }
                record.truncatedFields[field] = record.truncatedFields[field] ?? original.utf8.count
                let shorter = Self.utf8Prefix(original, bytes: max(16, original.utf8.count / 2))
                if field == "target" { record.target = shorter }
                else if field == "raw_target" { record.rawTarget = shorter }
                else { record.evidence = shorter }
            }
        }
        return record
    }
    static func validComponent(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value != "." && value != ".."
            && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }
    }
    private static func safeID(_ value: String) -> String {
        let bytes = value.utf8.filter { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }
        return String(decoding: bytes.prefix(64), as: UTF8.self)
    }
    private static func segmentName(_ name: String) -> Bool {
        name.hasPrefix("segment-") && name.utf8.count <= 200
            && (name.hasSuffix(".jsonl") || name.hasSuffix(".open.jsonl") || name.hasSuffix(".quarantine.jsonl"))
            && name.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 || $0 == 46 }
    }
    private static func metaName(_ name: String) -> Bool { name.hasPrefix("segment-") && name.hasSuffix(".meta.json") }
    private static func baseName(_ name: String) -> String {
        for suffix in [".quarantine.jsonl", ".open.jsonl", ".jsonl", ".meta.json"] where name.hasSuffix(suffix) {
            return String(name.dropLast(suffix.count))
        }
        return name
    }
    private static func utf8Prefix(_ value: String, bytes: Int) -> String {
        var raw = Array(value.utf8.prefix(bytes))
        while String(bytes: raw, encoding: .utf8) == nil && !raw.isEmpty { raw.removeLast() }
        return String(decoding: raw, as: UTF8.self)
    }
    private static func adding(_ a: Int, _ b: Int) -> Int {
        let (value, overflow) = a.addingReportingOverflow(b)
        return overflow ? Int.max : value
    }
    private static func reservationBytes(for encodedBytes: Int) -> Int {
        // Both the JSON Data and the record's String allocations remain live until the writer
        // finishes. Allow for array growth/batch movement and the value/dictionary allocation,
        // rather than counting only the text that will eventually be written to disk.
        2 * encodedBytes + max(2048, MemoryLayout<Pending>.stride * 3 + 256)
    }
    private static func encoder() -> JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = AccessLogTimestamp.encodingStrategy; e.outputFormatting = [.sortedKeys]; return e }
    private static func decoder() -> JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = AccessLogTimestamp.decodingStrategy; return d }
    private static func encodedLine<T: Encodable>(_ value: T) throws -> Data { var data = try encoder().encode(value); data.append(10); return data }
    private static func later(_ a: Date?, _ b: Date?) -> Date? { [a, b].compactMap { $0 }.max() }
}
