#if os(macOS)
import Darwin
import Foundation
import GuardCore
import os

/// Reads the stable collector daemon's root-only socket. Parsing and admission happen on its
/// reader queue; state delivery has one outstanding wake-up and bounded batches on the caller's
/// queue. No raw machine-wide stream is stored, and this class never changes source permissions.
final class Collector {
    private let lock = NSLock()
    private let readerQueue = DispatchQueue(label: "com.lsclpangpang.agentguard.collector.client")
    private var monitor = CollectorHealthMonitor(silenceTimeout: 120)
    private var backoff = RestartBackoff(base: 5, maximum: 300)
    private var source: DispatchSourceRead?
    private var fd: Int32 = -1
    private var framing = BoundedCollectorLineBuffer()
    private var wanted = false
    private var reconnectScheduled = false
    private var inputQueue: BoundedCollectorInputQueue?
    private var deliveryQueue: DispatchQueue?
    private var onBatch: (([CollectorInput]) -> Void)?
    private var deliveryScheduled = false
    private var generation: String?
    private var lastSourceSequence: UInt64?
    private let receiverID = UUID().uuidString
    private var receivedSequence: UInt64 = 0
    private let log = Logger(subsystem: "com.lsclpangpang.agentguard", category: "collector")

    /// Configure before start. The same budget must also be passed to the access-log writer.
    /// A reservation remains held until this callback returns, including its synchronous writer
    /// handoff; the writer reserves its own encoded representation before accepting the record.
    func configureDelivery(on queue: DispatchQueue, budget: EventQueueBudget,
                           onBatch: @escaping ([CollectorInput]) -> Void) {
        lock.lock()
        precondition(inputQueue == nil, "Collector delivery is configured once")
        inputQueue = BoundedCollectorInputQueue(budget: budget)
        deliveryQueue = queue
        self.onBatch = onBatch
        lock.unlock()
    }

    func health() -> CollectorHealth {
        lock.lock()
        var health = monitor.health(at: Date())
        let queue = inputQueue
        lock.unlock()
        if let status = queue?.status {
            health.coverage.queuedCount = status.queuedCount
            health.coverage.queuedBytes = status.queuedBytes
            health.coverage.inputDroppedCount = max(health.coverage.inputDroppedCount, status.droppedCount)
            health.coverage.attributionIncomplete = health.coverage.attributionIncomplete || status.attributionIncomplete
            if status.attributionIncomplete { health.problems.insert(.attributionIncomplete) }
        }
        return health
    }

    func coverageStatus() -> CollectorCoverageStatus { health().coverage }

    /// Called on the state delivery queue immediately before the access-log clear barrier.
    /// Capture once: new input arriving during the flush stays queued for the new generation.
    func flushPendingForAccessLogClear() {
        lock.lock()
        let destination = deliveryQueue
        let currentInputQueue = inputQueue
        let handler = onBatch
        lock.unlock()
        guard let destination, let currentInputQueue else { return }
        dispatchPrecondition(condition: .onQueue(destination))
        let checkpoint = currentInputQueue.checkpoint
        while true {
            let batch = currentInputQueue.takeBatch(maxCount: 256, before: checkpoint)
            guard !batch.inputs.isEmpty else { batch.release(); break }
            for input in batch.inputs { if case let .gap(gap) = input { record(.inputGap(gap)) } }
            handler?(batch.inputs)
            batch.release()
        }
    }

    func acknowledge() {
        lock.lock(); defer { lock.unlock() }
        monitor.acknowledgeAll()
    }

    /// The caller writes the existing file-events flag. A request is not actual subscription
    /// evidence: old installed daemons leave fileEventsSubscribed unknown until upgraded manually.
    func start(fileEvents: Bool) {
        lock.lock()
        let alreadyWanted = wanted
        wanted = true
        let configured = inputQueue != nil
        lock.unlock()
        precondition(configured, "Configure bounded collector delivery before start")
        guard !alreadyWanted else { return }
        readerQueue.async { [weak self] in self?.connect() }
    }

    private func record(_ signal: CollectorSignal) {
        lock.lock(); defer { lock.unlock() }
        monitor.record(signal, at: Date())
    }

    private func connect() {
        dispatchPrecondition(condition: .onQueue(readerQueue))
        reconnectScheduled = false
        guard fd < 0 else { return }
        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            log.error("socket() 失败 errno=\(errno)")
            scheduleReconnect()
            return
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            AgentGuardConfig.collectorSocketPath.utf8.prefix(raw.count - 1).enumerated().forEach { raw[$0.offset] = $0.element }
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            log.error("连接采集器失败 errno=\(errno)")
            close(socketFD)
            record(.exited)
            scheduleReconnect()
            return
        }
        fd = socketFD
        record(.started)
        log.notice("已连接采集器")
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: readerQueue)
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { close(socketFD) }
        self.source = source
        source.resume()
    }

    private func drain() {
        dispatchPrecondition(condition: .onQueue(readerQueue))
        guard fd >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        let count = recv(fd, &buffer, buffer.count, 0)
        if count < 0, errno == EINTR { return }
        guard count > 0 else { disconnect(); return }
        framing.consume(Data(buffer.prefix(count)), onLine: { [weak self] bytes in
            guard !bytes.isEmpty else { return }
            self?.handle(String(decoding: bytes, as: UTF8.self), encodedBytes: bytes.count)
        }, onOversizedLine: { [weak self] in
            self?.noteGap(CollectorInputGap(reason: .oversizedLine, kind: .unknown, at: Date()))
        })
    }

    private func handle(_ line: String, encodedBytes: Int) {
        let receivedAt = Date()
        receivedSequence &+= 1
        let sourceEventID = "collector:\(receiverID):\(receivedSequence)"
        guard let event = CollectorWire.decode(line) else {
            noteGap(CollectorInputGap(reason: .invalidWire, kind: .unknown, at: receivedAt))
            record(.unparseableOutput)
            return
        }
        switch event {
        case let .eslogger(payload):
            guard var parsed = try? ESLoggerParser.parse(payload) else {
                noteGap(CollectorInputGap(reason: .unparseableEvent, kind: .unknown, at: receivedAt))
                record(.unparseableOutput)
                return
            }
            parsed.receivedAt = receivedAt
            parsed.sourceEventID = sourceEventID
            if let last = lastSourceSequence, parsed.globalSequence > last,
               parsed.globalSequence - last > 1 {
                var gap = CollectorInputGap(reason: .sourceSequenceGap, kind: .unknown,
                                            droppedCount: parsed.globalSequence - last - 1,
                                            sourceSequence: last + 1, at: receivedAt)
                gap.lastSourceSequence = parsed.globalSequence - 1
                noteGap(gap)
            }
            if lastSourceSequence == nil || parsed.globalSequence > lastSourceSequence! { lastSourceSequence = parsed.globalSequence }
            record(.event(sequence: parsed.globalSequence))
            lock.lock(); backoff.recordProgress(); lock.unlock()
            enqueue(.es(parsed), encodedBytes: encodedBytes, at: receivedAt)
        case let .sandbox(payload):
            guard let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
                  let message = object["eventMessage"] as? String else {
                noteGap(CollectorInputGap(reason: .unparseableEvent, kind: .denial, at: receivedAt))
                return
            }
            // log stream can produce other diagnostics despite its predicate; only exact parsed
            // denials enter managed-process attribution and access logging.
            guard var denial = SandboxLogParser.parse(message) else { return }
            denial.receivedAt = receivedAt
            denial.sourceAt = SourceEventTimestamp.parseUnifiedLog(object["timestamp"])
            denial.sourceEventID = sourceEventID
            enqueue(.denial(denial), encodedBytes: encodedBytes, at: receivedAt)
        case let .error(payload):
            if payload.contains("Not permitted") || payload.contains("TCC") || payload.contains("Full Disk Access") {
                record(.authorizationDenied)
            }
        case let .status(status):
            if status.protocolVersion == CollectorRuntimeStatus.currentProtocolVersion, !status.generation.isEmpty {
                if let generation, generation != status.generation {
                    lastSourceSequence = nil
                    noteGap(CollectorInputGap(reason: .sourceRestarted, kind: .unknown, droppedCount: 0,
                                              possibleUnknownLoss: true, at: receivedAt))
                }
                generation = status.generation
            }
            record(.runtimeStatus(status))
        case let .gap(gap): noteGap(gap)
        }
    }

    private func enqueue(_ input: CollectorInput, encodedBytes: Int, at: Date) {
        lock.lock(); let queue = inputQueue; lock.unlock()
        _ = queue?.enqueue(input, encodedBytes: encodedBytes, at: at)
        scheduleDelivery()
    }

    private func noteGap(_ gap: CollectorInputGap) {
        lock.lock(); let queue = inputQueue; lock.unlock()
        queue?.recordGap(gap)
        scheduleDelivery()
    }

    private func scheduleDelivery() {
        lock.lock()
        guard !deliveryScheduled, let queue = deliveryQueue, inputQueue?.hasPending == true else { lock.unlock(); return }
        deliveryScheduled = true
        lock.unlock()
        queue.async { [weak self] in self?.deliverBatch() }
    }

    private func deliverBatch() {
        lock.lock()
        let queue = inputQueue
        let handler = onBatch
        lock.unlock()
        if let batch = queue?.takeBatch(maxCount: 256) {
            for input in batch.inputs { if case let .gap(gap) = input { record(.inputGap(gap)) } }
            handler?(batch.inputs)
            batch.release()
        }
        lock.lock(); deliveryScheduled = false; lock.unlock()
        // Reschedule at the end of the caller's queue so pending control requests can run.
        scheduleDelivery()
    }

    private func disconnect() {
        dispatchPrecondition(condition: .onQueue(readerQueue))
        source?.cancel()
        source = nil
        fd = -1
        _ = framing.reset()
        lastSourceSequence = nil
        noteGap(CollectorInputGap(reason: .disconnected, kind: .unknown, droppedCount: 0,
                                  possibleUnknownLoss: true, at: Date()))
        record(.exited)
        log.notice("与采集器断开；缺失时段与进程归属可能不完整")
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        dispatchPrecondition(condition: .onQueue(readerQueue))
        guard !reconnectScheduled else { return }
        lock.lock()
        let stillWanted = wanted
        let delay = backoff.nextDelay()
        lock.unlock()
        guard stillWanted else { return }
        reconnectScheduled = true
        readerQueue.asyncAfter(deadline: .now() + delay) { [weak self] in self?.connect() }
    }
}
#endif
