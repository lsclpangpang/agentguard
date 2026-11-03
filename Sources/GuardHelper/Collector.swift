#if os(macOS)
import Darwin
import Foundation
import GuardCore
import os

/// Consumes collector events from the privileged collector daemon.
///
/// The daemon owns `eslogger` and `log stream`; this class only reads newline-delimited
/// `CollectorWire` envelopes from its socket and keeps the same health bookkeeping as before. The
/// daemon is restarted by launchd, so a missing socket means "not started" rather than "gone".
final class Collector {
    var onLine: ((ESLine) -> Void)?
    var onDenial: ((SandboxDenial) -> Void)?

    private let lock = NSLock()
    private var monitor = CollectorHealthMonitor(silenceTimeout: 120)
    private var backoff = RestartBackoff(base: 5, maximum: 300)
    private var source: DispatchSourceRead?
    private var fd: Int32 = -1
    private var pending = Data()
    private var wanted = false
    private let log = Logger(subsystem: "com.lsclpangpang.agentguard", category: "collector")

    func health() -> CollectorHealth {
        lock.lock(); defer { lock.unlock() }
        return monitor.health(at: Date())
    }

    func acknowledge() {
        lock.lock(); defer { lock.unlock() }
        monitor.acknowledgeAll()
    }

    /// `fileEvents` is accepted for call-site compatibility; the daemon always collects the whole
    /// event set so a profile change never has to restart it.
    func start(fileEvents: Bool) {
        lock.lock()
        let alreadyWanted = wanted
        wanted = true
        lock.unlock()
        guard !alreadyWanted || fd < 0 else { return }
        connect()
    }

    private func record(_ signal: CollectorSignal) {
        lock.lock(); defer { lock.unlock() }
        monitor.record(signal, at: Date())
    }

    private func nextDelay() -> Double {
        lock.lock(); defer { lock.unlock() }
        return backoff.nextDelay()
    }

    private func recordProgress() {
        lock.lock(); defer { lock.unlock() }
        backoff.recordProgress()
    }

    private func connect() {
        lock.lock()
        guard wanted, fd < 0 else { lock.unlock(); return }
        lock.unlock()

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            log.error("socket() 失败 errno=\(errno)")
            scheduleReconnect()
            return
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let path = AgentGuardConfig.collectorSocketPath
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            path.utf8.prefix(raw.count - 1).enumerated().forEach { raw[$0.offset] = $0.element }
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            log.error("connect(\(AgentGuardConfig.collectorSocketPath, privacy: .public)) 失败 errno=\(errno)")
            close(socketFD)
            record(.exited)
            scheduleReconnect()
            return
        }
        log.notice("已连接采集器 \(AgentGuardConfig.collectorSocketPath, privacy: .public)")

        lock.lock(); fd = socketFD; lock.unlock()
        record(.started)

        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: DispatchQueue(label: "com.lsclpangpang.agentguard.collector.client"))
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { close(socketFD) }
        source.resume()
        lock.lock(); self.source = source; lock.unlock()
    }

    private func drain() {
        lock.lock()
        let socketFD = fd
        lock.unlock()
        guard socketFD >= 0 else { return }

        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        let read = recv(socketFD, &buffer, buffer.count, 0)
        guard read > 0 else {
            log.error("recv 返回 \(read) errno=\(errno)，断开重连")
            disconnect()
            return
        }
        pending.append(contentsOf: buffer[0..<read])
        while let newline = pending.firstIndex(of: 0x0A) {
            let line = String(decoding: pending[pending.startIndex..<newline], as: UTF8.self)
            pending.removeSubrange(pending.startIndex...newline)
            guard !line.isEmpty else { continue }
            handle(line)
        }
    }

    private func handle(_ line: String) {
        guard let event = CollectorWire.decode(line) else { return }
        switch event {
        case let .eslogger(payload):
            guard let parsed = try? ESLoggerParser.parse(payload) else {
                record(.unparseableOutput)
                return
            }
            record(.event(sequence: parsed.globalSequence))
            recordProgress()
            onLine?(parsed)
        case let .sandbox(payload):
            guard let data = payload.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let message = object["eventMessage"] as? String,
                  let denial = SandboxLogParser.parse(message)
            else { return }
            onDenial?(denial)
        case let .error(payload):
            if payload.contains("Not permitted") || payload.contains("TCC") || payload.contains("Full Disk Access") {
                record(.authorizationDenied)
            }
        }
    }

    private func disconnect() {
        lock.lock()
        let source = self.source
        self.source = nil
        fd = -1
        pending.removeAll()
        lock.unlock()
        source?.cancel()
        log.notice("与采集器断开")
        record(.exited)
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        lock.lock()
        let stillWanted = wanted
        lock.unlock()
        guard stillWanted else { return }
        let delay = nextDelay()
        DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.connect()
        }
    }
}
#endif
