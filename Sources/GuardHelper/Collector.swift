#if os(macOS)
import Foundation
import GuardCore

/// Runs eslogger (process lifecycle, optionally file events) and `log stream` (sandbox denials).
/// Both are best-effort observers; their failures surface through `health()`.
final class Collector {
    var onLine: ((ESLine) -> Void)?
    var onDenial: ((SandboxDenial) -> Void)?

    private let lock = NSLock()
    private var monitor = CollectorHealthMonitor(silenceTimeout: 120)
    private var eslogger: Process?
    private var logStream: Process?
    private var fileEvents: Bool?

    func health() -> CollectorHealth {
        lock.lock(); defer { lock.unlock() }
        return monitor.health(at: Date())
    }

    func acknowledge() {
        lock.lock(); defer { lock.unlock() }
        monitor.acknowledgeAll()
    }

    private func record(_ signal: CollectorSignal) {
        lock.lock(); defer { lock.unlock() }
        monitor.record(signal, at: Date())
    }

    func start(fileEvents: Bool) {
        if self.fileEvents == fileEvents, eslogger?.isRunning == true { return }
        self.fileEvents = fileEvents
        eslogger?.terminationHandler = nil
        eslogger?.terminate()
        var events = ["fork", "exec", "exit"]
        if fileEvents { events += ["open", "create", "rename", "unlink", "close"] }
        eslogger = launch("/usr/bin/eslogger", events + ["--format", "json"], onLine: { [weak self] text in
            guard let self else { return }
            do {
                let line = try ESLoggerParser.parse(text)
                self.record(.event(sequence: line.globalSequence))
                self.onLine?(line)
            } catch {
                self.record(.unparseableOutput)
            }
        }, onError: { [weak self] text in
            if text.contains("Not permitted") || text.contains("TCC") || text.contains("Full Disk Access") {
                self?.record(.authorizationDenied)
            }
        }, restart: { [weak self] in self?.start(fileEvents: fileEvents) })
        if eslogger != nil { record(.started) }

        if logStream?.isRunning != true {
            let predicate = "process == \"kernel\" AND eventMessage BEGINSWITH \"Sandbox: \""
            logStream = launch("/usr/bin/log", ["stream", "--style", "ndjson", "--predicate", predicate], onLine: { [weak self] text in
                guard let data = text.data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let message = object["eventMessage"] as? String,
                      let denial = SandboxLogParser.parse(message)
                else { return }
                self?.onDenial?(denial)
            }, onError: { _ in }, restart: nil)
        }
    }

    private func launch(_ path: String, _ arguments: [String], onLine: @escaping (String) -> Void,
                        onError: @escaping (String) -> Void, restart: (() -> Void)?) -> Process? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let output = Pipe(), errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        let buffer = LineBuffer(onLine: onLine)
        output.fileHandleForReading.readabilityHandler = { handle in buffer.append(handle.availableData) }
        errors.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if !data.isEmpty { onError(String(decoding: data, as: UTF8.self)) }
        }
        process.terminationHandler = { [weak self] _ in
            output.fileHandleForReading.readabilityHandler = nil
            errors.fileHandleForReading.readabilityHandler = nil
            guard let restart else { return }
            self?.record(.exited)
            DispatchQueue.global().asyncAfter(deadline: .now() + 30) { restart() }
        }
        do {
            try process.run()
            return process
        } catch {
            record(.exited)
            return nil
        }
    }
}

private final class LineBuffer {
    private var pending = Data()
    private let lock = NSLock()
    private let onLine: (String) -> Void

    init(onLine: @escaping (String) -> Void) {
        self.onLine = onLine
    }

    func append(_ data: Data) {
        lock.lock()
        pending.append(data)
        var lines: [String] = []
        while let newline = pending.firstIndex(of: 0x0A) {
            lines.append(String(decoding: pending[pending.startIndex..<newline], as: UTF8.self))
            pending.removeSubrange(pending.startIndex...newline)
        }
        lock.unlock()
        for line in lines where !line.isEmpty { onLine(line) }
    }
}
#endif
