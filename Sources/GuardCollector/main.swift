#if os(macOS)
import Darwin
import Foundation
import GuardCore

/// Privileged collector daemon.
///
/// It lives at `/Library/PrivilegedHelperTools/com.lsclpangpang.agentguard.collector`, outside the
/// app bundle, and is the only process that holds Full Disk Access: `eslogger` and `log stream` are
/// its children, so TCC attributes their requests to this stable binary instead of to the
/// frequently re-signed app. It publishes newline-delimited `CollectorWire` envelopes on a
/// root-only UNIX socket; the Helper consumes them.

// 客户端随时可能断开；写一个已经关闭的 socket 会触发 SIGPIPE，默认动作是杀掉进程。
signal(SIGPIPE, SIG_IGN)

let socketPath = AgentGuardConfig.collectorSocketPath
let esloggerPath = "/usr/bin/eslogger"
let logPath = "/usr/bin/log"
let sandboxPredicate = "process == \"kernel\" AND eventMessage BEGINSWITH \"Sandbox: \""

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(64)
}

// MARK: - Clients

private final class Subscribers {
    private let lock = NSLock()
    private var clients: [Int32] = []

    func add(_ fd: Int32) {
        lock.lock(); defer { lock.unlock() }
        clients.append(fd)
    }

    func broadcast(_ line: String) {
        guard let data = (line + "\n").data(using: .utf8) else { return }
        lock.lock()
        let snapshot = clients
        lock.unlock()
        var dead: [Int32] = []
        for fd in snapshot where !Self.writeAll(fd, data) { dead.append(fd) }
        guard !dead.isEmpty else { return }
        lock.lock()
        clients.removeAll { dead.contains($0) }
        lock.unlock()
        for fd in dead { close(fd) }
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard var base = raw.baseAddress else { return true }
            var remaining = raw.count
            while remaining > 0 {
                let written = write(fd, base, remaining)
                if written > 0 {
                    remaining -= written
                    base = base.advanced(by: written)
                } else if written < 0, errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }
}

// MARK: - Children

/// Runs one child process and restarts it with a growing delay while it keeps dying.
private final class Child {
    /// 订阅了哪一类事件；用来判断是否需要为“切到/切回学习模式”重启 eslogger。
    let fileEvents: Bool
    private let name: String
    private let path: String
    private let arguments: [String]
    private let onLine: (String) -> Void
    private let onStderr: (String) -> Void
    private var process: Process?
    private var backoff = RestartBackoff(base: 30, maximum: 600)
    private var stopping = false

    init(name: String, path: String, arguments: [String], fileEvents: Bool = false,
         onLine: @escaping (String) -> Void, onStderr: @escaping (String) -> Void) {
        self.fileEvents = fileEvents
        self.name = name
        self.path = path
        self.arguments = arguments
        self.onLine = onLine
        self.onStderr = onStderr
    }

    func start() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let output = Pipe(), errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        var pending = Data()
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            pending.append(data)
            while let newline = pending.firstIndex(of: 0x0A) {
                let line = String(decoding: pending[pending.startIndex..<newline], as: UTF8.self)
                pending.removeSubrange(pending.startIndex...newline)
                if !line.isEmpty { self?.onLine(line) }
            }
        }
        errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.onStderr(String(decoding: data, as: UTF8.self))
        }
        process.terminationHandler = { [weak self] finished in
            output.fileHandleForReading.readabilityHandler = nil
            errors.fileHandleForReading.readabilityHandler = nil
            guard let self, !self.stopping else { return }
            let delay = self.backoff.nextDelay()
            FileHandle.standardError.write(Data("\(self.name) exited (\(finished.terminationStatus))，\(Int(delay)) 秒后重启\n".utf8))
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, !self.stopping else { return }
                self.start()
            }
        }
        do {
            try process.run()
            self.process = process
        } catch {
            FileHandle.standardError.write(Data("无法启动 \(path): \(error)\n".utf8))
        }
    }

    func stop() {
        stopping = true
        process?.terminate()
    }
}

// MARK: - Socket

private let subscribers = Subscribers()
let umaskValue = umask(0o077)
_ = umask(umaskValue)

unlink(socketPath)
let serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
guard serverFD >= 0 else { fail("socket() 失败: \(String(cString: strerror(errno)))") }

var address = sockaddr_un()
address.sun_family = sa_family_t(AF_UNIX)
address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
withUnsafeMutableBytes(of: &address.sun_path) { raw in
    socketPath.utf8.prefix(raw.count - 1).enumerated().forEach { raw[$0.offset] = $0.element }
}

let bound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
}
guard bound == 0 else { fail("bind(\(socketPath)) 失败: \(String(cString: strerror(errno)))") }
guard listen(serverFD, 8) == 0 else { fail("listen() 失败: \(String(cString: strerror(errno)))") }
// Only root may read the event stream.
chmod(socketPath, 0o600)

DispatchQueue.global().async {
    while true {
        let client = accept(serverFD, nil, nil)
        if client < 0 {
            if errno == EINTR { continue }
            break
        }
        // 双保险：即使某次写失败，也不要让内核发 SIGPIPE。
        var on: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        subscribers.add(client)
    }
}

// MARK: - Children wiring

private let running = DispatchGroup()
running.enter()

/// eslogger 的订阅集合：进程生命周期永远订阅，文件事件只在学习模式下加进来。
private func esloggerArguments(fileEvents: Bool) -> [String] {
    var events = ["fork", "exec", "exit"]
    if fileEvents { events += ["open", "create", "rename", "unlink", "close"] }
    return events + ["--format", "json"]
}

private let control = DispatchQueue(label: "com.lsclpangpang.agentguard.collector.control")
private var eslogger: Child?

private func refreshEslogger(fileEvents: Bool) {
    control.async {
        if let current = eslogger, current.fileEvents == fileEvents { return }
        eslogger?.stop()
        let child = Child(
            name: "eslogger \(fileEvents ? "（含文件事件）" : "")",
            path: esloggerPath,
            arguments: esloggerArguments(fileEvents: fileEvents),
            fileEvents: fileEvents,
            onLine: { subscribers.broadcast(CollectorWire.encode(.eslogger($0))) },
            onStderr: { subscribers.broadcast(CollectorWire.encode(.error($0))) }
        )
        eslogger = child
        child.start()
        FileHandle.standardError.write(Data("eslogger 订阅已切换：fileEvents=\(fileEvents)\n".utf8))
    }
}

private func fileEventsEnabled() -> Bool {
    FileManager.default.fileExists(atPath: AgentGuardConfig.collectorFileEventsFlagPath)
}
private let sandboxLog = Child(
    name: "log stream",
    path: logPath,
    arguments: ["stream", "--style", "ndjson", "--predicate", sandboxPredicate],
    onLine: { subscribers.broadcast(CollectorWire.encode(.sandbox($0))) },
    onStderr: { _ in }
)

for signalNumber in [SIGTERM, SIGINT] {
    signal(signalNumber, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
    source.setEventHandler {
        eslogger?.stop()
        sandboxLog.stop()
        unlink(socketPath)
        running.leave()
        exit(0)
    }
    source.resume()
}

refreshEslogger(fileEvents: fileEventsEnabled())

let flagWatch = DispatchSource.makeTimerSource(queue: .global())
flagWatch.schedule(deadline: .now() + 5, repeating: 5)
flagWatch.setEventHandler { refreshEslogger(fileEvents: fileEventsEnabled()) }
flagWatch.resume()

sandboxLog.start()
running.wait()
#else
import Foundation

FileHandle.standardError.write(Data("agentguard-collector 只能在 macOS 上运行\n".utf8))
exit(1)
#endif
