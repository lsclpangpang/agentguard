#if os(macOS)
import Darwin
import Foundation
import GuardCore

/// Keep this installed collector's identity stable: its existing Full Disk Access grant belongs
/// to this binary. Updating the app never silently replaces or restarts the installed collector.
signal(SIGPIPE, SIG_IGN)

let socketPath = AgentGuardConfig.collectorSocketPath
let esloggerPath = "/usr/bin/eslogger"
let logPath = "/usr/bin/log"
let sandboxPredicate = "process == \"kernel\" AND (eventMessage BEGINSWITH \"Sandbox: \" OR (eventMessage CONTAINS \"duplicate report\" AND eventMessage CONTAINS \"Sandbox: \"))"

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(64)
}

// MARK: - Clients

/// Each client has a bounded whole-frame FIFO (2 MiB/128 frames, at most four clients).
/// Writable notifications resume partial nonblocking writes; producers only enqueue and never
/// schedule an unbounded task per event. Overflow disconnects that client, which the Helper reports.
/// This bounds transport retention; it does not reduce the system sources' JSON encoding load.
private final class Subscribers {
    private let transport = CollectorBroadcaster()
    private let maximumWireBytes = CollectorTransportLimits.maximumEncodedLineBytes

    func add(_ fd: Int32) {
        transport.add(takingSocket: fd)
    }

    func publishStatus(_ status: CollectorRuntimeStatus) {
        transport.publishInitialFrameAndBroadcast(Data((CollectorWire.encode(.status(status)) + "\n").utf8))
    }

    func broadcast(_ event: CollectorEvent) {
        var encoded = CollectorWire.encode(event)
        if encoded.utf8.count > maximumWireBytes {
            let kind: CollectorInputKind
            switch event {
            case .sandbox: kind = .denial
            case let .eslogger(raw): kind = (try? ESLoggerParser.parse(raw)).map { CollectorInput.es($0).kind } ?? .unknown
            default: kind = .unknown
            }
            encoded = CollectorWire.encode(.gap(CollectorInputGap(reason: .oversizedLine, kind: kind, at: Date())))
        }
        let data = Data((encoded + "\n").utf8)
        transport.broadcast(data)
    }
}

private final class PipeLines {
    private let lock = NSLock()
    private var buffer: BoundedCollectorLineBuffer
    init(limit: Int = 1024 * 1024) { buffer = BoundedCollectorLineBuffer(maxLineBytes: limit) }
    func consume(_ data: Data, onLine: (String) -> Void, onOversized: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        buffer.consume(data, onLine: { bytes in
            if !bytes.isEmpty { onLine(String(decoding: bytes, as: UTF8.self)) }
        }, onOversizedLine: onOversized)
    }
}

// MARK: - Children

private final class Child {
    let fileEvents: Bool
    private let name: String
    private let path: String
    private let arguments: [String]
    private let onLine: (String, String) -> Void
    private let onStderr: (String) -> Void
    private let onGap: (CollectorInputGap) -> Void
    private let onState: (Bool, String) -> Void
    private let lifecycle = DispatchQueue(label: "com.lsclpangpang.agentguard.collector.child")
    private var process: Process?
    private var generation = ""
    private var backoff = RestartBackoff(base: 30, maximum: 600)
    private var stopping = false

    init(name: String, path: String, arguments: [String], fileEvents: Bool = false,
         onLine: @escaping (String, String) -> Void, onStderr: @escaping (String) -> Void,
         onGap: @escaping (CollectorInputGap) -> Void, onState: @escaping (Bool, String) -> Void) {
        self.fileEvents = fileEvents
        self.name = name
        self.path = path
        self.arguments = arguments
        self.onLine = onLine
        self.onStderr = onStderr
        self.onGap = onGap
        self.onState = onState
    }

    func start() { lifecycle.async { [weak self] in self?.startNow() } }

    private func startNow() {
        guard !stopping else { return }
        generation = UUID().uuidString
        let sourceGeneration = generation
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let output = Pipe(), errors = Pipe()
        let outputLines = PipeLines(), errorLines = PipeLines(limit: 64 * 1024)
        process.standardOutput = output
        process.standardError = errors
        let readOutput: (FileHandle) -> Void = { [weak self] handle in
            // Bound the temporary read as well as the retained incomplete-line buffer.
            guard let data = try? handle.read(upToCount: 64 * 1024), !data.isEmpty else { return }
            outputLines.consume(data, onLine: { self?.onLine($0, sourceGeneration) }, onOversized: {
                self?.onGap(CollectorInputGap(reason: .oversizedLine, kind: .unknown, at: Date()))
            })
        }
        let readErrors: (FileHandle) -> Void = { [weak self] handle in
            guard let data = try? handle.read(upToCount: 64 * 1024), !data.isEmpty else { return }
            errorLines.consume(data, onLine: { self?.onStderr($0) }, onOversized: {
                self?.onStderr("collector diagnostic exceeded line limit")
            })
        }
        process.terminationHandler = { [weak self] finished in
            self?.lifecycle.async { [weak self] in
                output.fileHandleForReading.readabilityHandler = nil
                errors.fileHandleForReading.readabilityHandler = nil
                guard let self, !self.stopping else { return }
                self.onState(false, sourceGeneration)
                self.onGap(CollectorInputGap(reason: .sourceRestarted, kind: .unknown, droppedCount: 0,
                                             possibleUnknownLoss: true, at: Date()))
                let delay = self.backoff.nextDelay()
                FileHandle.standardError.write(Data("\(self.name) exited (\(finished.terminationStatus))，\(Int(delay)) 秒后重试\n".utf8))
                self.lifecycle.asyncAfter(deadline: .now() + delay) { [weak self] in self?.startNow() }
            }
        }
        do {
            try process.run()
            self.process = process
            onState(true, sourceGeneration)
            // Publish the generation before any of its events. A very fast child can already
            // have filled its pipe, but cannot confirm or forward an unannounced subscription.
            output.fileHandleForReading.readabilityHandler = readOutput
            errors.fileHandleForReading.readabilityHandler = readErrors
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            errors.fileHandleForReading.readabilityHandler = nil
            onState(false, generation)
            let delay = backoff.nextDelay()
            FileHandle.standardError.write(Data("无法启动 \(path): \(error)\n".utf8))
            lifecycle.asyncAfter(deadline: .now() + delay) { [weak self] in self?.startNow() }
        }
    }

    func stop() {
        lifecycle.sync {
            stopping = true
            process?.terminate()
            onState(false, generation)
        }
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
chmod(socketPath, 0o600)
DispatchQueue.global().async {
    while true {
        let client = accept(serverFD, nil, nil)
        if client < 0 { if errno == EINTR { continue }; break }
        var on: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        subscribers.add(client)
    }
}

// MARK: - Source subscriptions and actual coverage

private let running = DispatchGroup()
running.enter()
private let statusLock = NSLock()
private var subscriptionState = CollectorSubscriptionState()
private func updateStatus(_ update: (inout CollectorSubscriptionState) -> Void) {
    statusLock.lock()
    update(&subscriptionState)
    let snapshot = subscriptionState.status
    subscribers.publishStatus(snapshot)
    statusLock.unlock()
}
private func publishStatus() {
    statusLock.lock(); defer { statusLock.unlock() }
    let snapshot = subscriptionState.status
    subscribers.publishStatus(snapshot)
}

/// Lifecycle events remain subscribed; the existing root-owned flag now represents learning OR
/// access-log demand. It changes neither a managed profile's protection mode nor its permissions.
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
        if let current = eslogger {
            current.stop()
            subscribers.broadcast(.gap(CollectorInputGap(reason: .sourceRestarted, kind: .unknown, droppedCount: 0,
                                                         possibleUnknownLoss: true, at: Date())))
        }
        let child = Child(name: "eslogger", path: esloggerPath, arguments: esloggerArguments(fileEvents: fileEvents), fileEvents: fileEvents,
                          onLine: { line, generation in
                              statusLock.lock()
                              defer { statusLock.unlock() }
                              // Retired pipe callbacks can arrive after a subscription change.
                              // The transition has its own explicit gap; never mix its old
                              // sequence with the current generation's event stream.
                              guard subscriptionState.status.generation == generation,
                                    subscriptionState.status.esloggerRunning else { return }
                              if subscriptionState.needsConfirmation(generation: generation),
                                 (try? ESLoggerParser.parse(line)) != nil {
                                  subscriptionState.confirmEvent(generation: generation)
                                  subscribers.publishStatus(subscriptionState.status)
                              }
                              subscribers.broadcast(.eslogger(line))
                          },
                          onStderr: { subscribers.broadcast(.error($0)) },
                          onGap: { subscribers.broadcast(.gap($0)) },
                          onState: { isRunning, generation in updateStatus {
                              if isRunning { $0.esloggerStarted(generation: generation, fileEventsRequested: fileEvents) }
                              else { $0.esloggerStopped(generation: generation) }
                          } })
        eslogger = child
        child.start()
    }
}
private func fileEventsEnabled() -> Bool { FileManager.default.fileExists(atPath: AgentGuardConfig.collectorFileEventsFlagPath) }
private let sandboxLog = Child(name: "log stream", path: logPath,
                               arguments: ["stream", "--style", "ndjson", "--predicate", sandboxPredicate],
                               onLine: { line, _ in subscribers.broadcast(.sandbox(line)) }, onStderr: { _ in },
                               onGap: { subscribers.broadcast(.gap($0)) },
                               onState: { isRunning, _ in updateStatus { $0.sandboxRunning(isRunning) } })
private var signalSources: [DispatchSourceSignal] = []
for signalNumber in [SIGTERM, SIGINT] {
    signal(signalNumber, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
    source.setEventHandler {
        control.sync { eslogger?.stop() }
        sandboxLog.stop()
        unlink(socketPath)
        running.leave()
        exit(0)
    }
    source.resume()
    signalSources.append(source)
}
refreshEslogger(fileEvents: fileEventsEnabled())
let flagWatch = DispatchSource.makeTimerSource(queue: .global())
flagWatch.schedule(deadline: .now() + 5, repeating: 5)
flagWatch.setEventHandler { refreshEslogger(fileEvents: fileEventsEnabled()) }
flagWatch.resume()
let heartbeat = DispatchSource.makeTimerSource(queue: .global())
heartbeat.schedule(deadline: .now() + 15, repeating: 15)
heartbeat.setEventHandler { publishStatus() }
heartbeat.resume()
sandboxLog.start()
running.wait()
#else
import Foundation
FileHandle.standardError.write(Data("agentguard-collector 只能在 macOS 上运行\n".utf8))
exit(1)
#endif
