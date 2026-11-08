#if os(macOS)
import Darwin
import Foundation

/// These are hard upper bounds, even if a caller requests larger testing/configuration limits.
/// The encoded JSON line limit excludes its terminating newline.
public enum CollectorTransportLimits {
    public static let maximumClients = 4
    public static let maximumQueuedBytesPerClient = 2 * 1024 * 1024
    public static let maximumQueuedFramesPerClient = 128
    public static let maximumEncodedLineBytes = 1024 * 1024
    public static let maximumFrameBytes = maximumEncodedLineBytes + 1
}

public struct CollectorSocketSnapshot: Equatable, Sendable {
    public let isClosed: Bool
    public let descriptorClosed: Bool
    public let queuedFrames: Int
    public let retainedBytes: Int
    public let headOffset: Int
    public let pumpCount: UInt64
    public let writeAttempts: UInt64
    public let wouldBlockCount: UInt64
}

/// A single client's bounded, whole-frame FIFO. Producers only enqueue under a short lock.
/// One writable source resumes partial nonblocking writes, without scheduling one task per event.
public final class CollectorSocketWriter: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private let source: DispatchSourceWrite
    private let lifetime: SocketDescriptorLifetime
    private var frames: CollectorFrameQueue
    private var closed = false
    private var sourceSuspended = true
    private var pumpCount: UInt64 = 0
    private var writeAttempts: UInt64 = 0
    private var wouldBlockCount: UInt64 = 0

    // Fairness is independent of socket buffer size. A hot client yields to its queue after
    // bounded work; an EAGAIN yields immediately and retains its exact frame/offset.
    private static let maximumBytesPerPump = 256 * 1024
    private static let maximumWritesPerPump = 64

    /// Takes ownership on both success and failure. Limits may be lowered, never raised.
    public init?(
        takingSocket fd: Int32,
        maximumQueuedBytes: Int = CollectorTransportLimits.maximumQueuedBytesPerClient,
        maximumQueuedFrames: Int = CollectorTransportLimits.maximumQueuedFramesPerClient
    ) {
        guard BoundedCollectorSocket.makeNonBlocking(fd) else {
            Darwin.close(fd)
            return nil
        }
        self.fd = fd
        lifetime = SocketDescriptorLifetime(fd)
        frames = CollectorFrameQueue(
            maximumBytes: min(max(1, maximumQueuedBytes), CollectorTransportLimits.maximumQueuedBytesPerClient),
            maximumFrames: min(max(1, maximumQueuedFrames), CollectorTransportLimits.maximumQueuedFramesPerClient)
        )
        source = DispatchSource.makeWriteSource(
            fileDescriptor: fd,
            queue: DispatchQueue(label: "com.lsclpangpang.agentguard.collector.client")
        )
        source.setEventHandler { [weak self] in self?.pump() }
        // Capture only the lifetime object: keeping self here would prevent deinit/close.
        let descriptorLifetime = lifetime
        source.setCancelHandler { descriptorLifetime.close() }
    }

    public var isClosed: Bool {
        lock.lock(); defer { lock.unlock() }
        return closed
    }

    public var snapshot: CollectorSocketSnapshot {
        lock.lock(); defer { lock.unlock() }
        return CollectorSocketSnapshot(
            isClosed: closed, descriptorClosed: lifetime.isClosed,
            queuedFrames: frames.frameCount, retainedBytes: frames.retainedBytes,
            headOffset: frames.headOffset, pumpCount: pumpCount,
            writeAttempts: writeAttempts, wouldBlockCount: wouldBlockCount
        )
    }

    /// True means admitted to the bounded queue, not acknowledged by the receiving process.
    /// A failed admission closes only this client, making the interrupted stream explicit.
    @discardableResult
    public func enqueue(_ frame: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return false }
        guard frame.count <= CollectorTransportLimits.maximumFrameBytes,
              frames.enqueue(frame) else {
            closeLocked()
            return false
        }
        if !frames.isEmpty, sourceSuspended {
            sourceSuspended = false
            source.resume()
        }
        return true
    }

    public func close() {
        lock.lock(); defer { lock.unlock() }
        closeLocked()
    }

    deinit { close() }

    private func closeLocked() {
        guard !closed else { return }
        closed = true
        frames.removeAll()
        source.cancel()
        if sourceSuspended {
            sourceSuspended = false
            // A suspended source must be resumed so its cancellation handler can run.
            source.resume()
        }
        // Only the cancellation handler closes fd, after any outstanding event handler.
    }

    private func pump() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }
        pumpCount &+= 1
        var bytesWritten = 0
        var calls = 0
        while let head = frames.head,
              bytesWritten < Self.maximumBytesPerPump,
              calls < Self.maximumWritesPerPump {
            let offset = frames.headOffset
            let count = min(head.count - offset, Self.maximumBytesPerPump - bytesWritten)
            let written = head.withUnsafeBytes { raw in
                Darwin.write(fd, raw.baseAddress!.advanced(by: offset), count)
            }
            calls += 1
            writeAttempts &+= 1
            if written > 0 {
                frames.advance(by: written)
                bytesWritten += written
            } else if written < 0, errno == EINTR {
                continue
            } else if written < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                wouldBlockCount &+= 1
                return
            } else {
                closeLocked()
                return
            }
        }
        if frames.isEmpty, !sourceSuspended {
            sourceSuspended = true
            source.suspend()
        }
    }
}

/// fd remains valid until the dispatch source's cancel handler. Closing it earlier permits a
/// queued write handler to write to a reused descriptor; closing it twice has the same risk.
private final class SocketDescriptorLifetime: @unchecked Sendable {
    private let lock = NSLock()
    private let fd: Int32
    private var closed = false

    init(_ fd: Int32) { self.fd = fd }

    var isClosed: Bool {
        lock.lock(); defer { lock.unlock() }
        return closed
    }

    func close() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }
        Darwin.close(fd)
        closed = true
    }
}

/// Serializes admission order across producers, with at most four independent client writers.
/// At the default/hard limits, client queues retain at most 8 MiB of logical frame bytes total.
/// A single bounded initial/status frame is cached for new clients.
public final class CollectorBroadcaster: @unchecked Sendable {
    private let lock = NSLock()
    private var clients: [CollectorSocketWriter] = []
    private var initialFrame: Data?
    private let maximumQueuedBytes: Int
    private let maximumQueuedFrames: Int

    public init(
        maximumQueuedBytesPerClient: Int = CollectorTransportLimits.maximumQueuedBytesPerClient,
        maximumQueuedFramesPerClient: Int = CollectorTransportLimits.maximumQueuedFramesPerClient
    ) {
        maximumQueuedBytes = maximumQueuedBytesPerClient
        maximumQueuedFrames = maximumQueuedFramesPerClient
    }

    public var activeClientCount: Int {
        lock.lock(); defer { lock.unlock() }
        return clients.filter { !$0.isClosed }.count
    }

    /// Takes ownership on both success and failure.
    @discardableResult
    public func add(takingSocket fd: Int32) -> Bool {
        lock.lock(); defer { lock.unlock() }
        clients.removeAll { $0.isClosed }
        guard clients.count < CollectorTransportLimits.maximumClients else {
            Darwin.close(fd)
            return false
        }
        guard let writer = CollectorSocketWriter(
            takingSocket: fd,
            maximumQueuedBytes: maximumQueuedBytes,
            maximumQueuedFrames: maximumQueuedFrames
        ) else { return false }
        if let initialFrame, !writer.enqueue(initialFrame) { return false }
        clients.append(writer)
        return true
    }

    /// New clients see this frame first; publishing and broadcasting share one admission lock.
    @discardableResult
    public func publishInitialFrameAndBroadcast(_ frame: Data) -> Bool {
        guard frame.count <= CollectorTransportLimits.maximumFrameBytes else { return false }
        lock.lock(); defer { lock.unlock() }
        initialFrame = frame
        broadcastLocked(frame)
        return true
    }

    public func broadcast(_ frame: Data) {
        lock.lock(); defer { lock.unlock() }
        broadcastLocked(frame)
    }

    public func closeAll() {
        lock.lock(); defer { lock.unlock() }
        clients.forEach { $0.close() }
        clients.removeAll()
        initialFrame = nil
    }

    deinit { closeAll() }

    private func broadcastLocked(_ frame: Data) {
        clients.removeAll { !$0.enqueue(frame) }
    }
}
#endif
