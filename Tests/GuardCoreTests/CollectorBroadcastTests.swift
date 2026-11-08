#if os(macOS)
import Darwin
import Foundation
import Testing
@testable import GuardCore

@Suite(.serialized) struct CollectorBroadcastTests {
    private func sockets(sendBuffer: Int32 = 4096) throws -> (Int32, Int32) {
        var pair: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        var size = sendBuffer
        try #require(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size,
                               socklen_t(MemoryLayout<Int32>.size)) == 0)
        return (pair[0], pair[1])
    }

    private func receive(_ fd: Int32, expectedBytes: Int, timeout: TimeInterval = 5) async -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(timeout)
        while result.count < expectedBytes, Date() < deadline {
            let count = recv(fd, &buffer, min(buffer.count, expectedBytes - result.count), MSG_DONTWAIT)
            if count > 0 { result.append(contentsOf: buffer.prefix(count)) }
            else if count == 0 { break }
            else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { break }
            else { try? await Task.sleep(for: .milliseconds(1)) }
        }
        return result
    }

    private func waitUntil(timeout: TimeInterval = 3, _ condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition(), Date() < deadline { try? await Task.sleep(for: .milliseconds(1)) }
        return condition()
    }

    private func peerReachedEOF(_ fd: Int32) -> Bool {
        var byte: UInt8 = 0
        return recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0
    }

    private func jsonFrame(index: Int, padding: Int = 0) -> Data {
        Data((#"{"i":"# + String(index) + #","v":""# + String(repeating: "a", count: padding) + "\"}\n").utf8)
    }

    @Test func largeFrameSurvivesTemporarySocketBackpressure() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        defer { writer.close() }
        let frame = Data((#"{"k":"es","v":""# + String(repeating: "a", count: 512 * 1024) + "\"}\n").utf8)

        #expect(writer.enqueue(frame))
        #expect(!writer.isClosed)
        #expect(await waitUntil { writer.snapshot.headOffset > 0 && writer.snapshot.wouldBlockCount > 0 })
        #expect(writer.snapshot.retainedBytes == frame.count)
        let received = await receive(input, expectedBytes: frame.count)
        try #require(received.count == frame.count)
        #expect(received == frame)
        let value = try #require(try JSONSerialization.jsonObject(with: received) as? [String: String])
        #expect(value["v"]?.utf8.count == 512 * 1024)
        #expect(await waitUntil { writer.snapshot.queuedFrames == 0 })
        #expect(writer.snapshot.retainedBytes == 0)
        #expect(writer.snapshot.pumpCount > 1)
    }

    @Test func concurrentProducersKeepCompleteOrderedFrames() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        defer { writer.close() }
        let perProducer = 32
        let producers = 3
        let allFrames = (0..<(perProducer * producers)).map { jsonFrame(index: $0, padding: 2048) }
        let allAdmitted = await withTaskGroup(of: Bool.self, returning: Bool.self) { group in
            for producer in 0..<producers {
                group.addTask {
                    var success = true
                    for item in 0..<perProducer {
                        if !writer.enqueue(allFrames[producer * perProducer + item]) { success = false }
                    }
                    return success
                }
            }
            var success = true
            for await result in group { success = success && result }
            return success
        }
        try #require(allAdmitted)
        let expectedBytes = allFrames.reduce(0) { $0 + $1.count }
        let received = await receive(input, expectedBytes: expectedBytes)
        try #require(received.count == expectedBytes)
        let lines = received.split(separator: 10)
        try #require(lines.count == perProducer * producers)
        var indices: [Int] = []
        for line in lines {
            let object = try #require(try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any])
            indices.append(try #require(object["i"] as? Int))
            #expect((object["v"] as? String)?.utf8.count == 2048)
        }
        #expect(Set(indices).count == perProducer * producers)
        for producer in 0..<producers {
            let range = (producer * perProducer)..<((producer + 1) * perProducer)
            #expect(indices.filter { range.contains($0) } == Array(range))
        }
        #expect(!writer.isClosed)
    }

    @Test func slowClientDoesNotBlockOrDisconnectFastClient() async throws {
        let (slowOutput, slowInput) = try sockets()
        let (fastOutput, fastInput) = try sockets()
        defer { Darwin.close(slowInput); Darwin.close(fastInput) }
        let broadcast = CollectorBroadcaster(maximumQueuedBytesPerClient: 96 * 1024, maximumQueuedFramesPerClient: 16)
        defer { broadcast.closeAll() }
        try #require(broadcast.add(takingSocket: slowOutput))
        try #require(broadcast.add(takingSocket: fastOutput))
        var expectedSlowBytes = 0
        // Wait for each fast read before publishing the next frame. This keeps the healthy
        // client within its queue contract while the other peer deliberately never reads.
        for index in 0..<16 {
            let frame = jsonFrame(index: index, padding: 32 * 1024)
            expectedSlowBytes += frame.count
            broadcast.broadcast(frame)
            let received = await receive(fastInput, expectedBytes: frame.count)
            try #require(received.count == frame.count)
            #expect(received == frame)
        }
        #expect(broadcast.activeClientCount == 1)
        let slowReceived = await receive(slowInput, expectedBytes: expectedSlowBytes)
        #expect(slowReceived.count < expectedSlowBytes)
        // Further messages still arrive on the surviving stream with a clean line boundary.
        let finalFrame = jsonFrame(index: 999)
        broadcast.broadcast(finalFrame)
        #expect(await receive(fastInput, expectedBytes: finalFrame.count) == finalFrame)
    }

    @Test func partialFrameRetainsBudgetAndOverflowClosesOnlyThatWriter() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output, maximumQueuedBytes: 100 * 1024))
        defer { writer.close() }
        let frame = jsonFrame(index: 1, padding: 64 * 1024)
        try #require(writer.enqueue(frame))
        try #require(await waitUntil { writer.snapshot.headOffset > 0 && writer.snapshot.wouldBlockCount > 0 })
        let blocked = writer.snapshot
        #expect(blocked.retainedBytes == frame.count)
        #expect(blocked.headOffset < frame.count)
        try? await Task.sleep(for: .milliseconds(100))
        #expect(writer.snapshot.writeAttempts == blocked.writeAttempts)
        #expect(writer.snapshot.pumpCount == blocked.pumpCount)
        #expect(!writer.enqueue(frame))
        #expect(writer.isClosed)
        #expect(writer.snapshot.retainedBytes == 0)
        #expect(writer.snapshot.queuedFrames == 0)
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
        let prefix = await receive(input, expectedBytes: frame.count)
        #expect(prefix.count > 0)
        #expect(prefix.count < frame.count)
    }

    @Test func pendingFrameCountIsBoundedSeparatelyFromBytes() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output, maximumQueuedFrames: 2))
        defer { writer.close() }
        let frame = jsonFrame(index: 1, padding: 64 * 1024)
        try #require(writer.enqueue(frame))
        try #require(await waitUntil { writer.snapshot.headOffset > 0 })
        #expect(writer.enqueue(frame))
        #expect(writer.snapshot.queuedFrames == 2)
        #expect(!writer.enqueue(frame))
        #expect(writer.isClosed)
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
    }

    @Test func emptyAndDrainedWritersDoNotSpin() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        defer { writer.close() }
        try? await Task.sleep(for: .milliseconds(100))
        #expect(writer.snapshot.pumpCount == 0)
        #expect(writer.enqueue(Data()))
        #expect(writer.snapshot.queuedFrames == 0)
        let frame = jsonFrame(index: 1)
        #expect(writer.enqueue(frame))
        #expect(await receive(input, expectedBytes: frame.count) == frame)
        try #require(await waitUntil { writer.snapshot.queuedFrames == 0 })
        let drained = writer.snapshot
        try? await Task.sleep(for: .milliseconds(100))
        #expect(writer.snapshot.pumpCount == drained.pumpCount)
        #expect(writer.snapshot.writeAttempts == drained.writeAttempts)
        // Resume after a drained/suspended period also preserves delivery.
        #expect(writer.enqueue(frame))
        #expect(await receive(input, expectedBytes: frame.count) == frame)
    }

    @Test func closedPeerClosesAsynchronouslyAndReleasesItsDescriptor() async throws {
        let (output, input) = try sockets()
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        Darwin.close(input)
        #expect(writer.enqueue(jsonFrame(index: 1)))
        #expect(await waitUntil { writer.isClosed && writer.snapshot.descriptorClosed })
        #expect(writer.snapshot.retainedBytes == 0)
        writer.close()
        writer.close()
    }

    @Test func cancellingEmptySuspendedWriterClosesItsDescriptor() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        writer.close()
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
        #expect(writer.snapshot.pumpCount == 0)
        #expect(await waitUntil { peerReachedEOF(input) })
    }

    @Test func deinitCancelsInitiallySuspendedSource() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        var writer = CollectorSocketWriter(takingSocket: output)
        try #require(writer != nil)
        weak var weakWriter = writer
        writer = nil
        #expect(weakWriter == nil)
        #expect(await waitUntil { peerReachedEOF(input) })
    }

    @Test func cancelledPartialWriterNeverClosesAReusedDescriptor() async throws {
        let (originalOutput, input) = try sockets()
        defer { Darwin.close(input) }
        // Keep the reuse target away from ordinary low-numbered descriptors used by other
        // test suites. All ownership transfers in this test are real kernel descriptors.
        let output = fcntl(originalOutput, F_DUPFD_CLOEXEC, 512)
        Darwin.close(originalOutput)
        try #require(output >= 512)
        var writer = CollectorSocketWriter(takingSocket: output)
        try #require(writer != nil)
        try #require(writer?.enqueue(jsonFrame(index: 1, padding: 128 * 1024)) == true)
        try #require(await waitUntil { (writer?.snapshot.headOffset ?? 0) > 0 })
        writer?.close()
        try #require(await waitUntil { writer?.snapshot.descriptorClosed == true })
        // Allocate the lowest available descriptor atomically. If another suite acquired
        // output after cancellation, fail safely instead of overwriting its descriptor.
        let reused = fcntl(input, F_DUPFD_CLOEXEC, output)
        defer { if reused >= 0 { Darwin.close(reused) } }
        try #require(reused == output)
        writer?.close()
        writer = nil
        try? await Task.sleep(for: .milliseconds(100))
        #expect(fcntl(reused, F_GETFD) >= 0)
    }

    @Test func repeatedPartialCancellationReleasesEveryOwnedDescriptor() async throws {
        for index in 0..<24 {
            let (output, input) = try sockets()
            let writer = try #require(CollectorSocketWriter(takingSocket: output))
            let frame = jsonFrame(index: index, padding: 64 * 1024)
            try #require(writer.enqueue(frame))
            try #require(await waitUntil { writer.snapshot.headOffset > 0 })
            writer.close()
            #expect(await waitUntil { writer.snapshot.descriptorClosed })
            let prefix = await receive(input, expectedBytes: frame.count)
            #expect(prefix.count < frame.count)
            #expect(await waitUntil { peerReachedEOF(input) })
            Darwin.close(input)
        }
    }

    @Test func clientLimitAndInitialFrameOrderingAreEnforced() async throws {
        let broadcast = CollectorBroadcaster()
        defer { broadcast.closeAll() }
        let firstStatus = jsonFrame(index: -1)
        try #require(broadcast.publishInitialFrameAndBroadcast(firstStatus))
        var readers: [Int32] = []
        defer { readers.forEach { Darwin.close($0) } }
        for _ in 0..<CollectorTransportLimits.maximumClients {
            let (output, input) = try sockets()
            readers.append(input)
            try #require(broadcast.add(takingSocket: output))
        }
        let (rejectedOutput, rejectedInput) = try sockets()
        defer { Darwin.close(rejectedInput) }
        #expect(!broadcast.add(takingSocket: rejectedOutput))
        #expect(broadcast.activeClientCount == 4)
        #expect(await receive(rejectedInput, expectedBytes: 1).isEmpty)
        let event = jsonFrame(index: 1)
        broadcast.broadcast(event)
        for reader in readers {
            #expect(await receive(reader, expectedBytes: firstStatus.count + event.count) == firstStatus + event)
        }
        broadcast.closeAll()
        #expect(broadcast.activeClientCount == 0)
        let latestStatus = jsonFrame(index: -2)
        #expect(broadcast.publishInitialFrameAndBroadcast(latestStatus))
        let (newOutput, newInput) = try sockets()
        defer { Darwin.close(newInput) }
        #expect(broadcast.add(takingSocket: newOutput))
        #expect(await receive(newInput, expectedBytes: latestStatus.count) == latestStatus)
    }

    @Test func singleFrameLimitIncludesOnlyOneTerminatingNewline() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        #expect(!writer.enqueue(Data(repeating: 65, count: CollectorTransportLimits.maximumFrameBytes + 1)))
        #expect(writer.isClosed)
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
        #expect(await receive(input, expectedBytes: 1).isEmpty)
    }

    @Test func callersCannotRaiseHardPerClientByteLimit() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(
            takingSocket: output, maximumQueuedBytes: 100 * 1024 * 1024, maximumQueuedFrames: 10_000
        ))
        defer { writer.close() }
        let maximumFrame = Data(repeating: 65, count: CollectorTransportLimits.maximumFrameBytes)
        try #require(writer.enqueue(maximumFrame))
        try #require(await waitUntil { writer.snapshot.headOffset > 0 })
        #expect(writer.snapshot.retainedBytes == maximumFrame.count)
        // Two maximum-sized frames exceed 2 MiB by two newline bytes, even after a prefix sent.
        #expect(!writer.enqueue(maximumFrame))
        #expect(writer.isClosed)
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
    }

    @Test func callersCannotRaiseHardPerClientFrameCount() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output, maximumQueuedFrames: 10_000))
        defer { writer.close() }
        try #require(writer.enqueue(jsonFrame(index: 1, padding: 64 * 1024)))
        try #require(await waitUntil { writer.snapshot.wouldBlockCount > 0 })
        for _ in 1..<CollectorTransportLimits.maximumQueuedFramesPerClient {
            try #require(writer.enqueue(Data([10])))
        }
        #expect(writer.snapshot.queuedFrames == 128)
        #expect(!writer.enqueue(Data([10])))
        #expect(writer.isClosed)
        #expect(await waitUntil { writer.snapshot.descriptorClosed })
    }

    @Test func updatedInitialFrameIsFirstForLateSubscriber() async throws {
        let broadcast = CollectorBroadcaster()
        defer { broadcast.closeAll() }
        let oldStatus = jsonFrame(index: -1), newStatus = jsonFrame(index: -2), event = jsonFrame(index: 1)
        #expect(broadcast.publishInitialFrameAndBroadcast(oldStatus))
        let (oldOutput, oldInput) = try sockets()
        defer { Darwin.close(oldInput) }
        #expect(broadcast.add(takingSocket: oldOutput))
        #expect(broadcast.publishInitialFrameAndBroadcast(newStatus))
        let (lateOutput, lateInput) = try sockets()
        defer { Darwin.close(lateInput) }
        #expect(broadcast.add(takingSocket: lateOutput))
        broadcast.broadcast(event)
        let oldExpected = oldStatus + newStatus + event
        let lateExpected = newStatus + event
        #expect(await receive(oldInput, expectedBytes: oldExpected.count) == oldExpected)
        #expect(await receive(lateInput, expectedBytes: lateExpected.count) == lateExpected)
    }

    @Test func peerCanCloseItsSendingHalfAndKeepReceiving() async throws {
        let (output, input) = try sockets()
        defer { Darwin.close(input) }
        let writer = try #require(CollectorSocketWriter(takingSocket: output))
        defer { writer.close() }
        try #require(shutdown(input, SHUT_WR) == 0)
        let frame = jsonFrame(index: 1)
        #expect(writer.enqueue(frame))
        #expect(await receive(input, expectedBytes: frame.count) == frame)
        #expect(!writer.isClosed)
    }
}
#endif
