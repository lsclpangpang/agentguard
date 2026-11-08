#if os(macOS)
import Darwin
import Foundation
import Testing
@testable import GuardCore

@Suite struct BoundedCollectorSocketTests {
    @Test func slowReaderReturnsWithoutRetainingAWriteBacklog() throws {
        var sockets: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
        defer { close(sockets[0]); close(sockets[1]) }
        try #require(BoundedCollectorSocket.makeNonBlocking(sockets[0]))
        #expect(fcntl(sockets[0], F_GETFL) & O_NONBLOCK != 0)
        var size: Int32 = 1024
        _ = setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        let clock = ContinuousClock()
        let start = clock.now
        #expect(!BoundedCollectorSocket.writeAll(sockets[0], Data(repeating: 65, count: 2 * 1024 * 1024)))
        #expect(start.duration(to: clock.now) < .seconds(1))
        // A backpressured write is a failure, not reported as delivery success or queued for later.
        var received = [UInt8](repeating: 0, count: 4096)
        #expect(recv(sockets[1], &received, received.count, MSG_DONTWAIT) > 0)
    }

    @Test func completeSmallFramesAndClosedPeersHaveDistinctResults() throws {
        var sockets: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
        defer { close(sockets[0]) }
        try #require(BoundedCollectorSocket.makeNonBlocking(sockets[0]))
        let payload = Data("one\ntwo\n".utf8)
        #expect(BoundedCollectorSocket.writeAll(sockets[0], payload))
        var bytes = [UInt8](repeating: 0, count: 32)
        let count = recv(sockets[1], &bytes, bytes.count, MSG_DONTWAIT)
        #expect(count == payload.count)
        #expect(Data(bytes.prefix(max(0, count))) == payload)
        close(sockets[1])
        #expect(!BoundedCollectorSocket.writeAll(sockets[0], payload))
    }
}
#endif
