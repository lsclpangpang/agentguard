#if os(macOS)
import Darwin
import Foundation

/// Low-level socket setup and an unbuffered, one-shot write helper. The collector's streaming
/// transport uses CollectorSocketWriter's bounded whole-frame FIFO to resume temporary EAGAIN.
public enum BoundedCollectorSocket {
    public static func makeNonBlocking(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return false }
        var on: Int32 = 1
        return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size)) == 0
    }

    public static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
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
                    // This one-shot helper owns no queue. Callers must treat a partial failure
                    // as an interrupted stream, rather than retrying the complete frame.
                    return false
                }
            }
            return true
        }
    }
}
#endif
