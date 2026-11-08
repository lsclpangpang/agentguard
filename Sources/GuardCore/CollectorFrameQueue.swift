import Foundation

/// Counts complete retained frames, including the already-written prefix of the head frame.
/// The owner serializes access; this queue does not schedule work or perform socket operations.
struct CollectorFrameQueue {
    let maximumBytes: Int
    let maximumFrames: Int
    private var storage: [Data?] = []
    private var headIndex = 0
    private(set) var headOffset = 0
    private(set) var retainedBytes = 0
    private(set) var frameCount = 0

    init(maximumBytes: Int, maximumFrames: Int) {
        precondition(maximumBytes > 0 && maximumFrames > 0)
        self.maximumBytes = maximumBytes
        self.maximumFrames = maximumFrames
    }

    var head: Data? { frameCount == 0 ? nil : storage[headIndex] }
    var isEmpty: Bool { frameCount == 0 }

    mutating func enqueue(_ frame: Data) -> Bool {
        guard !frame.isEmpty else { return true }
        guard frameCount < maximumFrames, frame.count <= maximumBytes - retainedBytes else { return false }
        storage.append(frame)
        retainedBytes += frame.count
        frameCount += 1
        return true
    }

    mutating func advance(by byteCount: Int) {
        guard let frame = head else { preconditionFailure("Cannot advance an empty frame queue") }
        precondition(byteCount > 0 && byteCount <= frame.count - headOffset)
        headOffset += byteCount
        guard headOffset == frame.count else { return }
        retainedBytes -= frame.count
        frameCount -= 1
        storage[headIndex] = nil
        headIndex += 1
        headOffset = 0
        if frameCount == 0 {
            removeAll()
        } else if headIndex >= 64, headIndex >= storage.count / 2 {
            storage.removeFirst(headIndex)
            headIndex = 0
        }
    }

    mutating func removeAll() {
        storage.removeAll(keepingCapacity: false)
        headIndex = 0
        headOffset = 0
        retainedBytes = 0
        frameCount = 0
    }
}
