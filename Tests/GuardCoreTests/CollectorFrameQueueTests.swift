import Foundation
import Testing
@testable import GuardCore

@Suite struct CollectorFrameQueueTests {
    @Test func partialHeadKeepsItsWholeFrameReservation() {
        var queue = CollectorFrameQueue(maximumBytes: 12, maximumFrames: 3)
        let firstAccepted = queue.enqueue(Data(repeating: 1, count: 8))
        #expect(firstAccepted)
        queue.advance(by: 7)
        #expect(queue.retainedBytes == 8)
        #expect(queue.headOffset == 7)
        let oversizedAccepted = queue.enqueue(Data(repeating: 2, count: 5))
        #expect(!oversizedAccepted)
        let fittingAccepted = queue.enqueue(Data(repeating: 2, count: 4))
        #expect(fittingAccepted)
        queue.advance(by: 1)
        #expect(queue.retainedBytes == 4)
        #expect(queue.frameCount == 1)
        #expect(queue.headOffset == 0)
        #expect(queue.head == Data(repeating: 2, count: 4))
        queue.advance(by: 4)
        #expect(queue.isEmpty)
        #expect(queue.retainedBytes == 0)
        #expect(queue.head == nil)
    }

    @Test func frameLimitAndByteLimitAreIndependent() {
        var queue = CollectorFrameQueue(maximumBytes: 100, maximumFrames: 2)
        let firstAccepted = queue.enqueue(Data([1]))
        let secondAccepted = queue.enqueue(Data([2]))
        let thirdAccepted = queue.enqueue(Data([3]))
        #expect(firstAccepted)
        #expect(secondAccepted)
        #expect(!thirdAccepted)
        #expect(queue.retainedBytes == 2)
        queue.removeAll()
        let oversizedAccepted = queue.enqueue(Data(repeating: 4, count: 101))
        #expect(!oversizedAccepted)
        #expect(queue.isEmpty)
        let emptyAccepted = queue.enqueue(Data())
        #expect(emptyAccepted)
        #expect(queue.isEmpty)
    }

    @Test func repeatedCompactionPreservesFIFOAndReleasesAllReservations() {
        var queue = CollectorFrameQueue(maximumBytes: 1024, maximumFrames: 128)
        for value in 0..<128 {
            let accepted = queue.enqueue(Data([UInt8(value)]))
            #expect(accepted)
        }
        for value in 0..<96 {
            #expect(queue.head == Data([UInt8(value)]))
            queue.advance(by: 1)
        }
        for value in 128..<224 {
            let accepted = queue.enqueue(Data([UInt8(value)]))
            #expect(accepted)
        }
        for value in 96..<224 {
            #expect(queue.head == Data([UInt8(value)]))
            queue.advance(by: 1)
        }
        #expect(queue.isEmpty)
        #expect(queue.retainedBytes == 0)
        #expect(queue.headOffset == 0)
    }
}
