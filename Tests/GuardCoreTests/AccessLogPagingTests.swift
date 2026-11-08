import Foundation
import Testing
@testable import GuardCore

struct AccessLogPagingTests {
    @Test func pagingKeepsTheOriginalTimeWindowAndFilters() throws {
        let query = AccessLogQuery(profileID: "sample", from: Date(timeIntervalSince1970: 1),
                                   through: Date(timeIntervalSince1970: 20), outcome: .denied)
        var paging = AccessLogPagingState(query: query)
        try paging.accept(page(next: "second"))
        let advanced = paging.advance()
        #expect(advanced)
        #expect(paging.query.from == query.from)
        #expect(paging.query.through == query.through)
        #expect(paging.query.outcome == .denied)
        #expect(paging.query.cursor == "second")
        try paging.accept(page(next: nil))
        let advancedPastEnd = paging.advance()
        let returned = paging.goBack()
        #expect(!advancedPastEnd)
        #expect(returned)
        #expect(paging.query.cursor == nil)
        #expect(paging.pageNumber == 1)
    }

    @Test func emptyScannedPagesRemainNavigableAndStaleHistoryRequiresRefresh() throws {
        var paging = AccessLogPagingState(query: .init(profileID: "sample"))
        try paging.accept(page(next: "scan-more", incomplete: true))
        #expect(paging.page?.records.isEmpty == true)
        let advanced = paging.advance()
        #expect(advanced)
        #expect(throws: AccessLogError.historyExpired) { try paging.accept(page(next: nil, generation: 2)) }
        paging.reset(query: .init(profileID: "sample", through: Date(timeIntervalSince1970: 30)))
        try paging.accept(page(next: nil, generation: 2))
        #expect(paging.pageNumber == 1)
    }

    @Test func repeatedCursorCannotCreateAnEndlessNextPageLoop() throws {
        var paging = AccessLogPagingState(query: .init(profileID: "sample"))
        try paging.accept(page(next: "same"))
        let advanced = paging.advance()
        #expect(advanced)
        #expect(throws: AccessLogError.invalidCursor) { try paging.accept(page(next: "same")) }
    }

    @Test func backHistoryHasACountAndByteBudget() throws {
        var paging = AccessLogPagingState(query: .init(profileID: "sample"), maximumPositions: 3,
                                         maximumCursorBytes: 12)
        for index in 0..<10 {
            try paging.accept(page(next: "page-\(index)"))
            let advanced = paging.advance()
            #expect(advanced)
        }
        #expect(paging.pageNumber == 11)
        #expect(paging.retainedPositionCount <= 3)
        #expect(paging.retainedCursorBytes <= 12)
        let returned = paging.goBack()
        let returnedPastBudget = paging.goBack()
        #expect(returned)
        #expect(!returnedPastBudget)
        #expect(!paging.isFirstPage)
    }

    private func page(next: String?, generation: UInt64 = 1, incomplete: Bool = false) -> AccessLogPage {
        .init(records: [], nextCursor: next, generation: generation, incomplete: incomplete, scannedBytes: 100)
    }
}
