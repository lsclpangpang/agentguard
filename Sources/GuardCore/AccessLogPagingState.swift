import Foundation

/// One bounded page and a bounded list of return positions. Paging never changes the query window.
public struct AccessLogPagingState: Sendable {
    public private(set) var query: AccessLogQuery
    public private(set) var page: AccessLogPage?
    public private(set) var pageNumber = 1
    public var isFirstPage: Bool { pageNumber == 1 }
    public var canGoBack: Bool { position > 0 }
    public var canAdvance: Bool { page?.nextCursor != nil }
    public var retainedPositionCount: Int { positions.count }
    public var retainedCursorBytes: Int { positions.compactMap { $0 }.reduce(0) { $0 + $1.utf8.count } }

    private var positions: [String?] = [nil]
    private var position = 0
    private var generation: UInt64?
    private let maximumPositions: Int
    private let maximumCursorBytes: Int

    public init(query: AccessLogQuery, maximumPositions: Int = 32, maximumCursorBytes: Int = 2 * 1024 * 1024) {
        var initial = query
        initial.cursor = nil
        self.query = initial
        self.maximumPositions = max(1, maximumPositions)
        self.maximumCursorBytes = max(1, maximumCursorBytes)
    }

    public mutating func reset(query: AccessLogQuery) {
        self = Self(query: query, maximumPositions: maximumPositions, maximumCursorBytes: maximumCursorBytes)
    }

    public mutating func accept(_ result: AccessLogPage) throws {
        if let generation, generation != result.generation { throw AccessLogError.historyExpired }
        if let next = result.nextCursor, next == query.cursor { throw AccessLogError.invalidCursor }
        // A single unbounded cursor must not evade the App's return-position budget.
        if let next = result.nextCursor, next.utf8.count > maximumCursorBytes { throw AccessLogError.invalidCursor }
        generation = result.generation
        page = result
    }

    @discardableResult public mutating func advance() -> Bool {
        guard let next = page?.nextCursor else { return false }
        positions = Array(positions.prefix(position + 1))
        positions.append(next)
        position += 1
        pageNumber += 1
        while positions.count > 1 && (positions.count > maximumPositions || retainedCursorBytes > maximumCursorBytes) {
            positions.removeFirst()
            position -= 1
        }
        query.cursor = next
        page = nil
        return true
    }

    @discardableResult public mutating func goBack() -> Bool {
        guard canGoBack else { return false }
        position -= 1
        pageNumber -= 1
        query.cursor = positions[position]
        page = nil
        return true
    }
}
