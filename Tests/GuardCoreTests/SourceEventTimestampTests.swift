import Foundation
import Testing
@testable import GuardCore

@Suite struct SourceEventTimestampTests {
    @Test(arguments: [
        ("2023-11-14T22:13:20Z", 0.0),
        ("2023-11-14T22:13:20.1Z", 0.1),
        ("2023-11-14T22:13:20.123Z", 0.123),
        ("2023-11-14T22:13:20.123456Z", 0.123456),
        ("2023-11-14T22:13:20.123456789Z", 0.123456789),
        ("2023-11-15T06:13:20.123456+08:00", 0.123456),
        ("2023-11-14T16:43:20.123456-05:30", 0.123456),
        ("2023-11-14t22:13:20.123456z", 0.123456)
    ])
    func rfc3339RetainsTheSuppliedFraction(_ input: String, _ fraction: Double) throws {
        let date = try #require(SourceEventTimestamp.parse(input))
        #expect(abs(date.timeIntervalSince1970 - (1_700_000_000 + fraction)) < 0.000001)
    }

    @Test(arguments: [
        "2023-11-15 06:13:20.123456+0800",
        "2023-11-14 16:43:20.123456-0530",
        "2023-11-14 22:13:20.123456+0000",
        "2023-11-14T22:13:20.123456Z"
    ])
    func unifiedLogKeepsMicroseconds(_ input: String) throws {
        let date = try #require(SourceEventTimestamp.parseUnifiedLog(input))
        #expect(abs(date.timeIntervalSince1970 - 1_700_000_000.123456) < 0.000001)
    }

    @Test(arguments: [
        "", "garbage", "2023-11-14T22:13:20",
        "2023-11-14T22:13:20.Z", "2023-11-14T22:13:20.1234567890Z",
        "2023-11-14T22:13:20Ztail", "2023-11-14T22:13:20.123456Z ",
        "2023-02-29T22:13:20Z", "2024-02-30T22:13:20Z",
        "2023-00-14T22:13:20Z", "2023-13-14T22:13:20Z",
        "2023-11-00T22:13:20Z", "2023-11-31T22:13:20Z",
        "2023-11-14T24:13:20Z", "2023-11-14T22:60:20Z", "2023-11-14T22:13:60Z",
        "2023-11-14T22:13:20+24:00", "2023-11-14T22:13:20+08:60",
        "2023-11-14T22:13:20+08", "0000-11-14T22:13:20Z",
        "2023-11-14Ｔ22:13:20Z", "2023-11-14T22:13:20.１２３Z"
    ])
    func invalidOrUnsupportedTextRemainsUnrecorded(_ input: String) {
        #expect(SourceEventTimestamp.parse(input) == nil)
        #expect(SourceEventTimestamp.parseUnifiedLog(input) == nil)
    }

    @Test func unknownRepresentationsAreNotGuessed() {
        #expect(SourceEventTimestamp.parse(nil) == nil)
        #expect(SourceEventTimestamp.parse(1_700_000_000) == nil)
        #expect(SourceEventTimestamp.parse(true) == nil)
        #expect(SourceEventTimestamp.parse(["tv_sec": 1_700_000_000, "tv_nsec": 123_456_789]) == nil)
        #expect(SourceEventTimestamp.parseUnifiedLog(nil) == nil)
        #expect(SourceEventTimestamp.parse("2023-11-15 06:13:20.123456+0800") == nil)
    }

    @Test func leapYearDateIsValid() throws {
        let date = try #require(SourceEventTimestamp.parse("2024-02-29T00:00:00.654321Z"))
        #expect(abs(date.timeIntervalSince1970 - 1_709_164_800.654321) < 0.000001)
    }
}
