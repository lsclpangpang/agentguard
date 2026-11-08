import Foundation
import Testing
@testable import GuardCore

/// Fixtures follow the field names of the Endpoint Security message structures as rendered by eslogger.
/// They must be re-checked against real `eslogger --format json` output on a Mac (M0).
@Suite struct ESLoggerParserTests {
    func process(_ pid: Int, _ version: Int, _ path: String) -> String {
        #"{"audit_token":{"pid":\#(pid),"pidversion":\#(version),"euid":501},"executable":{"path":"\#(path)"}}"#
    }

    func line(_ seq: Int, _ event: String, pid: Int = 100, version: Int = 1, path: String = "/bin/zsh") -> String {
        #"{"global_seq_num":\#(seq),"seq_num":1,"event_type":0,"process":\#(process(pid, version, path)),"event":\#(event)}"#
    }

    let parent = ProcessKey(pid: 100, version: 1)

    @Test func parsesFork() throws {
        let parsed = try ESLoggerParser.parse(line(7, #"{"fork":{"child":\#(process(101, 1, "/bin/zsh"))}}"#))
        #expect(parsed.globalSequence == 7)
        #expect(parsed.process == parent)
        #expect(parsed.executablePath == "/bin/zsh")
        #expect(parsed.kind == .fork(child: ProcessKey(pid: 101, version: 1)))
        #expect(parsed.processEvent == .fork(parent: parent, child: ProcessKey(pid: 101, version: 1)))
    }

    @Test func parsesExecWithNewImage() throws {
        let parsed = try ESLoggerParser.parse(line(8, #"{"exec":{"target":\#(process(100, 2, "/usr/bin/git"))}}"#))
        #expect(parsed.kind == .exec(target: ProcessKey(pid: 100, version: 2), path: "/usr/bin/git"))
        #expect(parsed.processEvent == .exec(from: parent, to: ProcessKey(pid: 100, version: 2)))
        #expect(parsed.observedAccess == .exec("/usr/bin/git"))
    }

    @Test func parsesExit() throws {
        let parsed = try ESLoggerParser.parse(line(9, #"{"exit":{"stat":0}}"#))
        #expect(parsed.processEvent == .exit(parent))
    }

    @Test func birthsComeFromTheDescribedProcesses() throws {
        let text = #"{"global_seq_num":1,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":{"tv_sec":1700000000,"tv_usec":123456}},"event":{"fork":{"child":{"audit_token":{"pid":101,"pidversion":1},"start_time":{"tv_sec":1700000001,"tv_usec":234567}}}}}"#
        let parsed = try ESLoggerParser.parse(text)
        #expect(parsed.processStartTime == 1_700_000_000_123_456)
        #expect(parsed.relatedProcessStartTime == 1_700_000_001_234_567)
    }

    @Test(arguments: ["2023-11-14T22:13:20.123456Z", "2023-11-15T06:13:20.123456+08:00"])
    func exactRFC3339Birth(_ value: String) throws {
        let text = #"{"global_seq_num":1,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":"\#(value)"},"event":{"exit":{}}}"#
        #expect(try ESLoggerParser.parse(text).processStartTime == 1_700_000_000_123_456)
    }

    @Test(arguments: [
        ("2023-11-14T22:13:20.000001Z", UInt64(1_700_000_000_000_001)),
        ("2023-11-14T22:13:20.999999Z", UInt64(1_700_000_000_999_999)),
        ("2023-11-15T06:13:20.000001+08:00", UInt64(1_700_000_000_000_001)),
        ("2023-11-14T17:13:20.999999-05:00", UInt64(1_700_000_000_999_999)),
        ("2026-11-07T13:36:33.070013Z", UInt64(1_794_058_593_070_013))
    ])
    func birthRetainsIntegerMicroseconds(_ value: String, _ expected: UInt64) throws {
        let text = #"{"global_seq_num":1,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":"\#(value)"},"event":{"exit":{}}}"#
        #expect(try ESLoggerParser.parse(text).processStartTime == expected)
    }

    @Test(arguments: ["2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20.123456789Z", "garbage"])
    func roundedOrUnknownBirthDoesNotEstablishIdentity(_ value: String) throws {
        let text = #"{"global_seq_num":1,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":"\#(value)"},"event":{"exit":{}}}"#
        #expect(try ESLoggerParser.parse(text).processStartTime == nil)
    }

    @Test(arguments: [
        "2023-02-29T22:13:20.123456Z",
        "2100-02-29T00:00:00.123456Z",
        "2023-11-31T22:13:20.123456Z",
        "2023-11-14T24:13:20.123456Z",
        "2023-11-14T22:13:20.123456+24:00",
        "2023-11-14T22:13:20.123456+25:00",
        "2023-11-14T22:13:20.123456+08:60",
        "2023-11-14t22:13:20.123456Z",
        "2023-11-14T22:13:20.123456Z ",
        "2023-11-14T22:13:20.123456Zjunk",
        "2023-11-14T22:13:20.999999.000001Z",
        "2023-11-15T06:13:20.999999.000001+08:00",
        "2023-11-14T22:13:20.123.456789Z"
    ])
    func noncanonicalBirthDoesNotNormalizeIntoAnIdentity(_ value: String) throws {
        let text = #"{"global_seq_num":1,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":"\#(value)"},"event":{"exit":{}}}"#
        let parsed = try ESLoggerParser.parse(text)
        #expect(parsed.processStartTime == nil)
        #expect(parsed.kind == .exit)
        #expect(parsed.process == ProcessKey(pid: 100, version: 4))
    }

    @Test(arguments: [
        "2023-11-14T22:13:20.123456Z",
        "2023-11-14T22:13:20.123456789Z",
        "2023-11-15T06:13:20.123456+08:00",
        "2023-11-14T17:13:20.123456-05:00"
    ])
    func sourceEventTimeComesFromRootTime(_ value: String) throws {
        let text = #"{"global_seq_num":1,"time":"\#(value)","mach_time":999999,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":{"tv_sec":1600000000,"tv_usec":654321}},"event":{"exit":{}}}"#
        let parsed = try ESLoggerParser.parse(text)
        let sourceAt = try #require(parsed.sourceAt)
        #expect(abs(sourceAt.timeIntervalSince1970 - 1_700_000_000.123456789) < 0.000001)
        #expect(parsed.processStartTime == 1_600_000_000_654_321)
        #expect(parsed.receivedAt == nil)
        #expect(parsed.kind == .exit)
    }

    @Test(arguments: [
        "null", "0", "true", "{}", #""garbage""#,
        #""2023-02-29T22:13:20.123456Z""#,
        #""2023-11-14T24:13:20.123456Z""#,
        #""2023-11-14T22:13:20.123456""#,
        #""2023-11-14T22:13:20.123456+25:00""#,
        #""2023-11-14T22:13:20.1234567890Z""#
    ])
    func invalidSourceEventTimeDoesNotRejectTheEvent(_ rawTime: String) throws {
        let text = #"{"global_seq_num":1,"time":\#(rawTime),"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":{"tv_sec":1600000000,"tv_usec":654321}},"event":{"exit":{}}}"#
        let parsed = try ESLoggerParser.parse(text)
        #expect(parsed.sourceAt == nil)
        #expect(parsed.processStartTime == 1_600_000_000_654_321)
        #expect(parsed.kind == .exit)
    }

    @Test func missingSourceTimeDoesNotUseAnotherClock() throws {
        let text = #"{"global_seq_num":1,"mach_time":999999,"deadline":9999999,"process":{"audit_token":{"pid":100,"pidversion":4},"start_time":{"tv_sec":1600000000,"tv_usec":654321}},"event":{"exit":{}}}"#
        let parsed = try ESLoggerParser.parse(text)
        #expect(parsed.sourceAt == nil)
        #expect(parsed.processStartTime == 1_600_000_000_654_321)
    }

    @Test(arguments: [
        ("2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20.123456Z"),
        ("2023-11-14T22:13:20.123456789Z", "2023-11-14T22:13:20.123457Z")
    ])
    func sourceTimeSurvivesMicrosecondLogEncoding(_ input: String, _ output: String) throws {
        let text = #"{"global_seq_num":1,"time":"\#(input)","process":{"audit_token":{"pid":100,"pidversion":4}},"event":{"exit":{}}}"#
        let sourceAt = try #require(ESLoggerParser.parse(text).sourceAt)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = AccessLogTimestamp.encodingStrategy
        let data = try encoder.encode(sourceAt)
        #expect(String(decoding: data, as: UTF8.self) == "\"\(output)\"")
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = AccessLogTimestamp.decodingStrategy
        #expect(abs(try decoder.decode(Date.self, from: data).timeIntervalSince(sourceAt)) < 0.000001)
    }

    @Test func openWithWriteFlagIsWrite() throws {
        #expect(try ESLoggerParser.parse(line(1, #"{"open":{"fflag":3,"file":{"path":"/a"}}}"#)).observedAccess == .write("/a"))
        #expect(try ESLoggerParser.parse(line(1, #"{"open":{"fflag":1,"file":{"path":"/a"}}}"#)).observedAccess == .read("/a"))
    }

    @Test(arguments: [
        "", #""fflag":0,"#, #""fflag":32768,"#, #""fflag":true,"#,
        #""fflag":-1,"#, #""fflag":1.5,"#, #""fflag":"1","#,
        #""fflag":4294967296,"#,
    ])
    func unclassifiedOpenNeverSuggestsContentRead(_ flags: String) throws {
        let parsed = try ESLoggerParser.parse(line(1, #"{"open":{\#(flags)"file":{"path":"/a"}}}"#))
        #expect(parsed.rawOperation == "open")
        #expect(parsed.rawTargets == ["/a"])
        #expect(parsed.observedAccesses.isEmpty)
        #expect(parsed.processEvent == nil)
    }

    @Test func rawOpenFlagsRetainReadWriteAndUnknownModes() throws {
        for flags in [UInt32(0), 1, 2, 3, 32768, UInt32.max] {
            let parsed = try ESLoggerParser.parse(line(1, #"{"open":{"fflag":\#(flags),"file":{"path":"/a"}}}"#))
            #expect(parsed.openFlags == flags)
        }
        #expect(try ESLoggerParser.parse(line(1, #"{"open":{"file":{"path":"/a"}}}"#)).openFlags == nil)
        #expect(try ESLoggerParser.parse(line(1, #"{"exit":{}}"#)).openFlags == nil)
    }

    @Test func createSupportsExistingFileAndNewPath() throws {
        #expect(try ESLoggerParser.parse(line(1, #"{"create":{"destination":{"existing_file":{"path":"/d/x"}}}}"#)).observedAccess == .write("/d/x"))
        #expect(try ESLoggerParser.parse(line(1, #"{"create":{"destination":{"new_path":{"dir":{"path":"/d"},"filename":"y"}}}}"#)).observedAccess == .write("/d/y"))
    }

    @Test func renameUnlinkClose() throws {
        let rename = try ESLoggerParser.parse(line(1, #"{"rename":{"source":{"path":"/a"},"destination":{"new_path":{"dir":{"path":"/b"},"filename":"c"}}}}"#))
        #expect(rename.kind == .rename(from: "/a", to: "/b/c"))
        #expect(rename.observedAccesses == [.write("/a"), .write("/b/c")])
        #expect(try ESLoggerParser.parse(line(1, #"{"unlink":{"target":{"path":"/a"}}}"#)).observedAccess == .write("/a"))
        #expect(try ESLoggerParser.parse(line(1, #"{"close":{"modified":true,"target":{"path":"/a"}}}"#)).observedAccess == .write("/a"))
        #expect(try ESLoggerParser.parse(line(1, #"{"close":{"modified":false,"target":{"path":"/a"}}}"#)).observedAccess == nil)
    }

    @Test func unknownEventTypeIsKeptAsUnsupported() throws {
        let parsed = try ESLoggerParser.parse(line(3, #"{"signal":{"sig":9}}"#))
        #expect(parsed.kind == .unsupported("signal"))
        #expect(parsed.processEvent == nil)
        #expect(parsed.globalSequence == 3)
    }

    @Test(arguments: ["not json", "{}", #"{"global_seq_num":1}"#, #"{"global_seq_num":1,"process":{"audit_token":{"pid":1}},"event":{}}"#])
    func malformedLinesThrow(text: String) {
        #expect(throws: ESParseError.self) { try ESLoggerParser.parse(text) }
    }
}
