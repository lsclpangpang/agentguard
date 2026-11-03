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

    @Test func openWithWriteFlagIsWrite() throws {
        #expect(try ESLoggerParser.parse(line(1, #"{"open":{"fflag":3,"file":{"path":"/a"}}}"#)).observedAccess == .write("/a"))
        #expect(try ESLoggerParser.parse(line(1, #"{"open":{"fflag":1,"file":{"path":"/a"}}}"#)).observedAccess == .read("/a"))
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
