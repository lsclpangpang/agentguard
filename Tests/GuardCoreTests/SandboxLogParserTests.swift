import Testing
@testable import GuardCore

@Suite struct SandboxLogParserTests {
    @Test func parsesFileDenial() throws {
        let d = try #require(SandboxLogParser.parse("Sandbox: knodo-agentd(97140) deny(1) file-write-create /Users/me/.knodo/agent.json"))
        #expect(d.process == "knodo-agentd")
        #expect(d.pid == 97140)
        #expect(d.operation == "file-write-create")
        #expect(d.target == "/Users/me/.knodo/agent.json")
        #expect(d.access == .write("/Users/me/.knodo/agent.json"))
    }

    @Test func readAndExecOperations() throws {
        #expect(SandboxLogParser.parse("Sandbox: claude(1) deny(1) file-read-data /private/tmp/claude-501")?.access == .read("/private/tmp/claude-501"))
        #expect(SandboxLogParser.parse("Sandbox: sh(2) deny(1) process-exec* /usr/bin/curl")?.access == .exec("/usr/bin/curl"))
    }

    @Test func networkOperations() throws {
        #expect(SandboxLogParser.parse("Sandbox: knodo-agentd(3) deny(1) network-outbound 127.0.0.1:9910")?.access == .connectLoopback(9910))
        #expect(SandboxLogParser.parse("Sandbox: x(3) deny(1) network-outbound [::1]:8080")?.access == .connectLoopback(8080))
        #expect(SandboxLogParser.parse("Sandbox: x(3) deny(1) network-outbound 140.82.112.3:443")?.access == .connectRemote)
        #expect(SandboxLogParser.parse("Sandbox: x(3) deny(1) network-bind 0.0.0.0:3000")?.access == .listen(3000))
    }

    @Test func pathsWithSpacesAreKept() {
        #expect(SandboxLogParser.parse("Sandbox: a(4) deny(1) file-read-data /Users/me/Library/Application Support/x y")?.target == "/Users/me/Library/Application Support/x y")
    }

    @Test func unsupportedOperationStillParses() throws {
        let d = try #require(SandboxLogParser.parse("Sandbox: a(5) deny(1) mach-lookup com.apple.coreservices.launchservicesd"))
        #expect(d.access == nil)
        #expect(d.operation == "mach-lookup")
    }

    @Test func processNamesMayContainParentheses() {
        #expect(SandboxLogParser.parse("Sandbox: Code Helper (Plugin)(77) deny(1) file-read-data /x")?.pid == 77)
    }

    @Test(arguments: ["", "kernel: something else", "Sandbox: broken deny(1) file-read-data /x", "Sandbox: a(1) allow file-read-data /x"])
    func otherMessagesAreIgnored(message: String) {
        #expect(SandboxLogParser.parse(message) == nil)
    }
}
