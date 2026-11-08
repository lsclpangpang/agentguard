import Testing
@testable import GuardCore

@Suite struct CLICommandTests {
    @Test func parsesRun() throws {
        #expect(try CLICommand.parse(["run", "claude-work", "--", "claude", "--resume"]) == .run(profileID: "claude-work", command: ["claude", "--resume"]))
    }

    @Test func commandMayContainDoubleDash() throws {
        #expect(try CLICommand.parse(["run", "x", "--", "git", "log", "--", "file"]) == .run(profileID: "x", command: ["git", "log", "--", "file"]))
    }

    @Test(arguments: [
        ["run"], ["run", "x"], ["run", "x", "--"], ["run", "x", "claude"], ["run", "../x", "--", "sh"],
        ["run", "x", "--allow", "/", "--", "sh"], ["frobnicate"],
    ])
    func rejectsInvalidInvocations(args: [String]) {
        #expect(throws: CLIError.self) { try CLICommand.parse(args) }
    }

    @Test func otherCommands() throws {
        #expect(try CLICommand.parse([]) == .help)
        #expect(try CLICommand.parse(["help"]) == .help)
        #expect(try CLICommand.parse(["status"]) == .status(json: false))
        #expect(try CLICommand.parse(["status", "--json"]) == .status(json: true))
        #expect(try CLICommand.parse(["list"]) == .list)
        #expect(try CLICommand.parse(["version"]) == .version)
    }

    @Test func readDiagnosticsAcceptAnAbsolutePathAndOptionalJSON() throws {
        let path = "/Library/Application Support/AgentGuard/owner.json"
        #expect(try CLICommand.parse(["diagnose-read", "knodo", path])
                == .diagnoseRead(profileID: "knodo", path: path, json: false))
        #expect(try CLICommand.parse(["diagnose-read", "knodo", path, "--json"])
                == .diagnoseRead(profileID: "knodo", path: path, json: true))
    }

    @Test(arguments: [
        ["diagnose-read"], ["diagnose-read", "knodo"],
        ["diagnose-read", "../knodo", "/tmp/test"],
        ["diagnose-read", "knodo", "relative/path"],
        ["diagnose-read", "knodo", "/tmp/test", "--allow"],
        ["diagnose-read", "knodo", "/tmp/test", "--json", "--json"],
        ["diagnose-read", "knodo", "/tmp/\u{0}test"],
    ])
    func rejectsAmbiguousReadDiagnostics(args: [String]) {
        #expect(throws: CLIError.self) { try CLICommand.parse(args) }
    }
}
