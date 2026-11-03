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
}
