import Testing
import Foundation
@testable import GuardCore

@Suite struct LegacyImporterTests {
    let allowlist = Data("""
    {"read_write_roots": ["/Users/me/easyops", "/Users/me/.codex", "/Users/me/.claude", "/tmp"],
     "read_only_roots": ["/Users/me/.ssh"]}
    """.utf8)

    let policy = """
    (version 1)
    (deny default)
    ;; generated
    (import "bsd.sb")
    (allow file-read* (subpath "/System"))
    (allow file-read* file-write* (subpath "/Users/me/easyops"))
    (allow file-read* (literal "/Users/me/.gitconfig"))
    (allow file-read* file-write* (literal "/dev/null"))
    (allow process-exec)
    (allow process-exec (literal "/usr/bin/git"))
    (allow network-outbound (remote tcp))
    (deny network-outbound (remote tcp "localhost:*"))
    (allow network-outbound (remote tcp "localhost:9910"))
    (allow mach-lookup (global-name "com.apple.system.notification_center"))
    (allow sysctl-read)
    (deny file-write* (subpath "/Users/me/.knodo/agent/bin"))
    """

    func run() throws -> ImportResult {
        try LegacyImporter.importInstallation(profileID: "knodo", allowlistJSON: allowlist, policySBPL: policy)
    }

    @Test func allowlistRootsBecomeDirectoryGrants() throws {
        let files = try run().profile.files
        #expect(files.contains(FileGrant(path: "/Users/me/easyops", kind: .directory, access: .readWrite)))
        #expect(files.contains(FileGrant(path: "/tmp", kind: .directory, access: .readWrite)))
        #expect(files.contains(FileGrant(path: "/Users/me/.ssh", kind: .directory, access: .readOnly)))
    }

    @Test func recognizedRulesAreConverted() throws {
        let profile = try run().profile
        #expect(profile.files.contains(FileGrant(path: "/System", kind: .directory, access: .readOnly)))
        #expect(profile.files.contains(FileGrant(path: "/Users/me/.gitconfig", kind: .file, access: .readOnly)))
        #expect(profile.files.contains(FileGrant(path: "/dev/null", kind: .file, access: .readWrite)))
        #expect(profile.exec == [ExecGrant(path: "/usr/bin/git")])
        #expect(profile.unrestrictedExec)
        #expect(profile.network.loopbackTCPConnect == [9910])
        #expect(profile.network.outboundTCP == .allowed)
    }

    @Test func otherAllowRulesArePreservedVerbatim() throws {
        #expect(try run().profile.extraRules == [
            "(allow mach-lookup (global-name \"com.apple.system.notification_center\"))",
            "(allow sysctl-read)",
        ])
    }

    @Test func importsAsRevisionOneInEnforceMode() throws {
        let profile = try run().profile
        #expect(profile.revision == 1)
        #expect(profile.mode == .enforce)
        #expect(profile.id == "knodo")
    }

    @Test func rulesThatCannotBeRepresentedAreReportedNotDropped() throws {
        #expect(try run().unimportedRules == ["(deny file-write* (subpath \"/Users/me/.knodo/agent/bin\"))"])
        #expect(try run().baseRules == ["(import \"bsd.sb\")"])
    }

    @Test func malformedAllowlistIsRejected() {
        #expect(throws: (any Error).self) {
            try LegacyImporter.importInstallation(profileID: "knodo", allowlistJSON: Data("{}".utf8), policySBPL: "")
        }
    }

    @Test func importedProfileCompiles() throws {
        var env = Fixtures.environment
        env.allowsNestedReadOnly = true
        _ = try PolicyCompiler(environment: env).compile(try run().profile, catalog: TemplateCatalog([]))
    }
}
