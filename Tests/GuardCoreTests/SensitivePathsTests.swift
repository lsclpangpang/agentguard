import Testing
@testable import GuardCore

@Suite struct SensitivePathsTests {
    let sensitive = SensitivePaths(home: "/Users/me")

    @Test(arguments: [
        "/Users/me/.ssh/id_ed25519", "/Users/me/.aws/credentials", "/Users/me/Library/Keychains/login.keychain-db",
        "/Users/me/Library/Application Support/Google/Chrome/Default/Cookies", "/Users/me/Documents/合同.pdf",
        "/Users/me/.claude/settings.json", "/Users/me/.claude/hooks/pre.sh", "/Users/me/.codex/auth.json",
        "/Users/me/.config/gh/hosts.yml", "/Users/me/Library/Messages/chat.db",
    ])
    func flagsSensitivePaths(path: String) {
        #expect(sensitive.isSensitive(path))
    }

    @Test(arguments: ["/Users/me/easyops/main.go", "/Users/me/.claude/projects/x.jsonl", "/opt/homebrew/lib/libssl.dylib", "/Users/me/.sshconfig"])
    func ignoresOrdinaryPaths(path: String) {
        #expect(!sensitive.isSensitive(path))
    }

    @Test func directoryContainingSensitivePathIsSensitive() {
        #expect(sensitive.overlapsSensitive("/Users/me/.claude"))
        #expect(sensitive.overlapsSensitive("/Users/me/Library"))
        #expect(!sensitive.overlapsSensitive("/Users/me/easyops"))
    }
}
