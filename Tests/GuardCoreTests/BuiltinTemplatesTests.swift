import Testing
@testable import GuardCore

@Suite struct BuiltinTemplatesTests {
    let context = TemplateContext(home: "/Users/me", uid: 501, homebrewPrefix: "/opt/homebrew")

    @Test func idsAreUniqueAndVersioned() {
        let templates = BuiltinTemplates.all(context)
        #expect(Set(templates.map(\.id)).count == templates.count)
        #expect(templates.allSatisfy { $0.version >= 1 })
        #expect(Set(templates.map(\.id)) == ["system-base", "claude-code", "codex", "homebrew-python", "git"])
    }

    @Test func everyTemplateCompilesOnItsOwnAndAllTogether() throws {
        let templates = BuiltinTemplates.all(context)
        for template in templates {
            _ = try Fixtures.compile(Fixtures.profile(templates: [TemplateRef(id: template.id, version: template.version)]), templates: templates)
        }
        _ = try Fixtures.compile(Fixtures.profile(templates: templates.map { TemplateRef(id: $0.id, version: $0.version) }), templates: templates)
    }

    @Test func claudeTemplateUsesPerUserTempDirectoryAndKeepsSettingsReadOnly() throws {
        let claude = try #require(BuiltinTemplates.all(context).first { $0.id == "claude-code" })
        #expect(claude.files.contains(FileGrant(path: "/private/tmp/claude-501", kind: .directory, access: .readWrite)))
        #expect(!claude.files.contains { $0.access == .readWrite && $0.path == "/Users/me/.claude" })
        #expect(claude.files.contains { $0.path == "/Users/me/.claude" && $0.access == .readOnly })
    }

    @Test func gitTemplateMarksSSHAsSecrets() throws {
        let git = try #require(BuiltinTemplates.all(context).first { $0.id == "git" })
        #expect(git.files.contains(FileGrant(path: "/Users/me/.ssh", kind: .directory, access: .readOnly, readsSecrets: true)))
        #expect(git.exec.contains(ExecGrant(path: "/usr/bin/git")))
    }

    @Test func homebrewPrefixIsSubstituted() throws {
        let intel = TemplateContext(home: "/Users/me", uid: 501, homebrewPrefix: "/usr/local")
        let python = try #require(BuiltinTemplates.all(intel).first { $0.id == "homebrew-python" })
        #expect(python.files.allSatisfy { $0.path.hasPrefix("/usr/local") })
        #expect(python.exec.allSatisfy { $0.path.hasPrefix("/usr/local") })
    }
}
