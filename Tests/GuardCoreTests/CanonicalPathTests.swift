import Testing
@testable import GuardCore

@Suite struct CanonicalPathTests {
    let resolver = AliasResolver.macOSDefault

    @Test func rejectsRelativePath() {
        #expect(throws: PathError.notAbsolute("a/b")) { try CanonicalPath("a/b", resolver: resolver) }
    }

    @Test func rejectsEmptyPath() {
        #expect(throws: PathError.empty) { try CanonicalPath("", resolver: resolver) }
    }

    @Test func rejectsNULCharacter() {
        #expect(throws: PathError.containsNUL) { try CanonicalPath("/a\u{0}b", resolver: resolver) }
    }

    @Test func collapsesDotsDuplicateSlashesAndTrailingSlash() throws {
        #expect(try CanonicalPath("/Users//me/./a/../b/", resolver: resolver).value == "/Users/me/b")
    }

    @Test func parentOfRootStaysAtRoot() throws {
        #expect(try CanonicalPath("/../..", resolver: resolver).value == "/")
    }

    @Test func resolvesMacOSFirmlinkAliases() throws {
        #expect(try CanonicalPath("/tmp/claude-501", resolver: resolver).value == "/private/tmp/claude-501")
        #expect(try CanonicalPath("/tmp", resolver: resolver).value == "/private/tmp")
        #expect(try CanonicalPath("/var/folders/x", resolver: resolver).value == "/private/var/folders/x")
        #expect(try CanonicalPath("/etc/hosts", resolver: resolver).value == "/private/etc/hosts")
    }

    @Test func aliasMatchesWholeComponentsOnly() throws {
        #expect(try CanonicalPath("/tmpfoo/x", resolver: resolver).value == "/tmpfoo/x")
    }

    @Test func aliasIsAppliedAfterLexicalNormalization() throws {
        let custom = AliasResolver(aliases: ["/Users/me/link": "/Volumes/data/real"])
        #expect(try CanonicalPath("/Users/me/link/x/../y", resolver: custom).value == "/Volumes/data/real/y")
        #expect(try CanonicalPath("/Users/me/x/../link", resolver: custom).value == "/Volumes/data/real")
    }

    @Test func longestAliasWins() throws {
        let custom = AliasResolver(aliases: ["/a": "/x", "/a/b": "/y"])
        #expect(try CanonicalPath("/a/b/c", resolver: custom).value == "/y/c")
        #expect(try CanonicalPath("/a/c", resolver: custom).value == "/x/c")
    }

    @Test func containmentIsComponentWise() throws {
        let parent = try CanonicalPath("/a/b", resolver: resolver)
        #expect(parent.contains(try CanonicalPath("/a/b/c", resolver: resolver), caseInsensitive: false))
        #expect(parent.contains(parent, caseInsensitive: false))
        #expect(!parent.contains(try CanonicalPath("/a/bc", resolver: resolver), caseInsensitive: false))
        #expect(!parent.contains(try CanonicalPath("/a", resolver: resolver), caseInsensitive: false))
    }

    @Test func rootContainsEverything() throws {
        let root = try CanonicalPath("/", resolver: resolver)
        #expect(root.contains(try CanonicalPath("/x/y", resolver: resolver), caseInsensitive: false))
    }

    @Test func caseInsensitiveContainment() throws {
        let parent = try CanonicalPath("/Users/Me/Docs", resolver: resolver)
        let child = try CanonicalPath("/users/me/docs/x", resolver: resolver)
        #expect(parent.contains(child, caseInsensitive: true))
        #expect(!parent.contains(child, caseInsensitive: false))
    }
}
