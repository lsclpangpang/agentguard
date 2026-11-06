import Foundation
import Testing
@testable import GuardCore

@Suite struct PathPatternTests {
    typealias F = Fixtures
    let resolver = AliasResolver.macOSDefault

    func pattern(_ raw: String) throws -> PathPattern { try PathPattern(raw, resolver: resolver) }
    func path(_ raw: String) -> CanonicalPath { try! CanonicalPath(raw, resolver: resolver) }

    @Test func splitsAtTheFirstWildcardAndCanonicalizesTheBase() throws {
        let p = try pattern("/tmp/logs/*/run-?.log")
        #expect(p.base == path("/private/tmp/logs"))
        #expect(p.rest == ["*", "run-?.log"])
        #expect(p.value == "/private/tmp/logs/*/run-?.log")
    }

    @Test func rejectsWhatIsNotAPattern() {
        #expect(throws: PatternError.noWildcard("/Users/me/docs")) { try pattern("/Users/me/docs") }
        #expect(throws: PatternError.invalidComponent("a**")) { try pattern("/Users/me/a**/x") }
        #expect(throws: PatternError.invalidComponent(#"/Users/me/"*"#)) { try pattern(#"/Users/me/"*"#) }
        #expect(throws: PatternError.path(.notAbsolute("x*"))) { try pattern("x*") }
    }

    @Test func refusesWildcardsRightBelowRootOrHome() throws {
        let home = path("/Users/me")
        #expect(throws: PatternError.tooBroad("/Users/me/*")) { try pattern("/Users/me/*").validateBreadth(home: home, caseInsensitive: true) }
        #expect(throws: PatternError.tooBroad("/*/x")) { try pattern("/*/x").validateBreadth(home: home, caseInsensitive: true) }
        #expect(throws: PatternError.tooBroad("/**/x")) { try pattern("/**/x").validateBreadth(home: home, caseInsensitive: true) }
        try pattern("/Users/me/.claude*.jsonl").validateBreadth(home: home, caseInsensitive: true)
    }

    @Test func matchesWithinOneComponentOrAnyDepth() throws {
        let p = try pattern("/Users/me/.claude*.jsonl")
        #expect(p.matches(path("/Users/me/.claude.jsonl"), caseInsensitive: true))
        #expect(p.matches(path("/Users/me/.claude-backup.jsonl"), caseInsensitive: true))
        #expect(!p.matches(path("/Users/me/.claude/x.jsonl"), caseInsensitive: true))
        let deep = try pattern("/Users/me/.claude/projects/**/*.jsonl")
        #expect(deep.matches(path("/Users/me/.claude/projects/a.jsonl"), caseInsensitive: true))
        #expect(deep.matches(path("/Users/me/.claude/projects/p/q/a.jsonl"), caseInsensitive: true))
        #expect(!deep.matches(path("/Users/me/.claude/projects/p/a.json"), caseInsensitive: true))
    }

    @Test func reachDecidesProtectedOverlap() throws {
        let launchAgents = path("/Users/me/Library/LaunchAgents")
        #expect(try pattern("/Users/me/Lib*/LaunchAgents/*.plist").mayReachInside(launchAgents, kind: .file, caseInsensitive: true))
        #expect(try pattern("/Users/me/Lib*").mayReachInside(launchAgents, kind: .directory, caseInsensitive: true))
        #expect(!(try pattern("/Users/me/Lib*").mayReachInside(launchAgents, kind: .file, caseInsensitive: true)))
        #expect(!(try pattern("/Users/me/.claude*.jsonl").mayReachInside(launchAgents, kind: .directory, caseInsensitive: true)))
    }

    @Test func regexMatchesTheGrantExactly() throws {
        #expect(try pattern("/Users/me/.claude*.jsonl").regex(kind: .file) == #"^/Users/me/\.claude[^/]*\.jsonl$"#)
        #expect(try pattern("/Users/me/p/**/b?").regex(kind: .directory) == #"^/Users/me/p(/[^/]+)*/b[^/](/.*)?$"#)
        #expect(try pattern("/Users/me/.claude*.jsonl").sample == "/Users/me/.claudex.jsonl")
    }

    @Test func compilesToARegexRule() throws {
        let grant = FileGrant(path: "/Users/me/.claude*.jsonl", kind: .file, access: .readWrite, pattern: true)
        let policy = try F.compile(F.profile(files: [grant, F.ro("/Users/me/docs")]))
        #expect(policy.files.map(\.path) == ["/Users/me/docs"])
        #expect(policy.patterns.map(\.pattern) == ["/Users/me/.claude*.jsonl"])
        let sbpl = SBPLRenderer(environment: F.environment).render(policy)
        #expect(sbpl.contains(#"(allow file-read* file-write* (regex #"^/Users/me/\.claude[^/]*\.jsonl$"))"#))
    }

    @Test func compilerAppliesTheUsualBoundaries() {
        let intoProtected = FileGrant(path: "/Library/Application Support/Agent*/x", kind: .file, access: .readOnly, pattern: true)
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Library/Application Support/Agent*/x", protected: "/Library/Application Support/AgentGuard")) {
            try F.compile(F.profile(files: [intoProtected]))
        }
        let writableApp = FileGrant(path: "/Applications/Agent*.app", kind: .directory, access: .readWrite, pattern: true)
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Applications/Agent*.app", protected: "/Applications/AgentGuard.app")) {
            try F.compile(F.profile(files: [writableApp]))
        }
        let readOnlyInside = FileGrant(path: "/Users/me/work/*.lock", kind: .file, access: .readOnly, pattern: true)
        #expect(throws: CompileError.nestedReadOnlyInsideReadWrite(inner: "/Users/me/work/*.lock", outer: "/Users/me/work")) {
            try F.compile(F.profile(files: [F.rw("/Users/me/work"), readOnlyInside]))
        }
        let broad = FileGrant(path: "/Users/me/*", kind: .file, access: .readOnly, pattern: true)
        #expect(throws: CompileError.invalidPattern("/Users/me/*", .tooBroad("/Users/me/*"))) { try F.compile(F.profile(files: [broad])) }
    }

    @Test func writablePatternMakesMatchingExecutablesMutable() {
        let grant = FileGrant(path: "/Users/me/bin/*", kind: .file, access: .readWrite, pattern: true)
        #expect(throws: CompileError.mutableExecutableWithoutHash("/Users/me/bin/tool")) {
            try F.compile(F.profile(files: [grant], exec: [ExecGrant(path: "/Users/me/bin/tool")]))
        }
    }

    @Test func addingAPatternIsAnExpansionWithItsOwnSummary() throws {
        let grant = FileGrant(path: "/Users/me/.claude*.jsonl", kind: .file, access: .readOnly, pattern: true)
        let diff = PolicyDiff(from: try F.compile(F.profile()), to: try F.compile(F.profile(files: [grant])))
        #expect(diff.requiresAuthorization)
        #expect(diff.summaryLines == ["+ 只读通配文件 /Users/me/.claude*.jsonl"])
        var writable = grant
        writable.access = .readWrite
        let widen = PolicyDiff(from: try F.compile(F.profile(files: [grant])), to: try F.compile(F.profile(files: [writable])))
        #expect(widen.requiresAuthorization)
        #expect(widen.summaryLines == ["~ 通配文件 /Users/me/.claude*.jsonl：只读 → 读写"])
    }

    @Test func patternFlagRoundTripsAndStaysOutOfPlainGrants() throws {
        let grant = FileGrant(path: "/Users/me/.claude*.jsonl", kind: .file, access: .readOnly, pattern: true)
        let profile = F.profile(files: [grant, F.ro("/Users/me/docs")])
        #expect(try ProfileCodec.decode(ProfileCodec.encode(profile)) == profile)
        let plain = String(decoding: try ProfileCodec.encode(F.profile(files: [F.ro("/Users/me/docs")])), as: UTF8.self)
        #expect(!plain.contains("pattern"))
    }

    @Test func observedMatchesAreNotSuggestedAgain() throws {
        let grant = FileGrant(path: "/Users/me/.claude*.jsonl", kind: .file, access: .readWrite, pattern: true)
        let policy = try F.compile(F.profile(files: [grant]))
        let engine = SuggestionEngine(home: "/Users/me", aggregationThreshold: 20, templates: [], resolver: resolver, caseInsensitive: true)
        let items = engine.pendingItems(observations: [
            Observation(instance: 1, access: .write("/Users/me/.claude-1.jsonl"), denied: true),
            Observation(instance: 1, access: .read("/Users/me/other.txt"), denied: true),
        ], policy: policy, enabledTemplates: [])
        #expect(items.map(\.samples) == [["/Users/me/other.txt"]])
    }

    @Test func verificationProbesASampleMatch() throws {
        let grant = FileGrant(path: "/Users/me/.claude*.jsonl", kind: .file, access: .readOnly, pattern: true)
        let expectations = SandboxVerification.expectations(for: try F.compile(F.profile(files: [grant])), environment: F.environment)
        #expect(expectations.contains(SandboxExpectation(operation: .fileWrite, target: "/Users/me/.claudex.jsonl", allowed: false,
                                                          failure: "设为仅查看的通配授权 /Users/me/.claude*.jsonl 仍可写入，可能来自旧规则或其他重叠授权")))
    }

    @Test func sensitivityLooksAtEverythingThePatternReaches() throws {
        let sensitive = SensitivePaths(home: "/Users/me")
        #expect(sensitive.overlapsSensitive(try pattern("/Users/me/.ss?/*"), kind: .file, caseInsensitive: true))
        #expect(!sensitive.overlapsSensitive(try pattern("/Users/me/.claude*.jsonl"), kind: .file, caseInsensitive: true))
    }

    @Test func mergerKeepsPatternsAsWritten() throws {
        let grant = FileGrant(path: "/Users/me/work/*.log", kind: .file, access: .readOnly, pattern: true)
        let merged = try FileGrantMerger.normalize([grant, F.ro("/Users/me/docs"), grant], resolver: resolver, caseInsensitive: true)
        #expect(merged == [F.ro("/Users/me/docs"), grant])
    }
}
