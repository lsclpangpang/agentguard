import Testing
@testable import GuardCore

@Suite struct LegacyRulesTests {
    let resolver = AliasResolver.macOSDefault

    func analysis(_ rules: [String]) -> LegacyRuleAnalysis {
        LegacyRuleAnalysis(rules: rules, resolver: resolver, caseInsensitive: true)
    }

    @Test func classifiesRules() {
        let a = analysis([
            #"(allow file-write* (subpath "/Users/me/docs"))"#,
            #"(allow file-read-data (literal "/tmp/x"))"#,
            #"(allow file-write-data (regex #"^/Users/me/.*\.log$"))"#,
            #"(allow mach-lookup (global-name "com.apple.x"))"#,
            #"(allow file-read* (home-subpath "/x"))"#,
        ])
        #expect(a.fileRules.map(\.access) == [.readWrite, .readOnly])
        #expect(a.fileRules[1].matches == [.literal(try! CanonicalPath("/private/tmp/x", resolver: resolver))])
        #expect(a.other == [#"(allow mach-lookup (global-name "com.apple.x"))"#])
        #expect(a.unverified.count == 2)
    }

    @Test func unfilteredFileRuleReachesEverything() {
        let a = analysis(["(allow file-write*)"])
        #expect(a.rulesAbove(try! CanonicalPath("/Users/me/docs", resolver: resolver), access: .readWrite) == ["(allow file-write*)"])
    }

    @Test func downgradeDropsWriteRulesAtOrBelowThePath() throws {
        let rules = [
            #"(allow file-write* (subpath "/Users/me/docs/build"))"#,
            #"(allow file-read* (subpath "/Users/me/docs/notes"))"#,
            #"(allow file-write* (prefix "/Users/me/docs"))"#,
            #"(allow file-write* (subpath "/Users/me/other"))"#,
        ]
        let result = try LegacyRevocation.revoke("/Users/me/docs", keeping: .readOnly, from: rules, resolver: resolver, caseInsensitive: true)
        #expect(result.removed == [rules[0]])
        // `(prefix "/Users/me/docs")` also covers /Users/me/docs2, so it cannot be dropped for this path alone.
        #expect(result.stillGranting == [rules[2]])
        #expect(result.extraRules == [rules[1], rules[2], rules[3]])
    }

    @Test func removalDropsEveryRuleBelowAndReportsParents() throws {
        let rules = [
            #"(allow file-read* (subpath "/Users/me/docs/notes"))"#,
            #"(allow file-read* (subpath "/Users/me"))"#,
            #"(allow file-write-data (regex #"^/x"))"#,
        ]
        let result = try LegacyRevocation.revoke("/Users/me/docs", keeping: nil, from: rules, resolver: resolver, caseInsensitive: true)
        #expect(result.removed == [rules[0]])
        #expect(result.stillGranting == [rules[1], rules[2]])
    }

    @Test func readRuleAboveDoesNotBlockADowngrade() throws {
        let rules = [#"(allow file-read* (subpath "/Users/me"))"#]
        let result = try LegacyRevocation.revoke("/Users/me/docs", keeping: .readOnly, from: rules, resolver: resolver, caseInsensitive: true)
        #expect(result.removed.isEmpty)
        #expect(result.stillGranting.isEmpty)
    }

    @Test func readerHandlesStringsAndRejectsGarbage() {
        #expect(SExpression.parse(#"(allow file-read* (literal "/a \"b\""))"#)
                == .list([.atom("allow"), .atom("file-read*"), .list([.atom("literal"), .string(#"/a "b""#)])]))
        #expect(SExpression.parse("(allow file-read*") == nil)
        #expect(SExpression.parse("(allow) (allow)") == nil)
    }
}
