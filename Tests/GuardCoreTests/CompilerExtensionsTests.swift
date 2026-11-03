import Testing
@testable import GuardCore

@Suite struct CompilerExtensionsTests {
    typealias F = Fixtures

    @Test func stateDirectoryIsGrantedAutomaticallyWhenConfigured() throws {
        var env = F.environment
        env.stateRoot = "/Library/Application Support/AgentGuard State"
        let policy = try F.compile(F.profile(), environment: env)
        #expect(policy.files == [EffectiveFileGrant(path: "/Library/Application Support/AgentGuard State/knodo", kind: .directory, access: .readWrite, readsSecrets: false)])
        #expect(policy.stateDirectory == "/Library/Application Support/AgentGuard State/knodo")
    }

    @Test func profileIDMustBeSafeForPaths() {
        for bad in ["", "../x", "a/b", "A", "x y", String(repeating: "a", count: 65)] {
            var p = F.profile()
            p.id = bad
            #expect(throws: CompileError.invalidProfileID(bad)) { try F.compile(p) }
        }
    }

    @Test func unrestrictedExecIsRenderedAndFlagged() throws {
        let policy = try F.compile(F.profile(unrestrictedExec: true))
        #expect(policy.unrestrictedExec)
        let sbpl = SBPLRenderer(environment: F.environment).render(policy)
        #expect(sbpl.contains("\n(allow process-exec)\n"))
    }

    @Test func turningOnUnrestrictedExecExpands() throws {
        let d = PolicyDiff(from: try F.compile(F.profile()), to: try F.compile(F.profile(unrestrictedExec: true)))
        #expect(d.requiresAuthorization)
        #expect(d.summaryLines == ["+ 允许执行任意程序"])
        let back = PolicyDiff(from: try F.compile(F.profile(unrestrictedExec: true)), to: try F.compile(F.profile()))
        #expect(!back.requiresAuthorization)
    }

    @Test func extraRulesMustBeSingleAllowForms() throws {
        _ = try F.compile(F.profile(extraRules: ["(allow mach-lookup (global-name \"com.apple.system.logger\"))"]))
        for bad in ["(deny default)", "(allow default)", "(allow mach-lookup) (allow file-write*)", "(allow file-read*", "(allow x)\n(allow y)", "(import \"x.sb\")"] {
            #expect(throws: CompileError.invalidRawRule(bad)) { try F.compile(F.profile(extraRules: [bad])) }
        }
    }

    @Test func extraRulesAreSortedDeduplicatedAndRenderedBeforeBuiltinDenials() throws {
        let rule = "(allow sysctl-read)"
        let policy = try F.compile(F.profile(extraRules: [rule, rule, "(allow mach-lookup (global-name \"a\"))"]))
        #expect(policy.extraRules == ["(allow mach-lookup (global-name \"a\"))", rule])
        let lines = SBPLRenderer(environment: F.environment).render(policy).split(separator: "\n").map(String.init)
        let ruleIndex = try #require(lines.firstIndex(of: rule))
        let denyIndex = try #require(lines.firstIndex { $0.hasPrefix("(deny mach-lookup") })
        #expect(ruleIndex < denyIndex)
    }

    @Test func addingExtraRuleExpands() throws {
        let d = PolicyDiff(from: try F.compile(F.profile()), to: try F.compile(F.profile(extraRules: ["(allow sysctl-read)"])))
        #expect(d.requiresAuthorization)
        #expect(d.summaryLines == ["+ 原样规则 (allow sysctl-read)"])
    }

    @Test func baseRulesFollowDenyDefault() throws {
        var env = F.environment
        env.baseRules = ["(import \"bsd.sb\")"]
        let lines = SBPLRenderer(environment: env).render(try F.compile(F.profile(), environment: env)).split(separator: "\n").map(String.init)
        let deny = try #require(lines.firstIndex(of: "(deny default)"))
        #expect(lines[deny + 1] == "(import \"bsd.sb\")")
    }
}
