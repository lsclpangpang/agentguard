import Foundation
import Testing
@testable import GuardCore

@Suite struct ProcessControlTests {
    typealias F = Fixtures

    @Test func enablingIsExplicitIdempotentAndPreservesEveryOtherPermission() throws {
        let selfRule = "(allow signal (target self))"
        var profile = F.profile(files: [F.rw("/Users/me/work")],
                                network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed),
                                revision: 4, extraRules: [selfRule, "(allow process-fork)"])
        let original = profile
        #expect(!ProcessControl.isEnabled(in: profile))
        ProcessControl.enable(in: &profile)
        ProcessControl.enable(in: &profile)
        var expected = original
        expected.extraRules.append(ProcessControl.rule)
        #expect(profile == expected)
        #expect(ProcessControl.isEnabled(in: profile))
        #expect(try ProfileCodec.decode(ProfileCodec.encode(profile)) == profile)
        ProcessControl.disable(in: &profile)
        #expect(profile == original)
    }

    @Test func onlyTheExactScopedRuleIsRecognizedAndRevoked() {
        let formatted = "(allow  signal\n (target same-sandbox))"
        var profile = F.profile(extraRules: ["(allow signal)", "(allow signal (target self))",
                                            "(allow signal (target children))", formatted])
        #expect(ProcessControl.isEnabled(in: profile))
        ProcessControl.disable(in: &profile)
        #expect(profile.extraRules == ["(allow signal)", "(allow signal (target self))", "(allow signal (target children))"])
        #expect(!ProcessControl.isEnabled(in: profile))
    }

    @Test func scopedSignalRefusalsProduceOneSuggestionWithoutGuessingOtherTargets() throws {
        let engine = SuggestionEngine(home: "/Users/me", aggregationThreshold: 3, templates: [],
                                      resolver: AliasResolver(aliases: [:]), caseInsensitive: false)
        let targets = ["children [claude(67184)] signum:9", "same-sandbox [ssh(69508)] signum:15",
                       "others [Finder(300)] signum:9", "children-other [app(301)] signum:9", ""]
        let observations = targets.map { Observation(instance: 1, access: .signal(target: $0), denied: true) }
            + [Observation(instance: 1, access: .signal(target: targets[0]), denied: false)]
        let pending = engine.pendingItems(observations: observations, policy: try F.compile(F.profile()), enabledTemplates: [])
        let item = try #require(pending.first)
        #expect(pending.count == 1)
        #expect(item.suggestion == .processControl)
        #expect(item.denied == 2 && item.evidence == 2)
        #expect(item.samples == Array(targets.prefix(2)))
        #expect(try JSONDecoder().decode(PendingItem.self, from: JSONEncoder().encode(item)) == item)
        var allowed = F.profile()
        ProcessControl.enable(in: &allowed)
        #expect(engine.pendingItems(observations: observations, policy: try F.compile(allowed), enabledTemplates: []).isEmpty)
    }

    @Test func signalTargetsRemainVerbatimIncludingUnknownAndAbsentTargets() throws {
        for target in ["children [claude(67184)] signum:9", "others [Finder(300)] signum:9", ""] {
            let suffix = target.isEmpty ? "" : " " + target
            let denial = try #require(SandboxLogParser.parse("Sandbox: agent(20) deny(1) signal\(suffix)"))
            #expect(denial.access == .signal(target: target))
            let observation = Observation(instance: 1, access: try #require(denial.access), denied: true,
                                          processName: denial.process, pid: denial.pid)
            #expect(!observation.isNetwork)
            #expect(observation.summary.contains(target.isEmpty ? "系统未提供目标" : target))
            #expect(try JSONDecoder().decode(Observation.self, from: JSONEncoder().encode(observation)) == observation)
        }
    }

    @Test func enablingStillRequiresAuthorizationAndReportsItsFullScope() throws {
        let original = F.profile(extraRules: ["(allow signal (target self))"])
        var enabled = original
        ProcessControl.enable(in: &enabled)
        let before = try F.compile(original), after = try F.compile(enabled)
        let added = PolicyDiff(from: before, to: after)
        #expect(added.requiresAuthorization)
        #expect(added.changes == [.extraRuleAdded(ProcessControl.rule)])
        #expect(added.summaryLines == ["+ \(ProcessControl.title)：\(ProcessControl.detail)"])
        #expect(!added.summaryLines.joined().contains("(allow"))
        let revoked = PolicyDiff(from: after, to: before)
        #expect(!revoked.requiresAuthorization)
        #expect(revoked.summaryLines == ["- \(ProcessControl.title)（撤回此项显式授权）"])
        #expect(revoked.digest != added.digest)
        #expect(SBPLRenderer(environment: F.environment).render(after).contains(ProcessControl.rule))
        let summary = LegacyPermissionSummary(rules: [ProcessControl.rule, "(allow signal)"])
        #expect(summary.items.first?.title == ProcessControl.title)
        #expect(summary.items.first?.detail == ProcessControl.detail)
        #expect(summary.unknown == ["(allow signal)"])
    }
}
