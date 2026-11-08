import Foundation
import Testing
@testable import GuardCore

@Suite struct SystemDNSTests {
    typealias F = Fixtures

    @Test func oldProfilesKeepTheirExistingRulesUntilAnExplicitChoice() throws {
        let json = #"{"id":"knodo","revision":1,"mode":"enforce","templates":[],"files":[],"exec":[],"network":{"loopback_tcp_connect":[],"outbound_tcp":"denied","listen":"denied","udp":"denied"}}"#
        let profile = try ProfileCodec.decode(Data(json.utf8))
        #expect(profile.network.systemDNS == nil)
        #expect(!String(decoding: try ProfileCodec.encode(profile), as: UTF8.self).contains("system_dns"))
        let rendered = SBPLRenderer(environment: F.environment).render(try F.compile(profile))
        #expect(!rendered.contains(SystemDNS.socketPath))
    }

    @Test(arguments: [Toggle.allowed, .denied])
    func explicitChoicesSurviveExportAndImport(choice: Toggle) throws {
        let profile = F.profile(network: NetworkPolicy(systemDNS: choice))
        let encoded = try ProfileCodec.encode(profile)
        #expect(try ProfileCodec.decode(encoded) == profile)
        #expect(String(decoding: encoded, as: UTF8.self).contains("\"system_dns\""))
    }

    @Test func onlyTheExactDNSConnectionCreatesASuggestion() throws {
        let engine = SuggestionEngine(home: "/Users/me", aggregationThreshold: 3, templates: [],
                                      resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        func observation(_ path: String, _ operation: String = "network-outbound") -> Observation {
            Observation(instance: 1, access: .unixSocket(path: path, operation: operation), denied: true)
        }
        let observations = [
            observation(SystemDNS.socketPath), observation("/var/run/mDNSResponder"),
            observation(SystemDNS.socketPath + "-other"), observation("/private/tmp/other.sock"),
            observation(SystemDNS.socketPath, "network-bind"),
            observation("/var/run/../run/mDNSResponder-other"),
        ]
        let pending = engine.pendingItems(observations: observations, policy: try F.compile(F.profile()), enabledTemplates: [])
        #expect(pending.count == 1)
        let item = try #require(pending.first)
        #expect(item.suggestion == .systemDNS)
        #expect(item.denied == 2 && item.evidence == 2)
        #expect(item.samples == [SystemDNS.socketPath])
        #expect(try JSONDecoder().decode(PendingItem.self, from: JSONEncoder().encode(item)) == item)
        let allowed = try F.compile(F.profile(network: NetworkPolicy(systemDNS: .allowed)))
        #expect(engine.pendingItems(observations: observations, policy: allowed, enabledTemplates: []).isEmpty)
        let denied = try F.compile(F.profile(network: NetworkPolicy(systemDNS: .denied)))
        #expect(engine.pendingItems(observations: observations, policy: denied, enabledTemplates: []).map(\.suggestion) == [.systemDNS])
    }

    @Test func approvalDigestAndTighteningIncludeTheServiceChoice() throws {
        func policy(_ value: Toggle?) throws -> EffectivePolicy {
            try F.compile(F.profile(network: NetworkPolicy(systemDNS: value)))
        }
        let enable = PolicyDiff(from: try policy(nil), to: try policy(.allowed))
        #expect(enable.requiresAuthorization)
        #expect(enable.changes == [.systemDNSChanged(from: nil, to: .allowed)])
        #expect(enable.summaryLines.joined().contains(SystemDNS.socketPath))
        let revoke = PolicyDiff(from: try policy(.allowed), to: try policy(.denied))
        #expect(!revoke.requiresAuthorization)
        #expect(revoke.digest != enable.digest)
        let removeDenial = PolicyDiff(from: try policy(.denied), to: try policy(nil))
        #expect(removeDenial.requiresAuthorization)
    }

    @Test func serviceRuleIsExactAndExplicitDenialOverridesLegacyAllows() throws {
        let allow = "(allow network-outbound (literal \"\(SystemDNS.socketPath)\"))"
        let deny = "(deny network-outbound (literal \"\(SystemDNS.socketPath)\"))"
        let renderer = SBPLRenderer(environment: F.environment)
        let added = renderer.render(try F.compile(F.profile(network: NetworkPolicy(systemDNS: .allowed))))
        #expect(added.contains(allow))
        #expect(!added.contains("(remote tcp") && !added.contains("(remote udp"))
        #expect(!added.contains("(allow network-bind"))
        #expect(!added.contains("(allow file-read* (literal \"\(SystemDNS.socketPath)\"))"))
        let legacy = "(allow network*)"
        let revoked = renderer.render(try F.compile(F.profile(network: NetworkPolicy(systemDNS: .denied), extraRules: [legacy])))
        let legacyRange = try #require(revoked.range(of: legacy))
        let denialRange = try #require(revoked.range(of: deny))
        #expect(legacyRange.upperBound < denialRange.lowerBound)
    }

    @Test func runtimeChecksVerifyBothAllowAndRevocation() throws {
        for choice in [Toggle.allowed, .denied] {
            let policy = try F.compile(F.profile(network: NetworkPolicy(systemDNS: choice)))
            let check = try #require(SandboxVerification.expectations(for: policy, environment: F.environment)
                .first { $0.operation == .unixConnect })
            #expect(check.target == SystemDNS.socketPath && check.allowed == (choice == .allowed))
        }
        let unspecified = try F.compile(F.profile())
        #expect(!SandboxVerification.expectations(for: unspecified, environment: F.environment).contains { $0.operation == .unixConnect })
        let unprotected = try F.compile(F.profile(network: NetworkPolicy(systemDNS: .denied), mode: .unprotectedObserve))
        #expect(!SandboxVerification.expectations(for: unprotected, environment: F.environment).contains { $0.operation == .unixConnect })
    }
}
