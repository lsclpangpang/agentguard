import Foundation
import Testing
@testable import GuardCore

@Suite struct NetworkEndpointTests {
    @Test func literalAddressDoesNotInventProtocolOrURL() {
        let endpoint = NetworkEndpoint("203.0.113.10:443")
        #expect(endpoint.host == "203.0.113.10")
        #expect(endpoint.port == 443)
        #expect(endpoint.address == "203.0.113.10:443")
        #expect(endpoint.hostname == nil)
        #expect(endpoint.url == nil)
        #expect(endpoint.transport == nil)
    }

    @Test func realMacOSWildcardPreservesPortWithoutInventingHost() throws {
        let denial = try #require(SandboxLogParser.parse("Sandbox: codex(46505) deny(1) network-outbound remote:*:7897"))
        let endpoint = try #require(denial.networkEndpoint)
        #expect(denial.access == .connectRemote)
        #expect(endpoint.rawValue == "remote:*:7897")
        #expect(endpoint.port == 7897)
        #expect(endpoint.host == nil && endpoint.hostname == nil && endpoint.url == nil)
        #expect(endpoint.address == "目标地址未提供")
        #expect(!endpoint.isLoopback)
    }

    @Test func localDNSSocketIsNotAnInternetDestination() throws {
        let denial = try #require(SandboxLogParser.parse("Sandbox: knodo-agentd(46218) deny(1) network-outbound /private/var/run/mDNSResponder"))
        #expect(denial.access == .unixSocket(path: "/private/var/run/mDNSResponder", operation: "network-outbound"))
        #expect(denial.networkEndpoint?.socketPath == "/private/var/run/mDNSResponder")
        #expect(denial.networkEndpoint?.port == nil)
        #expect(denial.networkEndpoint?.transport == "Unix 套接字")
    }

    @Test func ipv6AddressesKeepTheirBracketsAndPort() {
        let endpoint = NetworkEndpoint("remote:[2001:db8::7]:8443")
        #expect(endpoint.host == "2001:db8::7")
        #expect(endpoint.port == 8443)
        #expect(endpoint.address == "[2001:db8::7]:8443")
        #expect(endpoint.hostname == nil)
        #expect(NetworkEndpoint("2001:db8::7").port == nil)
    }

    @Test func hostnameURLAndTransportAreShownOnlyWhenProvided() {
        let hostname = NetworkEndpoint("api.example.com:8443")
        #expect(hostname.hostname == "api.example.com")
        #expect(hostname.url == nil)
        let url = NetworkEndpoint("https://api.example.com:8443/v1/messages?mode=stream")
        #expect(url.host == "api.example.com")
        #expect(url.port == 8443)
        #expect(url.url == "https://api.example.com:8443/v1/messages?mode=stream")
        #expect(url.transport == nil)
        #expect(NetworkEndpoint("https://api.example.com/v1").port == nil)
        #expect(NetworkEndpoint("tcp 203.0.113.10:443").transport == "TCP")
        #expect(NetworkEndpoint("udp://[2001:db8::7]:53").transport == "UDP")
        #expect(NetworkEndpoint("tcp://*:7897").hostname == nil)
    }

    @Test(arguments: ["x:-1", "x:65536", "x:abc", "x:443 trailing", "x:", ":443"])
    func malformedPortIsNotPresentedAsAValidEndpoint(raw: String) {
        #expect(NetworkEndpoint(raw).port == nil)
        #expect(SandboxLogParser.parse("Sandbox: x(3) deny(1) network-outbound \(raw)")?.access == nil)
    }

    @Test func loopbackClassificationChecksAddressInsteadOfHostnamePrefix() {
        #expect(NetworkEndpoint("remote:[::1]:8080").isLoopback)
        #expect(NetworkEndpoint("[::ffff:127.0.0.1]:8080").isLoopback)
        #expect(NetworkEndpoint("127.0.0.2:8080").isLoopback)
        #expect(!NetworkEndpoint("127.example.com:8080").isLoopback)
        #expect(!NetworkEndpoint("127.999.0.1:8080").isLoopback)
    }

    @Test func oldObservationDecodesWithExplicitUnknownDestination() throws {
        let old = try JSONDecoder().decode(Observation.self, from: Data(#"{"instance":1,"access":{"connectRemote":{}},"denied":true,"count":1}"#.utf8))
        #expect(old.networkTarget == nil && old.pid == nil && old.processName == nil)
        #expect(old.summary == "对外连接 目标地址未记录")
        let loopback = Observation(instance: 1, access: .connectLoopback(9910), denied: true)
        #expect(loopback.networkPort == 9910)
    }

    @Test func transportAndSocketObservationsDoNotProposeUnrelatedPermissions() throws {
        let engine = SuggestionEngine(home: "/Users/me", aggregationThreshold: 3, templates: [],
                                      resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        let observations = [
            Observation(instance: 1, access: .connectRemote, denied: true, networkTarget: "udp 203.0.113.10:53"),
            Observation(instance: 1, access: .connectLoopback(53), denied: true, networkTarget: "udp 127.0.0.1:53"),
            Observation(instance: 1, access: .listen(53), denied: true, networkTarget: "udp 0.0.0.0:53"),
            Observation(instance: 1, access: .unixSocket(path: "/private/var/run/mDNSResponder", operation: "network-outbound"),
                        denied: true, networkTarget: "/private/var/run/mDNSResponder"),
        ]
        #expect(engine.pendingItems(observations: observations, policy: try Fixtures.compile(Fixtures.profile()), enabledTemplates: []).isEmpty)
        #expect(observations.last?.summary == "连接本机套接字 /private/var/run/mDNSResponder")
    }
}
