import Testing
@testable import GuardCore

@Suite struct SBPLRendererTests {
    typealias F = Fixtures

    func render(_ profile: Profile) throws -> [String] {
        let policy = try F.compile(profile)
        return SBPLRenderer(environment: F.environment).render(policy).split(separator: "\n").map(String.init)
    }

    func index(of line: String, in lines: [String], sourceLocation: SourceLocation = #_sourceLocation) -> Int {
        let i = lines.firstIndex(of: line)
        #expect(i != nil, "missing line: \(line)", sourceLocation: sourceLocation)
        return i ?? -1
    }

    @Test func enforcedProfileDeniesByDefault() throws {
        let lines = try render(F.profile())
        #expect(lines.first == "(version 1)")
        #expect(lines.contains("(deny default)"))
        #expect(!lines.contains("(allow default)"))
    }

    @Test func restrictedLearningAlsoDeniesByDefault() throws {
        let lines = try render(F.profile(mode: .restrictedLearning))
        #expect(lines.contains("(deny default)"))
    }

    @Test func headerNamesProfileAndRevision() throws {
        let lines = try render(F.profile(revision: 4))
        #expect(lines.contains(";; agentguard profile knodo revision 4"))
    }

    @Test func rendersDirectoryGrantsAsSubpaths() throws {
        let lines = try render(F.profile(files: [F.ro("/Users/me/docs"), F.rw("/Users/me/easyops")]))
        _ = index(of: "(allow file-read* (subpath \"/Users/me/docs\"))", in: lines)
        _ = index(of: "(allow file-read* file-write* (subpath \"/Users/me/easyops\"))", in: lines)
    }

    @Test func rendersFileGrantsAsLiterals() throws {
        let lines = try render(F.profile(files: [F.roFile("/Users/me/.gitconfig")]))
        _ = index(of: "(allow file-read* (literal \"/Users/me/.gitconfig\"))", in: lines)
    }

    @Test func rendersExecAllowListWithoutUnconditionalExec() throws {
        let lines = try render(F.profile(exec: [ExecGrant(path: "/opt/homebrew/bin/python3.13")]))
        _ = index(of: "(allow process-exec (literal \"/opt/homebrew/bin/python3.13\"))", in: lines)
        #expect(!lines.contains("(allow process-exec)"))
        #expect(!lines.contains("(allow process-exec*)"))
    }

    @Test func loopbackPortAllowsComeAfterLocalhostDeny() throws {
        let lines = try render(F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed)))
        let general = index(of: "(allow network-outbound (remote tcp))", in: lines)
        let deny = index(of: "(deny network-outbound (remote tcp \"localhost:*\"))", in: lines)
        let port = index(of: "(allow network-outbound (remote tcp \"localhost:9910\"))", in: lines)
        #expect(general < deny)
        #expect(deny < port)
    }

    @Test func deniedOutboundOmitsGeneralTCP() throws {
        let lines = try render(F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .denied)))
        #expect(!lines.contains("(allow network-outbound (remote tcp))"))
        _ = index(of: "(allow network-outbound (remote tcp \"localhost:9910\"))", in: lines)
    }

    @Test func listenIsDeniedUnlessAllowed() throws {
        let denied = try render(F.profile())
        #expect(!denied.contains("(allow network-bind)"))
        let allowed = try render(F.profile(network: NetworkPolicy(listen: .allowed)))
        _ = index(of: "(allow network-bind (local tcp))", in: allowed)
    }

    @Test func builtinDeniesComeAfterEveryAllow() throws {
        let lines = try render(F.profile(files: [F.ro("/Library")], exec: [ExecGrant(path: "/usr/bin/git")], network: NetworkPolicy(loopbackTCPConnect: [9910])))
        let lastAllow = lines.lastIndex { $0.hasPrefix("(allow") } ?? -1
        let writeDeny = index(of: "(deny file-write* (subpath \"/Library/Application Support/AgentGuard\"))", in: lines)
        let machDeny = index(of: "(deny mach-lookup (global-name \"com.example.agentguard.helper\"))", in: lines)
        #expect(lastAllow < writeDeny)
        #expect(lastAllow < machDeny)
    }

    @Test func unprotectedObserveAllowsDefaultButKeepsBuiltinDenies() throws {
        let lines = try render(F.profile(mode: .unprotectedObserve))
        let allowDefault = index(of: "(allow default)", in: lines)
        let machDeny = index(of: "(deny mach-lookup (global-name \"com.example.agentguard.helper\"))", in: lines)
        #expect(!lines.contains("(deny default)"))
        #expect(allowDefault < machDeny)
    }

    @Test func escapesQuotesAndBackslashes() throws {
        let lines = try render(F.profile(files: [F.ro("/Users/me/a\"b\\c")]))
        _ = index(of: "(allow file-read* (subpath \"/Users/me/a\\\"b\\\\c\"))", in: lines)
    }
}
