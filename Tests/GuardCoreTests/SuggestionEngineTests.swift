import Testing
@testable import GuardCore

@Suite struct SuggestionEngineTests {
    typealias F = Fixtures

    let python = Template(id: "homebrew-python", version: 1, files: [Fixtures.ro("/opt/homebrew/Cellar")], exec: [ExecGrant(path: "/opt/homebrew/bin/python3")], loopbackPorts: [])

    func engine(threshold: Int = 3) -> SuggestionEngine {
        SuggestionEngine(home: "/Users/me", aggregationThreshold: threshold, templates: [python], resolver: AliasResolver.macOSDefault, caseInsensitive: true)
    }

    func items(_ observations: [Observation], policy: Profile = Fixtures.profile(), enabled: Set<String> = []) throws -> [PendingItem] {
        engine().pendingItems(observations: observations, policy: try F.compile(policy), enabledTemplates: enabled)
    }

    func obs(_ access: ObservedAccess, count: Int = 1) -> Observation { Observation(instance: 1, access: access, denied: true, count: count) }

    @Test func coveredAccessProducesNothing() throws {
        let result = try items([obs(.read("/Users/me/easyops/a")), obs(.write("/Users/me/easyops/b"))], policy: F.profile(files: [F.rw("/Users/me/easyops")]))
        #expect(result.isEmpty)
    }

    @Test func writeUnderReadOnlyGrantIsStillPending() throws {
        let result = try items([obs(.write("/Users/me/docs/a"))], policy: F.profile(files: [F.ro("/Users/me/docs")]))
        #expect(result.map(\.suggestion) == [.file(path: "/Users/me/docs/a", kind: .file, access: .readWrite)])
    }

    @Test func systemPathsAreFolded() throws {
        #expect(try items([obs(.read("/System/Library/Frameworks/x")), obs(.read("/usr/lib/libz.dylib")), obs(.read("/dev/null"))]).isEmpty)
    }

    @Test func pathsAreCanonicalized() throws {
        let result = try items([obs(.write("/tmp/claude-501/x"))])
        #expect(result.map(\.suggestion) == [.file(path: "/private/tmp/claude-501/x", kind: .file, access: .readWrite)])
    }

    @Test func manyFilesInOneDirectoryAggregate() throws {
        let observations = (1...3).map { obs(.read("/Users/me/data/f\($0)")) } + [obs(.write("/Users/me/data/f1"))]
        let result = try items(observations)
        #expect(result.map(\.suggestion) == [.file(path: "/Users/me/data", kind: .directory, access: .readWrite)])
        #expect(result.first?.evidence == 4)
        #expect(result.first?.samples == ["/Users/me/data/f1", "/Users/me/data/f2", "/Users/me/data/f3"])
    }

    @Test func fewFilesStayIndividual() throws {
        let result = try items([obs(.read("/Users/me/data/a")), obs(.read("/Users/me/data/b"))])
        #expect(result.map(\.suggestion) == [
            .file(path: "/Users/me/data/a", kind: .file, access: .readOnly),
            .file(path: "/Users/me/data/b", kind: .file, access: .readOnly),
        ])
    }

    @Test func knownTemplateIsSuggestedInsteadOfPaths() throws {
        let result = try items([obs(.read("/opt/homebrew/Cellar/python@3.13/x"), count: 5), obs(.exec("/opt/homebrew/bin/python3"))])
        #expect(result.map(\.suggestion) == [.template(id: "homebrew-python")])
        #expect(result.first?.evidence == 6)
    }

    @Test func enabledTemplateIsNotSuggestedAgain() throws {
        let result = try items([obs(.exec("/opt/homebrew/bin/python3"))], enabled: ["homebrew-python"])
        #expect(result.map(\.suggestion) == [.exec("/opt/homebrew/bin/python3")])
    }

    @Test func unrestrictedExecCoversExec() throws {
        #expect(try items([obs(.exec("/usr/bin/curl"))], policy: F.profile(unrestrictedExec: true)).isEmpty)
    }

    @Test func networkSuggestions() throws {
        let result = try items([obs(.connectLoopback(9910)), obs(.connectRemote), obs(.listen(8080)), obs(.connectLoopback(9910))])
        #expect(result.map(\.suggestion) == [.loopbackPort(9910), .outboundTCP, .listen])
        #expect(result.first?.evidence == 2)
    }

    @Test func allowedNetworkIsCovered() throws {
        let policy = F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed, listen: .allowed))
        #expect(try items([obs(.connectLoopback(9910)), obs(.connectRemote), obs(.listen(1))], policy: policy).isEmpty)
    }

    @Test func sensitiveItemsComeFirstAndAreFlagged() throws {
        let result = try items([obs(.read("/Users/me/easyops2/a")), obs(.read("/Users/me/.ssh/id_ed25519"))])
        #expect(result.first?.suggestion == .file(path: "/Users/me/.ssh/id_ed25519", kind: .file, access: .readOnly))
        #expect(result.first?.sensitive == true)
        #expect(result.last?.sensitive == false)
    }
}
