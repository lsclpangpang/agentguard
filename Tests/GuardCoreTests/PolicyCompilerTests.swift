import Testing
@testable import GuardCore

@Suite struct PolicyCompilerTests {
    typealias F = Fixtures

    @Test func canonicalizesAndSortsFileGrants() throws {
        let policy = try F.compile(F.profile(files: [F.rw("/tmp"), F.rw("/Users/me/easyops/")]))
        #expect(policy.files.map(\.path) == ["/Users/me/easyops", "/private/tmp"])
    }

    @Test func mergesDuplicatePathsToTheWiderAccess() throws {
        let policy = try F.compile(F.profile(files: [F.ro("/Users/me/easyops"), F.rw("/Users/me/easyops/")]))
        #expect(policy.files == [EffectiveFileGrant(path: "/Users/me/easyops", kind: .directory, access: .readWrite, readsSecrets: false)])
    }

    @Test func resultIsIndependentOfGrantOrder() throws {
        let grants = [F.rw("/Users/me/easyops"), F.ro("/Users/me/docs"), F.roFile("/Users/me/.gitconfig")]
        let forward = try F.compile(F.profile(files: grants))
        let backward = try F.compile(F.profile(files: grants.reversed()))
        #expect(forward == backward)
    }

    @Test func templatesMergeWithManualGrantsRegardlessOfOrder() throws {
        let python = Template(id: "homebrew-python", version: 1, files: [F.ro("/opt/homebrew/lib")], exec: [ExecGrant(path: "/opt/homebrew/bin/python3.13")], loopbackPorts: [])
        let git = Template(id: "git", version: 2, files: [F.roFile("/Users/me/.gitconfig")], exec: [ExecGrant(path: "/usr/bin/git")], loopbackPorts: [])
        let refsA = [TemplateRef(id: "homebrew-python", version: 1), TemplateRef(id: "git", version: 2)]
        let a = try F.compile(F.profile(files: [F.rw("/Users/me/easyops")], templates: refsA), templates: [python, git])
        let b = try F.compile(F.profile(files: [F.rw("/Users/me/easyops")], templates: refsA.reversed()), templates: [git, python])
        #expect(a == b)
        #expect(a.files.map(\.path) == ["/Users/me/.gitconfig", "/Users/me/easyops", "/opt/homebrew/lib"])
        #expect(a.exec.map(\.path) == ["/opt/homebrew/bin/python3.13", "/usr/bin/git"])
    }

    @Test func rejectsUnknownTemplate() {
        #expect(throws: CompileError.unknownTemplate("git")) {
            try F.compile(F.profile(templates: [TemplateRef(id: "git", version: 1)]))
        }
    }

    @Test func rejectsTemplateVersionMismatch() {
        let git = Template(id: "git", version: 2, files: [], exec: [], loopbackPorts: [])
        #expect(throws: CompileError.templateVersionMismatch(id: "git", requested: 1, available: 2)) {
            try F.compile(F.profile(templates: [TemplateRef(id: "git", version: 1)]), templates: [git])
        }
    }

    @Test func rejectsRootAndHomeDirectory() {
        #expect(throws: CompileError.forbiddenPath("/")) { try F.compile(F.profile(files: [F.ro("/")])) }
        #expect(throws: CompileError.forbiddenPath("/Users/me")) { try F.compile(F.profile(files: [F.ro("/Users/me")])) }
        #expect(throws: CompileError.forbiddenPath("/Users/me")) { try F.compile(F.profile(files: [F.rw("/Users/me/")])) }
    }

    @Test func homeDirectoryCheckIsCaseInsensitiveWhenConfigured() {
        #expect(throws: CompileError.forbiddenPath("/users/ME")) { try F.compile(F.profile(files: [F.ro("/users/ME")])) }
    }

    @Test func rejectsWritableGrantContainingProtectedPath() {
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Library", protected: "/Library/Application Support/AgentGuard")) {
            try F.compile(F.profile(files: [F.rw("/Library")]))
        }
    }

    @Test func rejectsAnyGrantInsideProtectedPath() {
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Library/Application Support/AgentGuard/state", protected: "/Library/Application Support/AgentGuard")) {
            try F.compile(F.profile(files: [F.ro("/Library/Application Support/AgentGuard/state")]))
        }
    }

    @Test func allowsReadOnlyAncestorOfProtectedPathAndUnrelatedPaths() throws {
        _ = try F.compile(F.profile(files: [F.ro("/Library"), F.ro("/Library/Fonts")]))
    }

    @Test func rejectsReadOnlyNestedInsideReadWriteByDefault() {
        #expect(throws: CompileError.nestedReadOnlyInsideReadWrite(inner: "/Users/me/.claude/settings.json", outer: "/Users/me/.claude")) {
            try F.compile(F.profile(files: [F.rw("/Users/me/.claude"), F.roFile("/Users/me/.claude/settings.json")]))
        }
    }

    @Test func nestedCheckUsesCaseInsensitiveComparison() {
        #expect(throws: CompileError.nestedReadOnlyInsideReadWrite(inner: "/users/me/work/a", outer: "/Users/me/Work")) {
            try F.compile(F.profile(files: [F.rw("/Users/me/Work"), F.ro("/users/me/work/a")]))
        }
    }

    @Test func allowsNestedReadOnlyOnceCapabilityIsVerified() throws {
        var env = F.environment
        env.allowsNestedReadOnly = true
        let policy = try F.compile(F.profile(files: [F.rw("/Users/me/.claude"), F.roFile("/Users/me/.claude/settings.json")]), environment: env)
        #expect(policy.files.count == 2)
    }

    @Test func readWriteInsideReadOnlyIsAllowed() throws {
        let policy = try F.compile(F.profile(files: [F.ro("/Users/me/projects"), F.rw("/Users/me/projects/easyops")]))
        #expect(policy.files.count == 2)
    }

    @Test func fileGrantDoesNotContainOtherPaths() throws {
        let policy = try F.compile(F.profile(files: [F.rwFile("/Users/me/a.txt"), F.roFile("/Users/me/a.txt.bak")]))
        #expect(policy.files.count == 2)
    }

    @Test func readsSecretsFlagSurvivesMerging() throws {
        let secret = FileGrant(path: "/Users/me/.ssh", kind: .directory, access: .readOnly, readsSecrets: true)
        let policy = try F.compile(F.profile(files: [F.ro("/Users/me/.ssh"), secret]))
        #expect(policy.files.first?.readsSecrets == true)
    }

    @Test func rejectsInvalidPort() {
        #expect(throws: CompileError.invalidPort(0)) {
            try F.compile(F.profile(network: NetworkPolicy(loopbackTCPConnect: [0])))
        }
    }

    @Test func deduplicatesAndSortsPortsIncludingTemplatePorts() throws {
        let t = Template(id: "knodo-runtime", version: 1, files: [], exec: [], loopbackPorts: [9910])
        let policy = try F.compile(
            F.profile(network: NetworkPolicy(loopbackTCPConnect: [9910, 80, 9910]), templates: [TemplateRef(id: "knodo-runtime", version: 1)]),
            templates: [t]
        )
        #expect(policy.network.loopbackTCPConnect == [80, 9910])
    }

    @Test func executableInsideWritableAreaRequiresHash() throws {
        #expect(throws: CompileError.mutableExecutableWithoutHash("/Users/me/easyops/tool")) {
            try F.compile(F.profile(files: [F.rw("/Users/me/easyops")], exec: [ExecGrant(path: "/Users/me/easyops/tool")]))
        }
        _ = try F.compile(F.profile(files: [F.rw("/Users/me/easyops")], exec: [ExecGrant(path: "/Users/me/easyops/tool", sha256: String(repeating: "a", count: 64))]))
    }

    @Test func rejectsMalformedHash() {
        #expect(throws: CompileError.invalidHash("/usr/bin/git")) {
            try F.compile(F.profile(exec: [ExecGrant(path: "/usr/bin/git", sha256: "xyz")]))
        }
    }

    @Test func executablePathsAreCanonicalizedAndDeduplicated() throws {
        let policy = try F.compile(F.profile(exec: [ExecGrant(path: "/usr/bin/../bin/git"), ExecGrant(path: "/usr/bin/git")]))
        #expect(policy.exec == [EffectiveExecGrant(path: "/usr/bin/git", sha256: nil)])
    }

    @Test func conflictingHashesForSameExecutableAreRejected() {
        let a = String(repeating: "a", count: 64), b = String(repeating: "b", count: 64)
        #expect(throws: CompileError.conflictingHashes("/usr/bin/git")) {
            try F.compile(F.profile(exec: [ExecGrant(path: "/usr/bin/git", sha256: a), ExecGrant(path: "/usr/bin/git", sha256: b)]))
        }
    }

    @Test func modeAndRevisionArePropagated() throws {
        let policy = try F.compile(F.profile(mode: .restrictedLearning, revision: 7))
        #expect(policy.mode == .restrictedLearning)
        #expect(policy.revision == 7)
        #expect(policy.profileID == "knodo")
    }
}
