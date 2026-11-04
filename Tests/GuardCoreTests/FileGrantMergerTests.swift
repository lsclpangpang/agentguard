import Testing
import Foundation
@testable import GuardCore

@Suite struct FileGrantMergerTests {
    typealias F = Fixtures

    @Test func readWriteParentRemovesCoveredReadOnlyChildren() throws {
        let grants = [
            F.roFile("/Users/me/.knodo/agent"),
            F.roFile("/Users/me/.knodo/agent/bin"),
            F.roFile("/Users/me/.knodo/agent/browser-file-operations"),
            F.rwFile("/Users/me/.knodo/agent/bin/knodo-agent.tmp-14646"),
            F.rw("/Users/me/.knodo"),
        ]

        let normalized = try FileGrantMerger.normalize(grants, resolver: F.environment.resolver,
                                                       caseInsensitive: F.environment.caseInsensitive)

        #expect(normalized == [F.rw("/Users/me/.knodo")])

        var before = F.profile(files: Array(grants.dropLast()), unrestrictedExec: true)
        before.programs = ["/Users/me/.knodo/agent/bin/knodo-agentd"]
        var after = before
        after.files = normalized
        let policy = try F.compile(after)
        let diff = PolicyDiff(from: try F.compile(before), to: policy)
        #expect(diff.requiresAuthorization)
        #expect(diff.summaryLines.contains("+ 读写目录 /Users/me/.knodo"))
        #expect(SBPLRenderer(environment: F.environment).render(policy)
            .contains("(allow file-read* file-write* (subpath \"/Users/me/.knodo\"))"))
    }

    @Test func readOnlyParentKeepsNarrowReadWriteChild() throws {
        let grants = [F.ro("/Users/me/.knodo"), F.rw("/Users/me/.knodo/agent")]
        let normalized = try FileGrantMerger.normalize(grants, resolver: F.environment.resolver,
                                                       caseInsensitive: F.environment.caseInsensitive)
        #expect(normalized == grants)
    }

    @Test func loweringChildAccessMustNotPretendToRevokeParentAccess() throws {
        let parent = F.rw("/Users/me/work")
        let child = F.rwFile("/Users/me/work/data")
        _ = try F.compile(F.profile(files: [parent, child]))

        let changed = try FileGrantMerger.changingAccess(of: child, to: .readOnly, in: [parent, child],
                                                         resolver: F.environment.resolver,
                                                         caseInsensitive: F.environment.caseInsensitive)

        #expect(changed == [parent, F.roFile(child.path)])
        #expect(throws: CompileError.nestedReadOnlyInsideReadWrite(inner: child.path, outer: parent.path)) {
            try F.compile(F.profile(files: changed))
        }
    }

    @Test func raisingParentAccessMergesCoveredChildren() throws {
        let parent = F.ro("/Users/me/work")
        let child = F.roFile("/Users/me/work/data")

        let changed = try FileGrantMerger.changingAccess(of: parent, to: .readWrite, in: [parent, child],
                                                         resolver: F.environment.resolver,
                                                         caseInsensitive: F.environment.caseInsensitive)

        #expect(changed == [F.rw(parent.path)])
        _ = try F.compile(F.profile(files: changed))
    }

    @Test func loweringDuplicatePathDoesNotCreateDuplicateRows() throws {
        let readOnly = F.roFile("/Users/me/work/data")
        let writable = F.rwFile(readOnly.path)

        let changed = try FileGrantMerger.changingAccess(of: writable, to: .readOnly, in: [readOnly, writable],
                                                         resolver: F.environment.resolver,
                                                         caseInsensitive: F.environment.caseInsensitive)

        #expect(changed == [readOnly])
        #expect(try F.compile(F.profile(files: changed)).files.allSatisfy { $0.access == .readOnly })
    }

    @Test func coveredSensitiveChildMarksTheParent() throws {
        let marked = try FileGrantMerger.normalize([
            FileGrant(path: "/Users/me/.knodo/token", kind: .file, access: .readOnly, readsSecrets: true),
            F.rw("/Users/me/.knodo"),
        ], resolver: F.environment.resolver, caseInsensitive: F.environment.caseInsensitive)
        #expect(marked == [FileGrant(path: "/Users/me/.knodo", kind: .directory, access: .readWrite,
                                     readsSecrets: true)])
    }

    @Test func aliasesAndCaseDifferencesStillMerge() throws {
        let normalized = try normalize([F.ro("/Users/ME/Work/child"), F.rw("/Users/me/work")])
        #expect(normalized == [F.rw("/Users/me/work")])
        #expect(try normalize([F.ro("/private/tmp/a"), F.rw("/tmp")]) == [F.rw("/tmp")])
        #expect(try normalize([F.ro("/tmp/"), F.rw("/private/tmp")]) == [F.rw("/tmp/")])
    }

    @Test func unrelatedPathsAndDistinctFileNamesRemain() throws {
        let grants = [F.rwFile("/Users/me/a.txt"), F.roFile("/Users/me/a.txt.bak"),
                      F.rw("/Users/me/work"), F.ro("/Users/me/work-old")]
        let normalized = try FileGrantMerger.normalize(grants, resolver: F.environment.resolver,
                                                       caseInsensitive: F.environment.caseInsensitive)
        #expect(normalized == grants)
    }

    @Test func resultDoesNotDependOnWhetherParentWasAddedFirst() throws {
        let grants = [F.ro("/Users/me/work/child"), F.roFile("/Users/me/work/child/data"),
                      F.rw("/Users/me/work")]
        #expect(try normalize(grants) == normalize(grants.reversed()))
    }

    @Test func temporaryParentDoesNotEraseALongerLivedChild() throws {
        var parent = F.rw("/Users/me/work")
        parent.expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let child = F.roFile("/Users/me/work/data")
        #expect(try normalize([parent, child]) == [parent, child])

        var temporaryChild = child
        temporaryChild.expiresAt = parent.expiresAt?.addingTimeInterval(-60)
        #expect(try normalize([parent, temporaryChild]) == [parent])
    }

    @Test func duplicatePathsKeepTheirSeparateExpiry() throws {
        let permanent = F.roFile("/Users/me/work/data")
        var temporary = F.rwFile(permanent.path)
        temporary.expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(try normalize([permanent, temporary]) == [permanent, temporary])
    }

    @Test func caseSensitiveVolumesKeepDifferentPaths() throws {
        let grants = [F.ro("/Users/me/Work/child"), F.rw("/Users/me/work")]
        #expect(try FileGrantMerger.normalize(grants, resolver: F.environment.resolver, caseInsensitive: false) == grants)
    }

    @Test func protectedPathsStillCannotBeReleasedByMerging() throws {
        let normalized = try normalize([F.ro("/Applications/AgentGuard.app"), F.rw("/Applications")])
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Applications", protected: "/Applications/AgentGuard.app")) {
            try F.compile(F.profile(files: normalized))
        }
    }

    private func normalize(_ grants: [FileGrant]) throws -> [FileGrant] {
        try FileGrantMerger.normalize(grants, resolver: F.environment.resolver,
                                      caseInsensitive: F.environment.caseInsensitive)
    }
}
