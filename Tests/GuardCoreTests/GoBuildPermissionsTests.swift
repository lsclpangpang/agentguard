import Foundation
import Testing
@testable import GuardCore

@Suite struct GoBuildPermissionsTests {
    typealias F = Fixtures
    let home = "/Users/me"

    @Test func requiredScopeHasExactlyTheFourReviewedGrants() {
        let grants = GoBuildPermissions.requiredGrants(home: home)
        #expect(grants == [
            F.ro("/usr/local/go"),
            F.roFile("/Users/me/Library/Application Support/go/env"),
            F.rw("/Users/me/Library/Caches/go-build"),
            F.ro("/Users/me/go/pkg/mod"),
        ])
        #expect(grants.allSatisfy { !$0.pattern && $0.expiresAt == nil && !$0.readsSecrets })
        #expect(GoBuildPermissions.requiredGrants(home: home + "/") == grants)
    }

    @Test func enablingPreservesAllOtherSettingsAndIsIdempotent() throws {
        var profile = F.profile(files: [F.rw("/Users/me/work")],
                                network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed),
                                revision: 45, extraRules: ["(allow signal (target self))"])
        profile.programs = ["/Library/KnodoRestricted/release/knodo-agentd"]
        let original = profile
        #expect(!GoBuildPermissions.isEnabled(in: profile, home: home))
        GoBuildPermissions.enable(in: &profile, home: home)
        GoBuildPermissions.enable(in: &profile, home: home)
        var expected = original
        expected.files += GoBuildPermissions.requiredGrants(home: home)
        #expect(profile == expected)
        #expect(GoBuildPermissions.isEnabled(in: profile, home: home))
        #expect(try ProfileCodec.decode(ProfileCodec.encode(profile)) == profile)
    }

    @Test func strongerPermanentGrantsArePreservedWithoutDuplicatesOrDowngrades() {
        var profile = F.profile(files: GoBuildPermissions.requiredGrants(home: home).map {
            FileGrant(path: $0.path, kind: $0.kind, access: .readWrite, readsSecrets: true)
        })
        let original = profile
        #expect(GoBuildPermissions.isEnabled(in: profile, home: home))
        GoBuildPermissions.enable(in: &profile, home: home)
        #expect(profile == original)
        #expect(profile.files.count == 4)
    }

    @Test func aWeakerPermanentBuildCacheGrantIsUpgradedInPlace() {
        var grants = GoBuildPermissions.requiredGrants(home: home)
        grants[2] = FileGrant(path: grants[2].path, kind: .directory, access: .readOnly, readsSecrets: true)
        var profile = F.profile(files: grants)
        #expect(!GoBuildPermissions.isEnabled(in: profile, home: home))
        GoBuildPermissions.enable(in: &profile, home: home)
        grants[2].access = .readWrite
        #expect(profile.files == grants)
        #expect(profile.files.count == 4)
        #expect(GoBuildPermissions.isEnabled(in: profile, home: home))
    }

    @Test func temporaryOrWrongKindEntriesDoNotSubstituteForPermanentReviewedGrants() {
        let temporary = FileGrant(path: "/usr/local/go", kind: .directory, access: .readWrite,
                                  expiresAt: Date(timeIntervalSince1970: 2_000_000_000))
        let wrongKind = FileGrant(path: home + "/go/pkg/mod", kind: .file, access: .readWrite)
        var profile = F.profile(files: [temporary, wrongKind])
        GoBuildPermissions.enable(in: &profile, home: home)
        #expect(profile.files.prefix(2) == [temporary, wrongKind])
        #expect(profile.files.count == 6)
        #expect(GoBuildPermissions.isEnabled(in: profile, home: home))
        #expect(profile.files.contains(F.ro(home + "/go/pkg/mod")))
        #expect(!profile.files.contains(F.rw(home + "/go/pkg/mod")))
    }

    @Test func addingTheReviewedGrantsUsesTheExistingAuthorizationDiff() throws {
        let original = F.profile()
        var enabled = original
        GoBuildPermissions.enable(in: &enabled, home: home)
        let diff = PolicyDiff(from: try F.compile(original), to: try F.compile(enabled))
        #expect(diff.requiresAuthorization)
        #expect(diff.changes.count == 4)
        #expect(diff.summaryLines.contains("+ 只读目录 /usr/local/go"))
        #expect(diff.summaryLines.contains("+ 只读文件 /Users/me/Library/Application Support/go/env"))
        #expect(diff.summaryLines.contains("+ 读写目录 /Users/me/Library/Caches/go-build"))
        #expect(diff.summaryLines.contains("+ 只读目录 /Users/me/go/pkg/mod"))
    }

    @Test(arguments: ["/usr/local/go", "/usr/local/go/.", "/usr/local/go/",
                      "/Users/me/go/pkg/mod", "/Users/ME/go/pkg/MOD"])
    func validationRejectsWritableFilesThatWouldBecomeWritableDirectories(path: String) throws {
        let original = F.profile(files: [F.rwFile(path)])
        var unchecked = original
        GoBuildPermissions.enable(in: &unchecked, home: home)
        let canonical = try CanonicalPath(path, resolver: F.environment.resolver)
        let merged = try #require(F.compile(unchecked).files.first {
            $0.path.lowercased() == canonical.comparisonKey(caseInsensitive: true)
        })
        #expect(merged.kind == .directory)
        #expect(merged.access == .readWrite)

        #expect(throws: GoBuildPermissionsError.scopeConflict(path: merged.path)) {
            try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                    environment: F.environment, catalog: TemplateCatalog([]))
        }
        #expect(original.files == [F.rwFile(path)])
    }

    @Test func validationRejectsWritableFilesBehindCanonicalAliases() throws {
        let path = home + "/go/pkg/mod"
        let original = F.profile(files: [F.rwFile("/go-modules")])
        var environment = F.environment
        environment.resolver = AliasResolver(aliases: ["/go-modules": path])
        #expect(throws: GoBuildPermissionsError.scopeConflict(path: path)) {
            try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                    environment: environment, catalog: TemplateCatalog([]))
        }
        #expect(original.files == [F.rwFile("/go-modules")])
    }

    @Test func validationRejectsWritableFileConflictsInheritedFromTemplates() throws {
        let path = home + "/go/pkg/mod"
        let template = Template(id: "legacy-go", version: 1, files: [F.rwFile(path)], exec: [], loopbackPorts: [])
        let original = F.profile(templates: [TemplateRef(id: template.id, version: template.version)])
        #expect(throws: GoBuildPermissionsError.scopeConflict(path: path)) {
            try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                    environment: F.environment, catalog: TemplateCatalog([template]))
        }
        #expect(original.files.isEmpty)
    }

    @Test func validationChecksTheFourEffectiveGrantsAndPreservesOtherSettings() throws {
        let original = F.profile(files: [F.rw(home + "/work")],
                                 network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed),
                                 revision: 45, unrestrictedExec: true, extraRules: [ProcessControl.rule])
        let enabled = try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                              environment: F.environment, catalog: TemplateCatalog([]))
        let before = try F.compile(original)
        let after = try F.compile(enabled)
        let diff = PolicyDiff(from: before, to: after)
        let expected = GoBuildPermissions.requiredGrants(home: home).map {
            EffectiveFileGrant(path: $0.path, kind: $0.kind, access: $0.access, readsSecrets: false)
        }
        #expect(Set(after.files).subtracting(before.files) == Set(expected))
        #expect(Set(diff.changes) == Set(expected.map(PolicyChange.fileAdded)))
        #expect(diff.requiresAuthorization)
        var restored = enabled
        restored.files = original.files
        #expect(restored == original)
        #expect(try GoBuildPermissions.validatedProfile(from: enabled, home: home,
                                                       environment: F.environment, catalog: TemplateCatalog([])) == enabled)
    }

    @Test func validationAllowsOnlyTheReviewedKindAndAccessUpgrades() throws {
        let original = F.profile(files: [F.roFile(home + "/go/pkg/mod"),
                                         F.ro(home + "/Library/Caches/go-build")])
        let enabled = try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                              environment: F.environment, catalog: TemplateCatalog([]))
        let after = try F.compile(enabled)
        #expect(after.files.first { $0.path == home + "/go/pkg/mod" }?.kind == .directory)
        #expect(after.files.first { $0.path == home + "/go/pkg/mod" }?.access == .readOnly)
        #expect(after.files.first { $0.path == home + "/Library/Caches/go-build" }?.access == .readWrite)
        let diff = PolicyDiff(from: try F.compile(original), to: after)
        #expect(diff.changes.contains(.fileKindChanged(path: home + "/go/pkg/mod", from: .file, to: .directory)))
        #expect(diff.changes.contains(.fileAccessChanged(path: home + "/Library/Caches/go-build",
                                                        from: .readOnly, to: .readWrite)))
    }

    @Test func validationPreservesUnchangedStrongerPermanentPermissions() throws {
        let original = F.profile(files: GoBuildPermissions.requiredGrants(home: home).map {
            FileGrant(path: $0.path, kind: $0.kind, access: .readWrite, readsSecrets: true)
        })
        let enabled = try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                              environment: F.environment, catalog: TemplateCatalog([]))
        #expect(enabled == original)
        #expect(PolicyDiff(from: try F.compile(original), to: try F.compile(enabled)).changes.isEmpty)
    }

    @Test func anImplicitStateDirectoryDoesNotExpandTheReviewedPaths() throws {
        var environment = F.environment
        environment.stateRoot = "/Library/TestState"
        let original = F.profile()
        let enabled = try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                              environment: environment, catalog: TemplateCatalog([]))
        let before = try F.compile(original, environment: environment)
        let after = try F.compile(enabled, environment: environment)
        #expect(before.files == [
            EffectiveFileGrant(path: "/Library/TestState/knodo", kind: .directory,
                               access: .readWrite, readsSecrets: false),
        ])
        #expect(after.files.contains(before.files[0]))
        #expect(PolicyDiff(from: before, to: after).changes.count == 4)
    }

    @Test func validationRejectsAliasesThatMergeReviewedReadOnlyAndWritableTargets() throws {
        let moduleCache = home + "/go/pkg/mod"
        let buildCache = home + "/Library/Caches/go-build"
        var environment = F.environment
        environment.resolver = AliasResolver(aliases: [moduleCache: buildCache])
        #expect(throws: GoBuildPermissionsError.scopeConflict(path: buildCache)) {
            try GoBuildPermissions.validatedProfile(from: F.profile(), home: home,
                                                    environment: environment, catalog: TemplateCatalog([]))
        }
    }

    @Test func validationRejectsChangesOutsideTheFourReviewedEntries() throws {
        var original = F.profile()
        original.programs = ["/usr/local/go/bin/go"]
        // The newly readable toolchain covers this implicit program grant, so compilation removes
        // the separate file entry. The narrow maintenance action refuses any unreviewed diff.
        #expect(throws: GoBuildPermissionsError.unexpectedChange) {
            try GoBuildPermissions.validatedProfile(from: original, home: home,
                                                    environment: F.environment, catalog: TemplateCatalog([]))
        }
    }
}
