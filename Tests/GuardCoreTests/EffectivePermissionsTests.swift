import Testing
@testable import GuardCore

@Suite struct EffectivePermissionsTests {
    typealias F = Fixtures

    let tool = Template(id: "tool", version: 1, files: [F.rw("/Users/me/.tool/sessions"), F.ro("/Users/me/.tool")],
                        exec: [ExecGrant(path: "/usr/bin/tool")], loopbackPorts: [9000])

    func profile(files: [FileGrant] = [], extraRules: [String] = [], templates: [TemplateRef] = []) -> Profile {
        var p = F.profile(files: files, templates: templates, extraRules: extraRules)
        p.programs = ["/opt/bin/agent"]
        return p
    }

    @Test func mergesEverySourceWithItsOrigin() {
        let p = profile(files: [F.ro("/tmp/work")], extraRules: [#"(allow file-write* (subpath "/Users/me/old"))"#],
                        templates: [TemplateRef(id: "tool", version: 1)])
        let overview = EffectivePermissions.overview(of: p, templates: [tool], environment: F.environment)
        let byPath = Dictionary(uniqueKeysWithValues: overview.files.map { ($0.path, $0) })
        #expect(byPath["/private/tmp/work"]?.sources.map(\.source) == [.user])
        #expect(byPath["/Users/me/.tool/sessions"]?.sources.map(\.source) == [.template("tool")])
        #expect(byPath["/opt/bin/agent"]?.sources.map(\.source) == [.program])
        #expect(byPath["/Users/me/old"]?.access == .readWrite)
        #expect(overview.exec.map(\.path) == ["/opt/bin/agent", "/usr/bin/tool"])
        #expect(overview.ports == [PortPermission(port: 9000, sources: [.template("tool")])])
        #expect(overview.complete)
    }

    @Test func childInheritsFromBroaderGrantsAndShowsRedundancy() {
        let p = profile(files: [F.ro("/Users/me/code/app")], extraRules: [#"(allow file-write* (subpath "/Users/me/code"))"#])
        let overview = EffectivePermissions.overview(of: p, templates: [], environment: F.environment)
        let child = overview.files.first { $0.path == "/Users/me/code/app" }
        // Read-only as set by the user, but the legacy write rule above it wins.
        #expect(child?.ownAccess == .readOnly)
        #expect(child?.access == .readWrite)
        #expect(child?.redundant == true)
    }

    @Test func patternAboveCountsAsInherited() {
        let p = profile(files: [FileGrant(path: "/Users/me/logs/*", kind: .directory, access: .readWrite, pattern: true),
                                F.rwFile("/Users/me/logs/a/x.log")])
        let entry = EffectivePermissions.overview(of: p, templates: [], environment: F.environment).files.first { $0.path == "/Users/me/logs/a/x.log" }
        #expect(entry?.inherited.map(\.path) == ["/Users/me/logs/*"])
    }

    @Test func unverifiedLegacyRuleMakesTheListIncomplete() {
        let p = profile(extraRules: [#"(allow file-read* (regex #"^/Users/me/.*"))"#])
        #expect(!EffectivePermissions.overview(of: p, templates: [], environment: F.environment).complete)
    }

    @Test func removalFindsChildGrantsAndTemplateGrants() throws {
        let parent = F.ro("/Users/me/.tool")
        let child = F.rw("/Users/me/.tool/cache")
        let p = profile(files: [parent, child, F.ro("/Users/me/other")], templates: [TemplateRef(id: "tool", version: 1)])
        let check = try EffectivePermissions.remaining(at: parent.path, kind: .directory, keeping: nil, excluding: parent,
                                                       in: p, templates: [tool], environment: F.environment)
        #expect(check.innerUserGrants == [child])
        #expect(check.outerUserGrants.isEmpty)
        #expect(Set(check.fixed.map(\.path)) == ["/Users/me/.tool/sessions", "/Users/me/.tool"])
        #expect(!check.isComplete)
    }

    @Test func downgradeOnlyCountsWritableGrants() throws {
        let target = F.rw("/Users/me/.tool")
        let p = profile(files: [target], templates: [TemplateRef(id: "tool", version: 1)])
        let check = try EffectivePermissions.remaining(at: target.path, kind: .directory, keeping: .readOnly, excluding: target,
                                                       in: p, templates: [tool], environment: F.environment)
        #expect(check.fixed.map(\.path) == ["/Users/me/.tool/sessions"])
        #expect(check.innerUserGrants.isEmpty && check.outerUserGrants.isEmpty)
    }

    @Test func parentGrantIsNamedNotRemoved() throws {
        let target = F.rw("/Users/me/code/app")
        let parent = F.ro("/Users/me/code")
        let p = profile(files: [parent, target])
        let check = try EffectivePermissions.remaining(at: target.path, kind: .directory, keeping: nil, excluding: target,
                                                       in: p, templates: [], environment: F.environment)
        #expect(check.outerUserGrants == [parent])
        #expect(!check.isComplete)
    }

    @Test func unrelatedGrantsDoNotCount() throws {
        let target = F.rw("/Users/me/a")
        let p = profile(files: [target, F.rw("/Users/me/ab"), FileGrant(path: "/Users/me/b/*.log", kind: .file, access: .readWrite, pattern: true)])
        let check = try EffectivePermissions.remaining(at: target.path, kind: .directory, keeping: nil, excluding: target,
                                                       in: p, templates: [], environment: F.environment)
        #expect(check.innerUserGrants.isEmpty && check.outerUserGrants.isEmpty)
        #expect(check.isComplete)
    }
}

@Suite struct LegacyPrefixAndLoginTests {
    typealias F = Fixtures

    @Test func legacyPrefixCountsAsInherited() {
        let p = F.profile(files: [F.ro("/Users/me/docs2/a")], extraRules: [#"(allow file-write* (prefix "/Users/me/docs"))"#])
        let entry = EffectivePermissions.overview(of: p, templates: [], environment: F.environment).files.first { $0.path == "/Users/me/docs2/a" }
        #expect(entry?.access == .readWrite)
    }

    @Test func loginSettingIsKeptOutsideRevisions() throws {
        let files = InMemoryFileStore()
        let store = LoginSettingStore(root: "/cfg", files: files)
        var p = F.profile()
        #expect(store.runAtLogin(of: p) == nil)
        p.launch = LaunchSettings(executable: "/bin/x", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: false, runAtLogin: true)
        #expect(store.runAtLogin(of: p) == true)
        try store.set(false, for: "knodo")
        #expect(store.runAtLogin(of: p) == false)
        #expect(store.applied(to: p).launch?.runAtLogin == false)
        try store.remove("knodo")
        #expect(store.runAtLogin(of: p) == true)
    }
}
