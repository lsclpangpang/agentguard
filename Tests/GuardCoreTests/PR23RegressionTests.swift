import Foundation
import Testing
@testable import GuardCore

@Suite struct PR23RegressionTests {
    typealias F = Fixtures

    func pattern(_ path: String, _ access: Access, kind: PathKind = .file) -> FileGrant {
        FileGrant(path: path, kind: kind, access: access, pattern: true)
    }

    @Test func intersectingPatternsCannotPromiseReadOnly() throws {
        let p = F.profile(files: [pattern("/tmp/review/*.txt", .readOnly), pattern("/tmp/review/a*.txt", .readWrite)])
        #expect(throws: CompileError.self) { try F.compile(p) }
        let overview = EffectivePermissions.overview(of: p, templates: [], environment: F.environment)
        #expect(overview.files.first { $0.path.hasSuffix("/*.txt") }?.access == .readWrite)
        let check = try EffectivePermissions.remaining(at: p.files[0].path, kind: .file, keeping: nil,
                                                       excluding: p.files[0], in: p, templates: [], environment: F.environment)
        #expect(!check.isComplete)
        #expect(check.outerUserGrants == [p.files[1]])
    }

    @Test func legacyNetworkAndExecNeverLookCompletelyDenied() {
        let rules = [#"(allow network-outbound (remote udp))"#,
                     #"(allow process-exec (literal "/usr/bin/git") (literal "/usr/bin/curl"))"#]
        let p = F.profile(extraRules: rules)
        let overview = EffectivePermissions.overview(of: p, templates: [], environment: F.environment)
        #expect(!overview.complete)
        #expect(Set(overview.unverifiedLegacy) == Set(rules))
    }

    @Test func systemImportsAreOutsideTheEnumeratedOverview() {
        var env = F.environment
        env.baseRules = [#"(import "bsd.sb")"#]
        #expect(!EffectivePermissions.overview(of: F.profile(), templates: [], environment: env).complete)
    }

    @Test func unknownChildrenRemainUnknownAfterKnownRootExits() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 6000, version: 7)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root, restored: true)
        tracker.handle(.exit(root))
        let instances = tracker.instances(ofProfile: "knodo")
        #expect(instances[0].trackingIncomplete)
        #expect(RevisionState.evaluate(savedRevision: 2, instances: instances, verified: [:]) == .unconfirmed(instances: [1]))
        tracker.register(instance: 2, profileID: "knodo", revision: 2, root: ProcessKey(pid: 7000, version: 1))
        #expect(!RevisionState.evaluate(savedRevision: 2, instances: tracker.instances(ofProfile: "knodo"), verified: [2: true]).isComplete)
    }

    @Test func reusedRootCannotAdoptOrStopAnUnrelatedChild() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 6000, version: 7)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root, restored: true)
        let child = RunningProcess(key: ProcessKey(pid: 6001, version: 0), executablePath: "/bin/sh",
                                   parentPID: 6000, startTime: 900)
        let adopted = tracker.adoptDescendants(of: [child], knownBirths: [root: 7], birth: { $0 == 6000 ? 800 : 900 })
        #expect(adopted.isEmpty)
        #expect(tracker.owner(ofPID: 6000) == nil)
        #expect(tracker.owner(ofPID: 6001) == nil)
        let stop = ProcessStopPlan(processes: Array(tracker.liveProcesses(of: 1)), births: adopted, currentBirth: { _ in 900 })
        #expect(stop.targets.isEmpty)
        #expect(tracker.snapshot(of: 1)?.trackingIncomplete == true)
    }

    @Test func reusedChildFromAStaleListingIsNotAdopted() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 6000, version: 7)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root, restored: true)
        let child = RunningProcess(key: ProcessKey(pid: 6001, version: 0), executablePath: "/bin/sh",
                                   parentPID: 6000, startTime: 800)
        #expect(tracker.adoptDescendants(of: [child], knownBirths: [root: 7], birth: { $0 == 6000 ? 7 : 900 }).isEmpty)
    }

    @Test func gapsAlsoSurviveKnownProcessExit() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 1, version: 1)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root)
        tracker.handle(.gap)
        tracker.handle(.exit(root))
        #expect(!RevisionState.evaluate(savedRevision: 1, instances: tracker.instances(ofProfile: "knodo"), verified: [1: true]).isComplete)
    }

    @Test func onlyAKnownRebootClearsPersistedUncertainty() throws {
        let record = InstanceRecord(instance: 1, profileID: "knodo", revision: 1, pid: 6000, startTime: 7,
                                    supervisedByLaunchd: false, bootSessionID: "boot-a")
        let decoded = try JSONDecoder().decode(InstanceRecord.self, from: JSONEncoder().encode(record))
        #expect(!decoded.isFromEarlierBoot(current: "boot-a"))
        #expect(!decoded.isFromEarlierBoot(current: nil))
        #expect(decoded.isFromEarlierBoot(current: "boot-b"))
    }

    @Test func wildcardIntersectionHandlesDepthCaseAndDisjointNames() throws {
        func overlaps(_ a: String, _ b: String, _ kind: PathKind = .file) throws -> Bool {
            try PathPattern(a, resolver: F.environment.resolver)
                .overlaps(PathPattern(b, resolver: F.environment.resolver), kind: .file, otherKind: kind, caseInsensitive: true)
        }
        #expect(try overlaps("/tmp/review/**/secret?.txt", "/tmp/review/a*/SECRET*.txt"))
        #expect(try overlaps("/tmp/review/a*/x", "/tmp/review/*", .directory))
        #expect(try !overlaps("/tmp/review/a*.txt", "/tmp/review/b*.txt"))
        #expect(try !overlaps("/tmp/review/*", "/tmp/review/*/child"))
        // A directory parent can remain read-only while an explicit descendant is writable.
        _ = try F.compile(F.profile(files: [pattern("/tmp/review/*", .readOnly, kind: .directory),
                                           pattern("/tmp/review/*/child", .readWrite, kind: .directory)]))
    }

    @Test func narrowingStructuredPermissionsNamesRetainedLegacyGrants() {
        let rules = [#"(allow network-outbound (remote udp))"#, #"(allow process-exec (literal "/usr/bin/git"))"#]
        let before = F.profile(exec: [ExecGrant(path: "/usr/bin/git")], network: NetworkPolicy(udp: .allowed), extraRules: rules)
        let after = F.profile(extraRules: rules)
        let warnings = LegacyRuleAnalysis.revocationWarnings(from: before, to: after, environment: F.environment)
        #expect(rules.allSatisfy { warnings.contains($0) })
        #expect(LegacyRuleAnalysis.revocationWarnings(from: before, to: F.profile(), environment: F.environment).isEmpty)
    }

    @Test func uninstallInvalidatesPendingPollsAndRepairEvenAfterReinstall() {
        var lifecycle = HelperMaintenance()
        let pendingRepair = lifecycle.generation
        lifecycle.suspend()
        #expect(!lifecycle.accepts(pendingRepair))
        #expect(!lifecycle.accepts(lifecycle.generation))
        let reopened = HelperMaintenance(enabled: lifecycle.enabled)
        #expect(!reopened.accepts(reopened.generation))
        lifecycle.resume()
        #expect(!lifecycle.accepts(pendingRepair))
        #expect(lifecycle.accepts(lifecycle.generation))
    }

    @Test func manualRepairCanReplaceAReachableIncompatibleHelper() {
        #expect(HelperInstallRepair.action(status: .enabled, reachable: true, outdated: true) == .reregister)
        #expect(HelperInstallRepair.action(status: .enabled, reachable: true, outdated: false) == .none)
        #expect(HelperInstallRepair.action(status: .requiresApproval, reachable: false, outdated: true) == .none)
    }

    @Test func backgroundScriptPinsTheResolvedInterpreterAndPreservesArguments() throws {
        let script = "/Users/me/tool.js", interpreter = "/opt/homebrew/Cellar/node/22/bin/node"
        let probe = FakeProgramProbe(files: [script: Data("#!/usr/bin/env -S node --no-warnings\n".utf8),
                                             interpreter: ProgramPathTests.machO],
                                     links: ["/opt/homebrew/bin/node": interpreter])
        let setup = try ProgramSetup.analyze(script, home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe).get()
        var profile = F.profile(files: setup.files, exec: setup.exec.map { ExecGrant(path: $0) })
        profile.launch = setup.launch(arguments: ["user argument"], workingDirectory: nil, runAtLogin: true)
        let plan = try LaunchPlan.agent(policy: F.compile(profile), inheritedEnvironment: [:])
        #expect(try F.compile(profile).detectionTargets == [script])
        #expect(try ProfileCodec.decode(ProfileCodec.encode(profile)).launch?.scriptPath == script)
        #expect(plan.executable == interpreter)
        #expect(plan.arguments == ["--no-warnings", script, "user argument"])
        #expect(plan.environment["PATH"] == LaunchPlan.defaultPath)
    }

    @Test func shebangsDoNotSilentlyDropEnvironmentFlagsOrExpandVariables() {
        #expect(ScriptShebang.parse(Data("#!/usr/bin/env -i node\n".utf8)) == nil)
        #expect(ScriptShebang.parse(Data("#!/usr/bin/env -S node ${FLAGS}\n".utf8)) == nil)
        let shell = ScriptShebang.parse(Data("#!/bin/sh -e\n".utf8))
        #expect(shell?.interpreter == "/bin/sh")
        #expect(shell?.arguments == ["-e"])
    }

    @Test func patternRevocationIncludesPlainParentsTemplatesAndUnknownLegacyRules() throws {
        let target = pattern("/tmp/review/*.txt", .readWrite)
        let template = Template(id: "review", version: 1, files: [F.rwFile("/tmp/review/a.txt")], exec: [], loopbackPorts: [])
        let legacy = #"(allow file-write* (regex #"^/private/tmp/review/.*"))"#
        let profile = F.profile(files: [target, F.rw("/tmp/review")], templates: [TemplateRef(id: "review", version: 1)], extraRules: [legacy])
        let check = try EffectivePermissions.remaining(at: target.path, kind: target.kind, keeping: .readOnly, excluding: target,
                                                       in: profile, templates: [template], environment: F.environment)
        #expect(check.outerUserGrants == [F.rw("/tmp/review")])
        #expect(check.fixed.map(\.path) == ["/private/tmp/review/a.txt"])
        #expect(check.unverifiedRules == [legacy])
        #expect(!check.isComplete)
    }

    @Test func importedAndMixedLegacyRulesKeepTheirNonFileUncertainty() throws {
        let network = "(allow network-outbound (remote udp))"
        let exec = #"(allow file-read* process-exec (literal "/usr/bin/git"))"#
        let imported = try LegacyImporter.importInstallation(profileID: "review",
            allowlistJSON: Data(#"{"read_write_roots":[],"read_only_roots":[]}"#.utf8),
            policySBPL: "(version 1)\n(deny default)\n\(network)\n\(exec)\n")
        let overview = EffectivePermissions.overview(of: imported.profile, templates: [], environment: F.environment)
        #expect(!overview.complete)
        #expect(overview.unverifiedNetwork == [network])
        #expect(overview.unverifiedExec == [exec])
        #expect(Set(overview.unverifiedLegacy) == [network, exec])
        let preview = MigrationPreview.lines(for: imported, templates: [], environment: F.environment)
        #expect(preview.contains { $0.contains(network) })
        #expect(preview.contains { $0.contains(exec) })
    }

    @Test func reusedAdoptedChildCannotAnchorAnotherAdoption() {
        var tracker = InstanceTracker()
        let root = ProcessKey(pid: 6000, version: 7)
        tracker.register(instance: 1, profileID: "knodo", revision: 1, root: root, restored: true)
        let child = RunningProcess(key: ProcessKey(pid: 6001, version: 0), executablePath: "/bin/sh", parentPID: 6000, startTime: 100)
        let adopted = tracker.adoptDescendants(of: [child], knownBirths: [root: 7], birth: { $0 == 6000 ? 7 : 100 })
        #expect(adopted.count == 1)
        let grandchild = RunningProcess(key: ProcessKey(pid: 6002, version: 0), executablePath: "/bin/sh", parentPID: 6001, startTime: 1000)
        let next = tracker.adoptDescendants(of: [grandchild], knownBirths: adopted.merging([root: 7]) { a, _ in a },
                                            birth: { $0 == 6000 ? 7 : $0 == 6001 ? 900 : 1000 })
        #expect(next.isEmpty)
        #expect(tracker.owner(ofPID: 6001) == nil)
        #expect(tracker.owner(ofPID: 6002) == nil)
    }
}
