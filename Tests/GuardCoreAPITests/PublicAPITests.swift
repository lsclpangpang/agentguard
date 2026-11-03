import Foundation
import GuardCore
import Testing

/// Uses GuardCore exactly as the app, CLI and launcher do: plain `import`, no `@testable`.
/// It compiles only if everything those modules call is public.
@Suite struct PublicAPITests {
    @Test func appStatusComputation() {
        let report = StatusReport(profiles: [
            ProfileStatusReport(profileID: "knodo", savedRevision: 2, mode: .enforce, revisionState: .applied(running: true), runningInstances: [1], pendingCount: 0),
        ], collectorProblems: [])
        let objects = report.profiles.map { profile in
            ObjectStatus(profileID: profile.profileID,
                         protection: ProtectionState.derive(mode: profile.mode, observeUntil: nil, revision: profile.revisionState, capabilityPassed: true),
                         revision: profile.revisionState, pendingItems: profile.pendingCount, unmanagedInstances: 0)
        }
        let status = OverallStatus.evaluate(objects: objects, collector: CollectorHealth(problems: []), capabilityCheckPassed: true)
        #expect(status == .allGood)
        let unreachable = OverallStatus(level: .problem, reasons: ["无法连接 Helper"])
        #expect(unreachable.level == .problem)
        #expect(report.profiles.first?.revisionState.displayText == "已生效")
        #expect(Mode.restrictedLearning.displayName == "受限学习")

        let detached = ProfileStatusReport(profileID: "knodo", savedRevision: 2, mode: .enforce, revisionState: .applied(running: true),
                                           runningInstances: [1], pendingCount: 0, detachedInstances: [1])
        let object = ObjectStatus(profileID: detached.profileID, protection: .enforced, revision: detached.revisionState, pendingItems: 0,
                                  unmanagedInstances: 0, detachedInstances: detached.detachedInstances.count)
        #expect(OverallStatus.evaluate(objects: [object], collector: CollectorHealth(problems: []), capabilityCheckPassed: true).level == .attention)
    }

    @Test func appProfileEditing() throws {
        let config = AgentGuardConfig(home: "/Users/me", uid: 501, homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix { _ in false })
        let refs = config.templates.map { TemplateRef(id: $0.id, version: $0.version) }
        var profile = Profile(id: "work", revision: 1, mode: .restrictedLearning, templates: refs, files: [], exec: [], network: NetworkPolicy())
        #expect(ProfileID.isValid(profile.id))
        profile.files.append(FileGrant(path: "/Users/me/easyops", kind: .directory, access: .readWrite,
                                       readsSecrets: SensitivePaths(home: config.home).overlapsSensitive("/Users/me/easyops")))
        profile.exec.append(ExecGrant(path: "/usr/bin/git"))
        profile.network.loopbackTCPConnect.append(9910)
        profile.network.outboundTCP = .allowed
        profile.launch = LaunchSettings(executable: "/opt/x/agent", arguments: [], workingDirectory: nil, originalLabel: "com.x", restartOnCleanExit: true)
        let policy = try PolicyCompiler(environment: config.environment).compile(profile, catalog: TemplateCatalog(config.templates))
        _ = try LaunchPlan.agent(policy: policy, inheritedEnvironment: [:])
        _ = try LaunchPlan.interactive(policy: policy, command: ["git"], workingDirectory: "/", inheritedEnvironment: [:])
        _ = SBPLRenderer(environment: config.environment).render(policy)
        _ = config.store
        _ = config.ownerPath
        _ = config.launcherPath
    }

    @Test func appHelperMessages() throws {
        let info = PendingChangeInfo(id: "c", digest: "d", summary: ["+ x"], requiresAuthorization: true, baseRevision: 1, expiresAt: Date())
        let request = HelperRequest.approveChange(changeID: info.id, digest: info.digest, authorization: nil)
        #expect(try HelperWire.decodeRequest(HelperWire.encode(request)) == request)
        _ = HelperService.authorizationScope(forChange: info.id)
        _ = HelperService.authorizationScope(forRemoval: "knodo")
        _ = HelperFailure.message(for: "not_trusted")
        let item = PendingItem(suggestion: .loopbackPort(9910), sensitive: false, evidence: 1, samples: [])
        if case let .loopbackPort(port) = item.suggestion { #expect(port == 9910) }
        #expect(!item.sensitive && item.evidence == 1)
    }

    @Test func importAndCLI() throws {
        let allowlist = Data(#"{"read_write_roots":["/Users/me/easyops"],"read_only_roots":[]}"#.utf8)
        var result = try LegacyImporter.importInstallation(profileID: "knodo", allowlistJSON: allowlist, policySBPL: "(version 1)")
        result.profile.launch = LaunchSettings(executable: "/x", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: true)
        #expect(result.unimportedRules.isEmpty)
        #expect(try CLICommand.parse(["status"]) == .status(json: false))
        _ = CLICommand.usage
        if case let .failure(code) = HelperResponse.failure(code: "x") { #expect(code == "x") }
        _ = OwnerRecord(uid: 501, home: "/Users/me")
        _ = AgentGuardVersion.current
    }
}
