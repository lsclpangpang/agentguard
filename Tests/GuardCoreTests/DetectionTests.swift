import Foundation
import Testing
@testable import GuardCore

@Suite struct DetectionTests {
    let managedRoot = ProcessKey(pid: 100, version: 1)

    func tracker() -> InstanceTracker {
        var t = InstanceTracker()
        t.register(instance: 1, profileID: "knodo", revision: 2, root: managedRoot)
        return t
    }

    @Test func reportsTargetProcessesOutsideAnyInstance() {
        let running = [
            RunningProcess(key: managedRoot, executablePath: "/Library/Application Support/AgentGuard/releases/knodo/knodo-agentd"),
            RunningProcess(key: ProcessKey(pid: 200, version: 1), executablePath: "/Users/me/.knodo/agent/bin/knodo-agentd"),
            RunningProcess(key: ProcessKey(pid: 300, version: 1), executablePath: "/bin/zsh"),
        ]
        let targets = ["knodo": ["/Users/me/.knodo/agent/bin/knodo-agentd", "/Library/Application Support/AgentGuard/releases/knodo/knodo-agentd"]]
        let found = UnmanagedDetector.detect(running: running, tracker: tracker(), targets: targets, resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(found == ["knodo": [ProcessKey(pid: 200, version: 1)]])
    }

    @Test func comparesCanonicalPaths() {
        let running = [RunningProcess(key: ProcessKey(pid: 7, version: 1), executablePath: "/private/tmp/tool")]
        let found = UnmanagedDetector.detect(running: running, tracker: tracker(), targets: ["t": ["/tmp/tool"]], resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(found == ["t": [ProcessKey(pid: 7, version: 1)]])
    }

    @Test func reappearedStartupItems() {
        let found = UnmanagedDetector.reappearedStartupItems(existingLabels: ["com.knodo.local-agent", "com.other"], takenOver: ["knodo": "com.knodo.local-agent", "x": "com.x"])
        #expect(found == ["knodo"])
    }

    @Test func protectionDerivation() {
        let until = Date(timeIntervalSince1970: 1)
        #expect(ProtectionState.derive(mode: .enforce, observeUntil: nil, revision: .applied(running: true), capabilityPassed: true) == .enforced)
        #expect(ProtectionState.derive(mode: .restrictedLearning, observeUntil: nil, revision: .applied(running: true), capabilityPassed: true) == .restrictedLearning)
        #expect(ProtectionState.derive(mode: .unprotectedObserve, observeUntil: until, revision: .applied(running: true), capabilityPassed: true) == .unprotectedObserve(until: until))
        #expect(ProtectionState.derive(mode: .enforce, observeUntil: nil, revision: .applied(running: false), capabilityPassed: true) == .stopped)
        #expect(ProtectionState.derive(mode: .enforce, observeUntil: nil, revision: .awaitingVerification, capabilityPassed: true) == .unknown)
        #expect(ProtectionState.derive(mode: .enforce, observeUntil: nil, revision: .unconfirmed(instances: [1]), capabilityPassed: true) == .unknown)
        #expect(ProtectionState.derive(mode: .enforce, observeUntil: nil, revision: .applied(running: true), capabilityPassed: false) == .unknown)
    }

    @Test func stoppedObjectNeedsNoAttention() {
        let s = OverallStatus.evaluate(
            objects: [ObjectStatus(profileID: "knodo", protection: .stopped, revision: .applied(running: false), pendingItems: 0, unmanagedInstances: 0)],
            collector: CollectorHealth(problems: []), capabilityCheckPassed: true)
        #expect(s == .allGood)
    }
}
