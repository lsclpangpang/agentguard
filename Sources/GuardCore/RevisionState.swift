/// Whether the saved revision is what actually constrains the object right now.
public enum RevisionState: Equatable, Sendable, Codable {
    case applied(running: Bool)
    case oldInstancesAlive(residual: Set<ProcessKey>, newInstanceRunning: Bool)
    case unconfirmed(instances: [Int])
    case awaitingVerification
    case verificationFailed
    case inconsistent

    /// Only an applied state may be shown as "revocation complete".
    public var isComplete: Bool {
        if case .applied = self { return true }
        return false
    }

    public static func evaluate(savedRevision: Int, instances: [InstanceSnapshot], verified: [Int: Bool]) -> RevisionState {
        evaluate(savedRevision: savedRevision, instances: instances, verified: verified, includeTrackingGaps: true)
    }

    /// Describes only known running instances. Never use this to confirm revocation or
    /// completeness of the process tree: `evaluate` remains the authority for those decisions.
    public static func evaluateKnownProcesses(savedRevision: Int, instances: [InstanceSnapshot], verified: [Int: Bool]) -> RevisionState {
        evaluate(savedRevision: savedRevision, instances: instances, verified: verified, includeTrackingGaps: false)
    }

    private static func evaluate(savedRevision: Int, instances: [InstanceSnapshot], verified: [Int: Bool],
                                 includeTrackingGaps: Bool) -> RevisionState {
        if instances.contains(where: { $0.isRunning && $0.revision > savedRevision }) { return .inconsistent }

        let current = instances.filter { $0.revision == savedRevision && $0.isRunning }
        // A definite failed boundary check takes precedence over incomplete lineage.
        if instances.contains(where: { $0.isRunning && verified[$0.id] == false }) { return .verificationFailed }
        let old = instances.filter { $0.revision < savedRevision }
        let unconfirmed = instances.filter(\.trackingIncomplete).map(\.id).sorted()
        if includeTrackingGaps && !unconfirmed.isEmpty { return .unconfirmed(instances: unconfirmed) }

        let residual = old.reduce(into: Set<ProcessKey>()) { $0.formUnion($1.liveProcesses) }
        if !residual.isEmpty { return .oldInstancesAlive(residual: residual, newInstanceRunning: !current.isEmpty) }

        if current.isEmpty { return .applied(running: false) }
        let results = current.map { verified[$0.id] }
        if results.allSatisfy({ $0 == true }) { return .applied(running: true) }
        return .awaitingVerification
    }
}
