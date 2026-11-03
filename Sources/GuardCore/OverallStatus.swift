import Foundation

public enum ProtectionState: Equatable, Sendable {
    case stopped
    case enforced
    case restrictedLearning
    case unprotectedObserve(until: Date)
    case unknown

    /// Protection is only claimed for a running revision that passed verification on a capable system.
    public static func derive(mode: Mode, observeUntil: Date?, revision: RevisionState, capabilityPassed: Bool) -> ProtectionState {
        guard capabilityPassed else { return .unknown }
        switch revision {
        case .applied(running: false): return .stopped
        case .applied(running: true):
            switch mode {
            case .enforce: return .enforced
            case .restrictedLearning: return .restrictedLearning
            case .unprotectedObserve: return .unprotectedObserve(until: observeUntil ?? .distantPast)
            }
        default: return .unknown
        }
    }
}

public struct ObjectStatus: Equatable, Sendable {
    public var profileID: String
    public var protection: ProtectionState
    public var revision: RevisionState
    public var pendingItems: Int
    public var unmanagedInstances: Int

    public init(profileID: String, protection: ProtectionState, revision: RevisionState, pendingItems: Int, unmanagedInstances: Int) {
        self.profileID = profileID
        self.protection = protection
        self.revision = revision
        self.pendingItems = pendingItems
        self.unmanagedInstances = unmanagedInstances
    }
}

public enum StatusLevel: Int, Comparable, Sendable {
    case allGood
    case attention
    case problem

    public static func < (lhs: StatusLevel, rhs: StatusLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Menu-bar status. "All good" requires every object protected and applied, nothing pending,
/// a healthy collector and a passing capability check.
public struct OverallStatus: Equatable, Sendable {
    public let level: StatusLevel
    public let reasons: [String]

    public init(level: StatusLevel, reasons: [String]) {
        self.level = level
        self.reasons = reasons
    }

    public static let allGood = OverallStatus(level: .allGood, reasons: [])

    public static func evaluate(objects: [ObjectStatus], collector: CollectorHealth, capabilityCheckPassed: Bool) -> OverallStatus {
        var findings: [(StatusLevel, String)] = []
        if !capabilityCheckPassed { findings.append((.problem, "系统能力检查未通过")) }
        if !collector.isHealthy { findings.append((.attention, "采集器状态异常")) }
        for object in objects {
            let name = object.profileID
            switch object.protection {
            case .enforced, .stopped: break
            case .restrictedLearning: findings.append((.attention, "\(name)：受限学习中"))
            case .unprotectedObserve: findings.append((.problem, "\(name)：保护未启用"))
            case .unknown: findings.append((.attention, "\(name)：保护状态未知"))
            }
            if object.unmanagedInstances > 0 { findings.append((.problem, "\(name)：发现 \(object.unmanagedInstances) 个未受管实例")) }
            switch object.revision {
            case .applied: break
            case .verificationFailed: findings.append((.problem, "\(name)：验收失败"))
            case .inconsistent: findings.append((.problem, "\(name)：运行修订与已保存修订不一致"))
            case .oldInstancesAlive, .unconfirmed, .awaitingVerification: findings.append((.attention, "\(name)：修订尚未生效"))
            }
            if object.pendingItems > 0 { findings.append((.attention, "\(name)：\(object.pendingItems) 个待定项")) }
        }
        guard let worst = findings.map(\.0).max() else { return .allGood }
        return OverallStatus(level: worst, reasons: findings.map(\.1))
    }
}
