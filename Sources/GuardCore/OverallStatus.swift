import Foundation

public enum ProtectionState: Equatable, Sendable {
    case stopped
    case enforced
    case restrictedLearning
    case unprotectedObserve(until: Date)
    case unknown

    /// Protection is only claimed for a running revision whose sandbox the Helper checked from outside.
    public static func derive(mode: Mode, observeUntil: Date?, revision: RevisionState) -> ProtectionState {
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
    public var detachedInstances: Int
    /// Running instances whose process tree is not fully known.
    public var untrackedInstances: Int

    public init(profileID: String, protection: ProtectionState, revision: RevisionState, pendingItems: Int, unmanagedInstances: Int,
                detachedInstances: Int = 0, untrackedInstances: Int = 0) {
        self.profileID = profileID
        self.protection = protection
        self.revision = revision
        self.pendingItems = pendingItems
        self.unmanagedInstances = unmanagedInstances
        self.detachedInstances = detachedInstances
        self.untrackedInstances = untrackedInstances
    }
}

/// Whether the status on screen still describes the present. Running programs change on their own,
/// so a report the Helper has not confirmed recently may no longer be true.
public enum StatusFreshness: Equatable, Sendable {
    case current
    case stale(confirmedAt: Date?)

    public static let maxAge: TimeInterval = 15

    public static func evaluate(confirmedAt: Date?, now: Date, maxAge: TimeInterval = maxAge) -> StatusFreshness {
        guard let confirmedAt, now.timeIntervalSince(confirmedAt) <= maxAge else { return .stale(confirmedAt: confirmedAt) }
        return .current
    }

    public var isStale: Bool { self != .current }
}

public enum StatusLevel: Int, Comparable, Sendable {
    case allGood
    case attention
    case problem

    public static func < (lhs: StatusLevel, rhs: StatusLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Menu-bar status. "All good" requires every object protected and applied, nothing pending,
/// a healthy collector and a status the Helper confirmed recently.
public struct OverallStatus: Equatable, Sendable {
    public let level: StatusLevel
    public let reasons: [String]

    public init(level: StatusLevel, reasons: [String]) {
        self.level = level
        self.reasons = reasons
    }

    public static let allGood = OverallStatus(level: .allGood, reasons: [])

    public static func evaluate(objects: [ObjectStatus], collector: CollectorHealth, freshness: StatusFreshness = .current) -> OverallStatus {
        var findings: [(StatusLevel, String)] = []
        if freshness.isStale { findings.append((.attention, "状态待确认：最近没有收到 Helper 的确认")) }
        // Missing activity records affect what is listed, not whether the limits hold.
        if !collector.isHealthy { findings.append((.attention, "部分活动记录缺失：被阻止的访问可能没有全部列出")) }
        for object in objects {
            let name = object.profileID
            switch object.protection {
            // Recording more activity still blocks everything not allowed.
            case .enforced, .stopped, .restrictedLearning: break
            case .unprotectedObserve: findings.append((.problem, "\(name)：保护未启用"))
            case .unknown: break
            }
            if object.unmanagedInstances > 0 { findings.append((.problem, "\(name)：\(object.unmanagedInstances) 个副本没有经过 AgentGuard 运行，不受保护")) }
            if object.detachedInstances > 0 { findings.append((.attention, "\(name)：启动入口已退出，程序异常后可能不会自动重启")) }
            if object.untrackedInstances > 0 { findings.append((.attention, "\(name)：暂时无法确认所有运行副本的保护状态")) }
            switch object.revision {
            case .applied: break
            case .verificationFailed: findings.append((.problem, "\(name)：保护未通过确认"))
            case .inconsistent: findings.append((.problem, "\(name)：运行中的权限与保存的不一致"))
            case .oldInstancesAlive: findings.append((.attention, "\(name)：新权限已保存，重启后生效"))
            case .unconfirmed: findings.append((.attention, "\(name)：暂时无法确认旧副本是否已退出"))
            case .awaitingVerification: findings.append((.attention, "\(name)：正在确认保护"))
            }
            if object.pendingItems > 0 { findings.append((.attention, "\(name)：\(object.pendingItems) 项活动需要处理")) }
        }
        guard let worst = findings.map(\.0).max() else { return .allGood }
        return OverallStatus(level: worst, reasons: findings.map(\.1))
    }
}
