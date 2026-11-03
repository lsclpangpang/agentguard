/// SMAppService status, mirrored so the decision logic stays testable off macOS.
public enum HelperInstallStatus: Equatable, Sendable {
    case notRegistered
    case enabled
    case requiresApproval
    case notFound
}

public enum HelperRegisterError: Equatable, Sendable {
    /// SMAppServiceErrorDomain code 1. On first registration smd refuses to bootstrap a daemon the
    /// user has not yet allowed in Login Items; the item is nevertheless registered.
    case notPermitted
    case other(String)

    public static func classify(domain: String, code: Int, description: String) -> HelperRegisterError {
        domain == "SMAppServiceErrorDomain" && code == 1 ? .notPermitted : .other(description)
    }
}

public struct HelperInstallOutcome: Equatable, Sendable {
    public var notice: String?
    public var error: String?
    public var openLoginItems: Bool

    public init(notice: String?, error: String?, openLoginItems: Bool) {
        self.notice = notice
        self.error = error
        self.openLoginItems = openLoginItems
    }

    public static func evaluate(statusAfter: HelperInstallStatus, registerError: HelperRegisterError?) -> HelperInstallOutcome {
        switch statusAfter {
        case .enabled:
            return HelperInstallOutcome(notice: nil, error: nil, openLoginItems: false)
        case .requiresApproval:
            return HelperInstallOutcome(notice: "Helper 已登记，请在“系统设置 > 通用 > 登录项 > 允许在后台”中允许 AgentGuard",
                                        error: nil, openLoginItems: true)
        case .notRegistered, .notFound:
            let reason: String
            switch registerError {
            case let .other(description): reason = description
            case .notPermitted: reason = "系统拒绝登记后台项目"
            case nil: reason = "未能登记后台项目"
            }
            return HelperInstallOutcome(notice: nil, error: "安装 Helper 失败：\(reason)", openLoginItems: false)
        }
    }
}

/// Delay before restarting a collector that exited without making progress, so a missing
/// authorization does not turn into a restart loop.
public struct RestartBackoff: Sendable {
    public let base: Double
    public let maximum: Double
    private var failures = 0

    public init(base: Double, maximum: Double) {
        self.base = base
        self.maximum = maximum
    }

    public mutating func nextDelay() -> Double {
        let delay = min(maximum, base * Double(1 << min(failures, 20)))
        failures += 1
        return delay
    }

    public mutating func recordProgress() {
        failures = 0
    }
}
