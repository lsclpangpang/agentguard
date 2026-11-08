import Foundation

/// Protocol compatibility and the running code identity are separate component checks.
public enum ComponentVersionStatus: Equatable, Sendable {
    case current
    case updateRequired
    case identityUnavailable

    public static func helper(protocolVersion: Int, requiredProtocol: Int,
                              runtimeCodeHash: String?, bundledCodeHash: String?) -> Self {
        // Without a verified target identity, even a repair cannot confirm what should run.
        guard let bundled = normalizedCodeHash(bundledCodeHash) else { return .identityUnavailable }
        guard protocolVersion >= requiredProtocol,
              let runtime = normalizedCodeHash(runtimeCodeHash), runtime == bundled else { return .updateRequired }
        return .current
    }

    private static func normalizedCodeHash(_ value: String?) -> String? {
        guard let value, value.utf8.count == 40,
              value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) })
        else { return nil }
        return value.lowercased()
    }
}

/// Describes only the installer decision at Helper startup, not running identity, system
/// authorization or source readiness. Keeping existing code must never imply it was updated.
public enum CollectorInstallationStatus: Codable, Equatable, Sendable {
    case installedBundled
    case keptExisting
    case keptOutdated
    case failed(reason: String)

    public var requiresMaintenance: Bool {
        switch self {
        case .keptOutdated, .failed: return true
        case .installedBundled, .keptExisting: return false
        }
    }

    public var description: String {
        switch self {
        case .installedBundled: return "已安装随包采集器；运行状态另行核对"
        case .keptExisting: return "沿用现有采集器；安装状态不代表采集能力已确认"
        case .keptOutdated: return "现有采集器与随包版本不同；为保留现有系统授权，已保留原文件，需要单独维护"
        case let .failed(reason): return "采集器安装未完成：\(reason)"
        }
    }
}
