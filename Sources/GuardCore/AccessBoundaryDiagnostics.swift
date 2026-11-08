/// A kernel query describes the boundary at the time of the query; it does not open the target
/// or establish that any earlier event read its contents.
public enum AccessBoundaryDecision: String, Codable, Equatable, Sendable {
    case allowed, denied, missing, unavailable

    init(_ result: SandboxCheckResult) {
        switch result {
        case .allowed: self = .allowed
        case .denied: self = .denied
        case .missing: self = .missing
        case .unavailable: self = .unavailable
        }
    }

    public var displayText: String {
        switch self {
        case .allowed: return "允许"
        case .denied: return "拒绝"
        case .missing: return "路径不存在，未确认"
        case .unavailable: return "系统未能确认"
        }
    }
}

public enum AccessBoundaryIdentity: String, Codable, Equatable, Sendable {
    case verified
    case missingExpectedIdentity = "missing_expected_identity"
    case processUnavailable = "process_unavailable"
    case processChanged = "process_changed"
    case notSandboxed = "not_sandboxed"
    case sandboxUnavailable = "sandbox_unavailable"

    public var displayText: String {
        switch self {
        case .verified: return "进程身份已核对"
        case .missingExpectedIdentity: return "缺少后台核对的完整进程身份，请更新后台服务或等待核验"
        case .processUnavailable: return "进程已经退出，或系统无法查询其身份"
        case .processChanged: return "进程身份已变化，本次结果作废"
        case .notSandboxed: return "进程尚未应用保护，未形成权限核验结论"
        case .sandboxUnavailable: return "系统暂时无法核验保护状态"
        }
    }
}

public struct AccessBoundaryDiagnostic: Codable, Equatable, Sendable {
    public var instanceID: Int
    public var revision: Int
    public var pid: Int32?
    public var path: String
    public var identity: AccessBoundaryIdentity
    /// The independently matched full OS birth, never a truncated birth or audit pidversion.
    public var processStartTime: UInt64?
    public var contentRead: AccessBoundaryDecision?
    public var metadataRead: AccessBoundaryDecision?
    public var contentWrite: AccessBoundaryDecision?
}

/// Read-only checks, gated by the Helper's independently established full process birth. A PID
/// alone cannot select a managed process; all answers are discarded if identity changes.
public enum AccessBoundaryDiagnostics {
    public static func check(instanceID: Int, revision: Int, pid: Int32?, expectedStartTime: UInt64?,
                             path: String, processStartTime: (Int32) -> UInt64?,
                             probe: any SandboxProbe) -> AccessBoundaryDiagnostic {
        var report = AccessBoundaryDiagnostic(instanceID: instanceID, revision: revision, pid: pid,
                                              path: path, identity: .missingExpectedIdentity)
        guard let pid, pid > 0, let expectedStartTime, expectedStartTime > 0 else { return report }
        guard let before = processStartTime(pid) else {
            report.identity = .processUnavailable
            return report
        }
        guard before == expectedStartTime else {
            report.identity = .processChanged
            return report
        }
        let sandboxedBefore = probe.isSandboxed(pid: pid)
        var answers: [SandboxOperation: AccessBoundaryDecision] = [:]
        if sandboxedBefore == true {
            for operation in [SandboxOperation.fileRead, .fileMetadata, .fileWrite] {
                answers[operation] = AccessBoundaryDecision(probe.check(pid: pid, operation: operation, target: path))
            }
        }
        let sandboxedAfter = probe.isSandboxed(pid: pid)
        guard let after = processStartTime(pid) else {
            report.identity = .processUnavailable
            return report
        }
        guard after == expectedStartTime else {
            report.identity = .processChanged
            return report
        }
        guard let sandboxedBefore, let sandboxedAfter else {
            report.identity = .sandboxUnavailable
            return report
        }
        guard sandboxedBefore && sandboxedAfter else {
            report.identity = .notSandboxed
            return report
        }
        report.identity = .verified
        report.processStartTime = after
        report.contentRead = answers[.fileRead]
        report.metadataRead = answers[.fileMetadata]
        report.contentWrite = answers[.fileWrite]
        return report
    }
}
