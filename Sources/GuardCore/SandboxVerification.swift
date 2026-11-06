/// One sandbox operation the Helper can ask the kernel about for another process.
public enum SandboxOperation: String, Sendable {
    case fileRead = "file-read-data"
    case fileWrite = "file-write-data"
    case machLookup = "mach-lookup"
}

/// What one probe of a running process must find for its revision to count as in effect.
public struct SandboxExpectation: Equatable, Sendable {
    public var operation: SandboxOperation
    public var target: String
    public var allowed: Bool
    /// Shown to the user when the process does not behave this way.
    public var failure: String

    public init(operation: SandboxOperation, target: String, allowed: Bool, failure: String) {
        self.operation = operation
        self.target = target
        self.allowed = allowed
        self.failure = failure
    }
}

public enum SandboxCheckResult: Equatable, Sendable {
    case allowed
    case denied
    /// The system could not answer, e.g. the process exited between two probes.
    case unavailable
}

/// Asks the kernel how another process's sandbox decides an operation (`sandbox_check` on macOS).
/// The probed process takes no part, so a managed program cannot vouch for itself.
public protocol SandboxProbe: Sendable {
    /// Nil when the system cannot answer.
    func isSandboxed(pid: Int32) -> Bool?
    func check(pid: Int32, operation: SandboxOperation, target: String) -> SandboxCheckResult
}

public enum SandboxVerdict: Equatable, Sendable {
    case passed
    case failed([String])
    /// The process has not entered a sandbox (yet): the launcher applies it right after registering.
    case notSandboxed
    case unavailable
}

/// Checks a running instance against the revision it registered with. Passing means the kernel
/// enforces the boundaries the user can see, not merely that the rules compiled.
public enum SandboxVerification {
    /// A name nothing grants: if it is reachable, deny-by-default is not in force.
    static let unlistedName = ".agentguard-unlisted-probe"
    /// Probing a directory grant uses a child that need not exist; path filters match the string.
    static let childName = ".agentguard-probe"

    public static func expectations(for policy: EffectivePolicy, environment: CompileEnvironment) -> [SandboxExpectation] {
        var result: [SandboxExpectation] = [
            SandboxExpectation(operation: .machLookup, target: environment.helperServiceName, allowed: false,
                               failure: "受管进程可以连接 AgentGuard Helper"),
        ]
        for path in environment.protectedPaths + environment.writeProtectedPaths {
            result.append(SandboxExpectation(operation: .fileWrite, target: child(of: path), allowed: false,
                                             failure: "受保护的位置 \(path) 可以写入"))
        }
        // Unprotected observation runs with `(allow default)`; only the built-in denials hold.
        guard !policy.mode.liftsBoundary else { return result }

        let unlisted = environment.homeDirectory + "/" + unlistedName
        result.append(SandboxExpectation(operation: .fileRead, target: unlisted, allowed: false,
                                         failure: "未授权的位置 \(unlisted) 可以读取：默认拒绝没有生效，或有旧规则放开了它"))
        result.append(SandboxExpectation(operation: .fileWrite, target: unlisted, allowed: false,
                                         failure: "未授权的位置 \(unlisted) 可以写入：默认拒绝没有生效，或有旧规则放开了它"))
        for grant in policy.files {
            let target = grant.kind == .directory ? child(of: grant.path) : grant.path
            result.append(SandboxExpectation(operation: .fileRead, target: target, allowed: true,
                                             failure: "已授权的 \(grant.path) 不能读取"))
            switch grant.access {
            case .readWrite:
                result.append(SandboxExpectation(operation: .fileWrite, target: target, allowed: true,
                                                 failure: "已授权修改的 \(grant.path) 不能写入"))
            case .readOnly:
                result.append(SandboxExpectation(operation: .fileWrite, target: target, allowed: false,
                                                 failure: "设为仅查看的 \(grant.path) 仍可写入，可能来自旧规则或其他重叠授权"))
            }
        }
        for grant in policy.patterns {
            let target = grant.kind == .directory ? child(of: grant.sample) : grant.sample
            result.append(SandboxExpectation(operation: .fileRead, target: target, allowed: true,
                                             failure: "通配授权 \(grant.pattern) 匹配的 \(grant.sample) 不能读取"))
            result.append(SandboxExpectation(operation: .fileWrite, target: target, allowed: grant.access == .readWrite,
                                             failure: grant.access == .readWrite
                                                ? "通配授权 \(grant.pattern) 匹配的 \(grant.sample) 不能写入"
                                                : "设为仅查看的通配授权 \(grant.pattern) 仍可写入，可能来自旧规则或其他重叠授权"))
        }
        return result
    }

    public static func verify(pid: Int32, expectations: [SandboxExpectation], probe: any SandboxProbe) -> SandboxVerdict {
        guard let sandboxed = probe.isSandboxed(pid: pid) else { return .unavailable }
        guard sandboxed else { return .notSandboxed }
        var failures: [String] = []
        for expectation in expectations {
            switch probe.check(pid: pid, operation: expectation.operation, target: expectation.target) {
            case .unavailable: return .unavailable
            case .allowed where !expectation.allowed, .denied where expectation.allowed: failures.append(expectation.failure)
            case .allowed, .denied: break
            }
        }
        return failures.isEmpty ? .passed : .failed(failures)
    }

    private static func child(of path: String) -> String {
        (path.hasSuffix("/") ? path : path + "/") + childName
    }
}
