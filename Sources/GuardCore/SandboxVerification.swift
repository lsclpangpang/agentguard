/// One sandbox operation the Helper can ask the kernel about for another process.
public enum SandboxOperation: String, Hashable, Sendable {
    case fileRead = "file-read-data"
    case fileMetadata = "file-read-metadata"
    case fileWrite = "file-write-data"
    case machLookup = "mach-lookup"
    /// Unix-domain sockets use the path filter, unlike IP endpoints.
    case unixConnect = "network-outbound"
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
    /// Path lookup failed; the kernel's answer cannot establish either access or a boundary.
    case missing
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
    /// All available checks passed. Only positive grants refer to paths not present yet.
    /// This does not establish access to those paths; it does not defer any denial boundary.
    case passedWithDeferred([String])
    case failed([String])
    /// No mismatch was established, but some checks could not be completed.
    case inconclusive([String])
    /// The process has not entered a sandbox (yet): the launcher applies it right after registering.
    case notSandboxed
    case unavailable
}

/// Checks a running instance against the revision it registered with. Passing means the kernel
/// enforces the boundaries the user can see, not merely that the rules compiled.
public enum SandboxVerification {
    /// Fallback only; an absent object yields an inconclusive check, never a confirmed denial.
    static let unlistedName = ".agentguard-unlisted-probe"

    public static func expectations(for policy: EffectivePolicy, environment: CompileEnvironment) -> [SandboxExpectation] {
        var result: [SandboxExpectation] = [
            SandboxExpectation(operation: .machLookup, target: environment.helperServiceName, allowed: false,
                               failure: "受管进程可以连接 AgentGuard Helper"),
        ]
        for path in environment.protectedPaths + environment.writeProtectedPaths {
            result.append(SandboxExpectation(operation: .fileWrite, target: path, allowed: false,
                                             failure: "受保护的位置 \(path) 可以写入"))
        }
        // Unprotected observation runs with `(allow default)`; only the built-in denials hold.
        guard !policy.mode.liftsBoundary else { return result }

        if let systemDNS = policy.network.systemDNS {
            result.append(SandboxExpectation(operation: .unixConnect, target: SystemDNS.socketPath,
                                             allowed: systemDNS == .allowed,
                                             failure: systemDNS == .allowed
                                                ? "已授权的系统域名解析服务不能连接"
                                                : "已设为阻止的系统域名解析服务仍可连接"))
        }
        if let unlisted = unlistedProbe(for: policy, environment: environment) {
            result.append(SandboxExpectation(operation: .fileRead, target: unlisted, allowed: false,
                                             failure: "未授权的位置 \(unlisted) 可以读取：默认拒绝没有生效，或有旧规则放开了它"))
            result.append(SandboxExpectation(operation: .fileWrite, target: unlisted, allowed: false,
                                             failure: "未授权的位置 \(unlisted) 可以写入：默认拒绝没有生效，或有旧规则放开了它"))
        }
        for grant in policy.files {
            // Probe the actual directory. A made-up child would be denied by path lookup
            // even under a rule that allows every descendant.
            let target = grant.path
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
            let target = grant.sample
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
        var pending: [String] = []
        var deferred: [String] = []
        for expectation in expectations {
            switch probe.check(pid: pid, operation: expectation.operation, target: expectation.target) {
            case .missing:
                if expectation.allowed {
                    deferred.append(expectation.target)
                } else {
                    pending.append("路径暂不存在，尚未核验限制：\(expectation.target)")
                }
            case .unavailable:
                pending.append("系统暂时无法核验：\(expectation.target)")
            case .allowed where !expectation.allowed, .denied where expectation.allowed: failures.append(expectation.failure)
            case .allowed, .denied: break
            }
        }
        // A missing target must not conceal a confirmed mismatch elsewhere, nor turn an
        // untestable denial into a successful boundary check.
        if !failures.isEmpty { return .failed(failures) }
        var seen: Set<String> = []
        if !pending.isEmpty { return .inconclusive(pending.filter { seen.insert($0).inserted }) }
        if !deferred.isEmpty { return .passedWithDeferred(deferred.filter { seen.insert($0).inserted }) }
        return .passed
    }

    /// Prefer real system directories, outside the explicit grants, for the default-deny check.
    static func unlistedProbe(for policy: EffectivePolicy, environment: CompileEnvironment) -> String? {
        let identity = AliasResolver(aliases: [:])
        let files = policy.files.compactMap { g in (try? CanonicalPath(g.path, resolver: identity)).map { (g, $0) } }
        let patterns = policy.patterns.compactMap { g in (try? PathPattern(g.pattern, resolver: identity)).map { (g, $0) } }
        let candidates = ["/private/var/empty", "/private/var/root",
                          environment.homeDirectory + "/" + unlistedName]
        return candidates.first { candidate in
            guard let path = try? CanonicalPath(candidate, resolver: identity) else { return false }
            let byFile = files.contains { grant, granted in
                grant.kind == .directory ? granted.contains(path, caseInsensitive: environment.caseInsensitive)
                    : granted.isSame(as: path, caseInsensitive: environment.caseInsensitive)
            }
            let byPattern = patterns.contains { grant, pattern in pattern.covers(path, kind: grant.kind, caseInsensitive: environment.caseInsensitive) }
            return !byFile && !byPattern
        }
    }
}
