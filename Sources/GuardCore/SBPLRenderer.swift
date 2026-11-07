/// Renders an effective policy as an SBPL profile. In SBPL the last matching rule wins,
/// so built-in denials are emitted after every allow.
public struct SBPLRenderer: Sendable {
    public let environment: CompileEnvironment

    public init(environment: CompileEnvironment) {
        self.environment = environment
    }

    public func render(_ policy: EffectivePolicy) -> String {
        var lines = [
            "(version 1)",
            ";; agentguard profile \(policy.profileID) revision \(policy.revision)",
        ]
        if policy.mode.liftsBoundary {
            lines.append("(allow default)")
        } else {
            lines.append("(deny default)")
            lines += environment.baseRules
            lines += fileRules(policy.files)
            lines += policy.patterns.map { grant in
                let operations = grant.access == .readWrite ? "file-read* file-write*" : "file-read*"
                // `#"` starts an SBPL regex literal; patterns never contain `"`.
                return "(allow \(operations) (regex #\"\(grant.regex)\"))"
            }
            if policy.unrestrictedExec { lines.append("(allow process-exec)") }
            lines += policy.exec.map { "(allow process-exec (literal \(quote($0.path))))" }
            lines += networkRules(policy.network)
            lines += policy.extraRules
            // The explicit choice wins over imported/baseline rules, including broad Unix-socket
            // allows. Nil leaves old profiles unchanged; it is not a verified denial.
            if let systemDNS = policy.network.systemDNS {
                let action = systemDNS == .allowed ? "allow" : "deny"
                lines.append("(\(action) network-outbound (literal \(quote(SystemDNS.socketPath))))")
            }
        }
        lines += builtinDenials()
        return lines.joined(separator: "\n") + "\n"
    }

    private func fileRules(_ files: [EffectiveFileGrant]) -> [String] {
        files.map { grant in
            let operations = grant.access == .readWrite ? "file-read* file-write*" : "file-read*"
            let filter = grant.kind == .directory ? "subpath" : "literal"
            return "(allow \(operations) (\(filter) \(quote(grant.path))))"
        }
    }

    private func networkRules(_ network: NetworkPolicy) -> [String] {
        var lines: [String] = []
        if network.outboundTCP == .allowed {
            lines.append("(allow network-outbound (remote tcp))")
            lines.append("(deny network-outbound (remote tcp \"localhost:*\"))")
        }
        lines += network.loopbackTCPConnect.map { "(allow network-outbound (remote tcp \"localhost:\($0)\"))" }
        if network.udp == .allowed { lines.append("(allow network-outbound (remote udp))") }
        if network.listen == .allowed { lines.append("(allow network-bind (local tcp))") }
        return lines
    }

    private func builtinDenials() -> [String] {
        (environment.protectedPaths + environment.writeProtectedPaths).map { "(deny file-write* (subpath \(quote($0))))" }
            + ["(deny mach-lookup (global-name \(quote(environment.helperServiceName))))"]
    }

    private func quote(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
