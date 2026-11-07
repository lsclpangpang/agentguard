import Foundation

public struct SandboxDenial: Equatable, Sendable {
    public var process: String
    public var pid: Int32
    public var operation: String
    public var target: String?

    public var networkEndpoint: NetworkEndpoint? {
        guard operation == "network-outbound" || operation == "network-bind",
              let target else { return nil }
        return NetworkEndpoint(target)
    }

    /// The access this denial corresponds to, when it maps onto something a profile can grant.
    public var access: ObservedAccess? {
        if operation == "signal" { return .signal(target: target ?? "") }
        guard let target else { return nil }
        if operation.hasPrefix("file-read") { return target.hasPrefix("/") ? .read(target) : nil }
        if operation.hasPrefix("file-write") { return target.hasPrefix("/") ? .write(target) : nil }
        if operation.hasPrefix("process-exec") { return target.hasPrefix("/") ? .exec(target) : nil }
        if operation == "network-outbound" || operation == "network-bind" {
            guard let endpoint = networkEndpoint else { return nil }
            if let path = endpoint.socketPath { return .unixSocket(path: path, operation: operation) }
            guard let port = endpoint.port else { return nil }
            if operation == "network-bind" { return .listen(port) }
            return endpoint.isLoopback ? .connectLoopback(port) : .connectRemote
        }
        return nil
    }
}

/// Parses kernel sandbox violation messages such as
/// `Sandbox: knodo-agentd(97140) deny(1) file-write-create /path`.
public enum SandboxLogParser {
    nonisolated(unsafe) private static let pattern = try! NSRegularExpression(pattern: #"^Sandbox: (.+)\((\d+)\) deny\(\d+\) (\S+)(?: (.+))?$"#)

    public static func parse(_ message: String) -> SandboxDenial? {
        let range = NSRange(message.startIndex..., in: message)
        guard let match = pattern.firstMatch(in: message, range: range),
              let name = Range(match.range(at: 1), in: message), let pid = Range(match.range(at: 2), in: message),
              let operation = Range(match.range(at: 3), in: message), let pidValue = Int32(message[pid])
        else { return nil }
        let target = Range(match.range(at: 4), in: message).map { String(message[$0]) }
        return SandboxDenial(process: String(message[name]), pid: pidValue, operation: String(message[operation]), target: target)
    }
}
