import Foundation

public struct SandboxDenial: Equatable, Sendable {
    public var process: String
    public var pid: Int32
    public var operation: String
    public var target: String?

    /// The access this denial corresponds to, when it maps onto something a profile can grant.
    public var access: ObservedAccess? {
        guard let target else { return nil }
        if operation.hasPrefix("file-read") { return target.hasPrefix("/") ? .read(target) : nil }
        if operation.hasPrefix("file-write") { return target.hasPrefix("/") ? .write(target) : nil }
        if operation.hasPrefix("process-exec") { return target.hasPrefix("/") ? .exec(target) : nil }
        if operation == "network-outbound" || operation == "network-bind" {
            guard let colon = target.lastIndex(of: ":"), let port = Int(target[target.index(after: colon)...]) else { return nil }
            if operation == "network-bind" { return .listen(port) }
            let host = target[..<colon].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let loopback = host == "localhost" || host == "::1" || host.hasPrefix("127.")
            return loopback ? .connectLoopback(port) : .connectRemote
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
