import Foundation

/// Information actually present in a network log target. Never resolves DNS or guesses a URL,
/// an application protocol, or a transport protocol from a port number.
public struct NetworkEndpoint: Equatable, Sendable {
    public let rawValue: String
    public private(set) var host: String?
    public private(set) var port: Int?
    public private(set) var transport: String?
    public private(set) var url: String?
    public private(set) var socketPath: String?

    public init(_ rawValue: String) {
        self.rawValue = rawValue
        var target = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if target.hasPrefix("/") {
            socketPath = target
            transport = "Unix 套接字"
            return
        }
        // macOS can report only `remote:*:7897`. The wildcard is a missing address, not
        // a hostname and not proof of a particular proxy or destination URL.
        for prefix in ["remote:", "local:"] where target.hasPrefix(prefix) {
            target = String(target.dropFirst(prefix.count))
            break
        }
        if let range = target.range(of: #"^(?i:tcp|udp)(?:4|6)?\s+"#, options: .regularExpression) {
            transport = String(target[range].prefix(3)).uppercased()
            target = String(target[range.upperBound...])
        }
        if target.contains("://") {
            guard let components = URLComponents(string: target),
                  let scheme = components.scheme?.lowercased(),
                  ["http", "https", "ws", "wss", "tcp", "udp"].contains(scheme),
                  let host = components.host, !host.isEmpty,
                  components.port.map({ (0...65535).contains($0) }) ?? true
            else { return }
            let normalizedHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            self.host = normalizedHost == "*" ? nil : normalizedHost
            port = components.port
            if scheme == "tcp" || scheme == "udp" {
                transport = scheme.uppercased()
            } else {
                url = target
            }
            return
        }
        // Brackets distinguish an IPv6 address from the following port. Bare IPv6 addresses
        // remain unparsed, rather than treating their final segment as a port.
        guard let colon = target.lastIndex(of: ":") else { return }
        let hostPart = String(target[..<colon])
        let portPart = String(target[target.index(after: colon)...])
        guard !portPart.isEmpty, portPart.allSatisfy({ $0.isASCII && $0.isNumber }),
              let port = Int(portPart), (0...65535).contains(port) else { return }
        if hostPart.hasPrefix("[") && hostPart.hasSuffix("]") {
            let host = String(hostPart.dropFirst().dropLast())
            guard host.contains(":"), !host.contains(where: \.isWhitespace) else { return }
            self.host = host
        } else {
            guard !hostPart.isEmpty, !hostPart.contains(where: { $0.isWhitespace || ":/[]@".contains($0) }) else { return }
            host = hostPart == "*" ? nil : hostPart
        }
        self.port = port
    }

    public var address: String {
        if let socketPath { return socketPath }
        guard let host else { return port == nil ? rawValue : "目标地址未提供" }
        let formatted = host.contains(":") ? "[\(host)]" : host
        return port.map { "\(formatted):\($0)" } ?? formatted
    }

    public var hostname: String? {
        guard let host, !host.contains(":") else { return nil }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        let isIPv4 = parts.count == 4 && parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { $0.isASCII && $0.isNumber }
                && Int(part).map { (0...255).contains($0) } == true
        }
        return isIPv4 ? nil : host
    }

    public var isLoopback: Bool {
        guard let host else { return false }
        let lower = host.lowercased()
        if lower == "localhost" || lower == "::1" || lower == "0:0:0:0:0:0:0:1" { return true }
        let ipv4 = lower.hasPrefix("::ffff:") ? String(lower.dropFirst(7)) : lower
        let parts = ipv4.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.first == "127" && parts.allSatisfy {
            !$0.isEmpty && $0.allSatisfy { $0.isASCII && $0.isNumber }
                && Int($0).map { (0...255).contains($0) } == true
        }
    }
}

extension Observation {
    public var isNetwork: Bool {
        switch access {
        case .connectRemote, .connectLoopback, .listen, .unixSocket: return true
        default: return false
        }
    }

    public var networkEndpoint: NetworkEndpoint? {
        guard isNetwork, let networkTarget, !networkTarget.isEmpty else { return nil }
        return NetworkEndpoint(networkTarget)
    }

    public var networkPort: Int? {
        if let port = networkEndpoint?.port { return port }
        switch access {
        case let .connectLoopback(port), let .listen(port): return port
        default: return nil
        }
    }

    public var summary: String {
        switch access {
        case let .read(path): return "读取 \(path)"
        case let .write(path): return "写入 \(path)"
        case let .exec(path): return "运行 \(path)"
        case .connectLoopback: return "连接本机 \(networkEndpoint?.address ?? "目标地址未记录")"
        case .connectRemote:
            let direction = networkEndpoint?.host == nil ? "网络连接" : "对外连接"
            return "\(direction) \(networkEndpoint?.url ?? networkEndpoint?.address ?? "目标地址未记录")"
        case .listen: return "监听 \(networkEndpoint?.address ?? "地址未记录")"
        case let .unixSocket(path, operation):
            return "\(operation == "network-bind" ? "监听本机套接字" : "连接本机套接字") \(path)"
        }
    }
}
