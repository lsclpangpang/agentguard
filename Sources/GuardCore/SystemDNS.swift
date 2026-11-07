/// A fixed system service, not an arbitrary Unix-socket grant.
public enum SystemDNS {
    public static let title = "系统域名解析与服务发现"
    public static let socketPath = "/private/var/run/mDNSResponder"
    public static let detail = "连接 macOS 的 mDNSResponder 服务，用于解析域名和发现局域网服务。系统服务可能代为发送 DNS 查询。"

    public static func matches(path: String, operation: String) -> Bool {
        operation == "network-outbound"
            && (path == socketPath || path == "/var/run/mDNSResponder")
    }
}

extension Observation {
    public var isSystemDNS: Bool {
        guard case let .unixSocket(path, operation) = access else { return false }
        return SystemDNS.matches(path: path, operation: operation)
    }
}
