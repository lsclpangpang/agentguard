/// Presentation only: exact, familiar forms get an explanation. This never changes policy,
/// treats an unrecognized clause as harmless, or removes it from revocation analysis.
public struct LegacyPermissionSummary: Equatable, Sendable {
    public struct Item: Equatable, Sendable {
        public var rule: String
        public var title: String
        public var detail: String
    }

    public var items: [Item] = []
    public var unknown: [String] = []
    public var allowsLocalBind = false
    public var allowsLocalInbound = false

    public init(rules: [String]) {
        for rule in rules {
            guard case let .list(parts)? = SExpression.parse(rule), parts.first == .atom("allow") else {
                unknown.append(rule)
                continue
            }
            var description: (String, String)?
            switch parts {
            case [.atom("allow"), .atom("file-read-metadata")]:
                description = ("读取文件属性", "允许查询各路径的类型、大小等属性；这条规则本身不授予读取文件内容的权限。")
            case [.atom("allow"), .atom("process-fork")]:
                description = ("创建子进程", "允许程序创建子进程；子进程继承已有的访问限制。")
            case [.atom("allow"), .atom("signal"), .list([.atom("target"), .atom("self")])]:
                description = ("向自身发送信号", "允许程序向自身发送控制信号。")
            case [.atom("allow"), .atom("signal"), .list([.atom("target"), .atom("same-sandbox")])]:
                description = (ProcessControl.title, ProcessControl.detail)
            case [.atom("allow"), .atom("sysctl-read")]:
                description = ("查询系统信息", "允许查询系统提供的内核和运行环境信息。")
            case [.atom("allow"), .atom("ipc-posix-shm-read-data"),
                  .list([.atom("ipc-posix-name"), .string("apple.shm.notification_center")])]:
                description = ("读取系统通知共享数据", "允许读取系统通知中心使用的共享内存。")
            case [.atom("allow"), .atom("network-bind"),
                  .list([.atom("local"), .atom("ip"), .string("localhost:*")])]:
                allowsLocalBind = true
                description = ("绑定本机端口", "旧规则允许绑定本机回环地址的任意端口；下方监听开关关闭时，这条授权仍保留。")
            case [.atom("allow"), .atom("network-inbound"),
                  .list([.atom("local"), .atom("ip"), .string("localhost:*")])]:
                allowsLocalInbound = true
                description = ("接收本机连接", "旧规则允许在本机回环地址接收连接；下方监听开关关闭时，这条授权仍保留。")
            default:
                if parts.count > 2, parts[1] == .atom("mach-lookup") {
                    let names = parts.dropFirst(2).compactMap { part -> String? in
                        guard case let .list(filter) = part, filter.count == 2, filter[0] == .atom("global-name"),
                              case let .string(name) = filter[1], let label = Self.services[name] else { return nil }
                        return "\(label)（\(name)）"
                    }
                    if names.count == parts.count - 2 {
                        description = ("连接指定系统服务", names.joined(separator: "、"))
                    }
                }
            }
            if let (title, detail) = description {
                items.append(Item(rule: rule, title: title, detail: detail))
            } else {
                unknown.append(rule)
            }
        }
    }

    public var localNetworkNotice: String? {
        guard allowsLocalBind || allowsLocalInbound else { return nil }
        let access = allowsLocalBind && allowsLocalInbound ? "绑定本机回环地址的任意端口并接收连接"
            : allowsLocalBind ? "绑定本机回环地址的任意端口" : "在本机回环地址接收连接"
        return "旧规则仍允许\(access)。关闭“允许接收连接”不会撤回这条旧授权。"
    }

    private static let services: [String: String] = [
        "com.apple.system.logger": "系统日志",
        "com.apple.system.notification_center": "系统通知",
        "com.apple.SystemConfiguration.configd": "系统配置",
        "com.apple.networkd": "网络服务",
        "com.apple.mDNSResponder": "DNS 查询",
        "com.apple.system.opendirectoryd.libinfo": "目录信息查询",
        "com.apple.trustd.agent": "证书信任检查",
    ]
}
