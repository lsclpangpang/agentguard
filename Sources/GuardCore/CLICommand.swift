public enum CLIError: Error, Equatable, Sendable {
    case usage(String)
}

/// `guard` only starts already-approved profiles; it never accepts permissions on the command line.
public enum CLICommand: Equatable, Sendable {
    case run(profileID: String, command: [String])
    case status(json: Bool)
    case diagnoseRead(profileID: String, path: String, json: Bool)
    case list
    case version
    case help

    public static let usage = """
    用法：
      guard run <配置档> -- <命令> [参数...]   以已批准的配置档启动命令
      guard status [--json]                     查看受管对象状态
      guard diagnose-read <配置档> <绝对路径> [--json]
                                                只核验当前读取边界，不读取文件内容
      guard list                                列出配置档
      guard version
    """

    public static func parse(_ args: [String]) throws -> CLICommand {
        guard let verb = args.first else { return .help }
        let rest = Array(args.dropFirst())
        switch verb {
        case "run":
            guard let profileID = rest.first else { throw CLIError.usage("缺少配置档") }
            guard ProfileID.isValid(profileID) else { throw CLIError.usage("配置档名称无效：\(profileID)") }
            guard rest.count >= 2, rest[1] == "--" else { throw CLIError.usage("配置档后必须跟 -- 再写命令") }
            let command = Array(rest.dropFirst(2))
            guard !command.isEmpty else { throw CLIError.usage("缺少要运行的命令") }
            return .run(profileID: profileID, command: command)
        case "status":
            if rest.isEmpty { return .status(json: false) }
            if rest == ["--json"] { return .status(json: true) }
            throw CLIError.usage("status 只接受 --json")
        case "diagnose-read":
            guard rest.count == 2 || (rest.count == 3 && rest[2] == "--json") else {
                throw CLIError.usage("diagnose-read 需要配置档、绝对路径，可选 --json")
            }
            guard ProfileID.isValid(rest[0]) else { throw CLIError.usage("配置档名称无效：\(rest[0])") }
            guard rest[1].hasPrefix("/"), !rest[1].utf8.contains(0) else {
                throw CLIError.usage("核验路径必须是有效的绝对路径")
            }
            return .diagnoseRead(profileID: rest[0], path: rest[1], json: rest.count == 3)
        case "list" where rest.isEmpty: return .list
        case "version" where rest.isEmpty: return .version
        case "help", "-h", "--help": return .help
        default: throw CLIError.usage("未知命令：\(verb)")
        }
    }
}
