import Foundation

public enum HelperFailure {
    public static func message(for code: String) -> String {
        if code.hasPrefix("startup_error:") { return String(code.dropFirst("startup_error:".count)) }
        switch code {
        case "not_trusted": return "调用方不是本机已安装的 AgentGuard 组件，或没有该操作的权限"
        case "managed_caller": return "受管进程不能修改权限或再启动受管实例"
        case "authorization_missing": return "没有完成本次变更的系统认证"
        case "authorization_required": return "这项变更会扩大权限，需要认证"
        case "revision_conflict": return "配置档已被修改，请刷新后重试"
        case "compile_error": return "配置档无效（路径冲突或包含受保护目录）"
        case "unknown_profile": return "配置档不存在或尚未批准"
        case "stale_revision": return "配置档已更新，请重新启动"
        case "unknown_change", "already_used", "expired", "digest_mismatch": return "这次批准已失效，请重新提交"
        case "no_launch_settings": return "配置档没有启动设置，不能接管启动项"
        case "invalid_profile": return "配置档名称无效"
        case "profile_running": return "配置档还有运行中的实例，请先停止它再删除"
        case "temporary_grants_unavailable": return "临时授权暂未开放：到期后收回运行中程序的权限还没有完成"
        default: return "Helper 拒绝了请求（\(code)）"
        }
    }
}

/// The reason a profile was refused, in the words the user needs to fix it.
///
/// `HelperFailure` only ever answers `compile_error` for the whole family, so the grant path and the
/// protected directory it collided with never cross the XPC boundary. The App recompiles the same
/// revision locally and shows this instead: "没有保存：/Users/me/Library 与受保护目录
/// /Users/me/Library/LaunchAgents 重叠…" is actionable, "配置档无效" is not.
extension CompileError {
    public var message: String {
        switch self {
        case let .invalidProfileID(id):
            return "配置档名称无效：\(id)"
        case let .invalidRawRule(rule):
            return "自定义规则无效：\(rule)"
        case let .invalidPath(path, error):
            return "\(path) 不是可用的路径：\(error.displayText)"
        case let .unknownTemplate(id):
            return "运行时模板不存在：\(id)"
        case let .templateVersionMismatch(id, requested, available):
            return "运行时模板 \(id) 的版本不匹配：需要 \(requested)，本机只有 \(available)"
        case let .forbiddenPath(path):
            return "\(path) 不能整体放行：根目录和你的主目录会连受保护目录一起放开，请选它们下面的具体目录"
        case let .overlapsProtectedPath(grant, protected):
            return "\(grant) 与受保护目录 \(protected) 重叠，请选 \(protected) 之外更具体的目录"
        case let .nestedReadOnlyInsideReadWrite(inner, outer):
            return "\(inner) 是只读，但外层的 \(outer) 是读写，两条规则互相矛盾。要收回写权限，请先将外层目录改为只读或移除它的读写授权"
        case let .invalidPort(port):
            return "端口无效：\(port)"
        case let .invalidHash(hash):
            return "哈希无效：\(hash)"
        case let .conflictingHashes(path):
            return "\(path) 出现了两个不同的哈希"
        case let .mutableExecutableWithoutHash(path):
            return "\(path) 落在受管程序可写的目录里，程序可以替换它，所以不能直接放行执行。请改为放行不可写位置的程序"
        case let .invalidLaunchLabel(label):
            return "启动项标签无效：\(label)"
        }
    }
}

extension PathError {
    public var displayText: String {
        switch self {
        case .empty: return "路径为空"
        case let .notAbsolute(raw): return "不是绝对路径（\(raw)）"
        case .containsNUL: return "路径里有非法字符"
        }
    }
}

extension RevisionState {
    public var displayText: String {
        switch self {
        case .applied(running: true): return "已生效"
        case .applied(running: false): return "已停止"
        case let .oldInstancesAlive(residual, _): return "待生效：旧实例仍有 \(residual.count) 个进程"
        case .unconfirmed: return "无法确认旧实例是否已退出"
        case .awaitingVerification: return "等待验收"
        case .verificationFailed: return "验收失败"
        case .inconsistent: return "运行修订与已保存修订不一致"
        }
    }
}

extension Mode {
    public var displayName: String {
        switch self {
        case .enforce: return "强制保护"
        case .restrictedLearning: return "受限学习"
        case .unprotectedObserve: return "无保护观察"
        }
    }
}

extension AgentGuardConfig {
    public static func detectHomebrewPrefix(fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> String {
        fileExists("/opt/homebrew/bin/brew") || !fileExists("/usr/local/bin/brew") ? "/opt/homebrew" : "/usr/local"
    }

    public var ownerPath: String { configRoot + "/owner.json" }
}

/// The single user this installation serves, recorded by the Helper on the first trusted app connection.
public struct OwnerRecord: Codable, Equatable, Sendable {
    public var uid: Int
    public var home: String

    public init(uid: Int, home: String) {
        self.uid = uid
        self.home = home
    }

    public func encode() throws -> Data { try JSONEncoder().encode(self) }
    public static func decode(_ data: Data) throws -> OwnerRecord { try JSONDecoder().decode(OwnerRecord.self, from: data) }
}

public enum AgentGuardVersion {
    public static var current: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "dev"
        let build = info?["CFBundleVersion"] as? String
        return build.map { "\(version) (\($0))" } ?? version
    }
}
