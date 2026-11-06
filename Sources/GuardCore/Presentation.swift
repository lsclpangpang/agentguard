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
        case let .invalidPattern(text, error):
            return "\(text) 不是可用的通配路径：\(error.displayText)"
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
        case .applied(running: true): return "当前权限已生效"
        case .applied(running: false): return "未运行"
        case let .oldInstancesAlive(residual, _): return "运行中 · 权限待更新（旧副本还有 \(residual.count) 个进程）"
        case .unconfirmed: return "暂时无法确认旧副本是否已退出"
        case .awaitingVerification: return "正在确认保护"
        case .verificationFailed: return "保护未通过确认"
        case .inconsistent: return "运行中的权限与保存的不一致"
        }
    }
}

extension Mode {
    public var displayName: String {
        switch self {
        case .enforce: return "保护中"
        case .restrictedLearning: return "保护中 · 记录更多活动"
        case .unprotectedObserve: return "无保护观察"
        }
    }
}

/// One program's state in three parts: what is happening now, what it means, and what to do.
public struct ProgramStatusSummary: Equatable, Sendable {
    public enum Next: Equatable, Sendable {
        case start
        case restartAndApply
        case restart
        case checkAndRecover
        case stopUnmanaged
    }

    public var headline: String
    public var impact: String
    public var next: Next?
    public var level: StatusLevel

    public init(headline: String, impact: String, next: Next?, level: StatusLevel) {
        self.headline = headline
        self.impact = impact
        self.next = next
        self.level = level
    }

    public static func evaluate(_ status: ProfileStatusReport?, freshness: StatusFreshness, programName: String, hasLaunch: Bool) -> ProgramStatusSummary {
        guard let status, !freshness.isStale else {
            return ProgramStatusSummary(headline: "状态待确认", impact: "最近没有收到 Helper 的确认，下面显示的可能不是当前情况。",
                                        next: .checkAndRecover, level: .attention)
        }
        var summary: ProgramStatusSummary
        switch status.revisionState {
        case .applied(running: true) where !status.untrackedInstances.isEmpty:
            summary = ProgramStatusSummary(headline: "运行中 · 暂时无法确认所有运行副本",
                                           impact: "Helper 重启或活动记录中断前启动的子程序可能没有被跟踪，不能确认它们都受这份权限限制。",
                                           next: .restart, level: .attention)
        case .applied(running: true):
            summary = ProgramStatusSummary(headline: "运行中 · 当前权限已生效", impact: "已从外部核对，\(programName) 按下面的权限运行。", next: nil, level: .allGood)
        case .applied(running: false):
            summary = ProgramStatusSummary(headline: "未运行", impact: "启动后按下面的权限运行。", next: hasLaunch ? .start : nil, level: .allGood)
        case .oldInstancesAlive:
            summary = ProgramStatusSummary(headline: "运行中 · 权限待更新",
                                           impact: "新权限已保存，但 \(programName) 仍在使用之前的权限。重启 \(programName) 后生效，旧权限才会收回。",
                                           next: hasLaunch ? .restartAndApply : .restart, level: .attention)
        case .unconfirmed:
            summary = ProgramStatusSummary(headline: "暂时无法确认旧副本是否已退出",
                                           impact: "活动记录中断，旧权限可能仍在被使用。", next: .checkAndRecover, level: .attention)
        case .awaitingVerification:
            summary = ProgramStatusSummary(headline: "正在确认保护", impact: "\(programName) 已启动，正在核对它实际受到的限制。", next: nil, level: .attention)
        case .verificationFailed:
            summary = ProgramStatusSummary(headline: "保护未通过确认",
                                           impact: "运行中的 \(programName) 没有按下面的权限受到限制，原因见下方。", next: .restart, level: .problem)
        case .inconsistent:
            summary = ProgramStatusSummary(headline: "运行中的权限与保存的不一致", impact: "无法确认 \(programName) 当前受到的限制。",
                                           next: .restart, level: .problem)
        }
        if !status.unmanagedProcesses.isEmpty {
            summary.impact += " 另有 \(status.unmanagedProcesses.count) 个副本没有经过 AgentGuard 运行，不受保护。"
            summary.level = .problem
            if summary.next == nil { summary.next = .stopUnmanaged }
        }
        return summary
    }
}

extension ProgramStatusSummary.Next {
    public var title: String {
        switch self {
        case .start: return "启动程序"
        case .restartAndApply: return "重启并应用"
        case .restart: return "重启程序"
        case .checkAndRecover: return "检查并恢复"
        case .stopUnmanaged: return "查看未受保护的副本"
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

extension PatternError {
    public var displayText: String {
        switch self {
        case let .path(error): return error.displayText
        case .noWildcard: return "没有通配符，请按普通路径添加"
        case let .invalidComponent(component): return "“\(component)”无效：** 只能单独作为一级目录，路径里不能有引号或换行"
        case .tooBroad: return "通配符紧跟在根目录或主目录下，会放开那里的几乎所有内容，请写得更具体，例如 ~/.claude*.jsonl"
        }
    }
}
