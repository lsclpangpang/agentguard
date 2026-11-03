#if os(macOS)
import GuardCore
import SwiftUI

/// Colors, symbols and wording shared by every screen.
enum Theme {
    static func color(_ level: StatusLevel) -> Color {
        switch level {
        case .allGood: return .green
        case .attention: return .orange
        case .problem: return .red
        }
    }

    static func symbol(_ level: StatusLevel) -> String {
        switch level {
        case .allGood: return "checkmark.shield.fill"
        case .attention: return "exclamationmark.shield.fill"
        case .problem: return "xmark.shield.fill"
        }
    }

    static func title(_ level: StatusLevel) -> String {
        switch level {
        case .allGood: return "全部正常"
        case .attention: return "需要关注"
        case .problem: return "存在问题"
        }
    }
}

extension Mode {
    var tint: Color {
        switch self {
        case .enforce: return .green
        case .restrictedLearning: return .blue
        case .unprotectedObserve: return .red
        }
    }

    var symbol: String {
        switch self {
        case .enforce: return "lock.shield.fill"
        case .restrictedLearning: return "magnifyingglass"
        case .unprotectedObserve: return "exclamationmark.triangle.fill"
        }
    }

    var explanation: String {
        switch self {
        case .enforce: return "只放行已允许的访问"
        case .restrictedLearning: return "未允许的访问被拒绝并记为待定项"
        case .unprotectedObserve: return "不限制，只记录"
        }
    }
}

extension RevisionState {
    var tint: Color {
        switch self {
        case .applied(running: true): return .green
        case .applied(running: false): return .secondary
        case .verificationFailed, .inconsistent: return .red
        case .oldInstancesAlive, .unconfirmed, .awaitingVerification: return .orange
        }
    }
}

struct TemplateInfo {
    let title: String
    let detail: String
    let symbol: String

    static func of(_ id: String) -> TemplateInfo {
        switch id {
        case "system-base": return TemplateInfo(title: "系统基础", detail: "系统库、常用命令与基本设备", symbol: "gearshape.2")
        case "claude-code": return TemplateInfo(title: "Claude Code", detail: "~/.claude 只读，会话与临时目录可写", symbol: "sparkles")
        case "codex": return TemplateInfo(title: "Codex", detail: "~/.codex 只读，会话与日志可写", symbol: "terminal")
        case "homebrew-python": return TemplateInfo(title: "Homebrew Python", detail: "解释器、标准库与依赖，全部只读", symbol: "chevron.left.forwardslash.chevron.right")
        case "git": return TemplateInfo(title: "Git", detail: "git、命令行工具，.gitconfig 与 .ssh 只读", symbol: "arrow.triangle.branch")
        default: return TemplateInfo(title: id, detail: "", symbol: "square.stack.3d.up")
        }
    }
}

extension Suggestion {
    var symbol: String {
        switch self {
        case .template: return "square.stack.3d.up.fill"
        case let .file(_, kind, _): return kind == .directory ? "folder.fill" : "doc.fill"
        case .exec: return "play.square.fill"
        case .loopbackPort: return "point.3.connected.trianglepath.dotted"
        case .outboundTCP: return "globe"
        case .listen: return "antenna.radiowaves.left.and.right"
        }
    }

    var title: String {
        switch self {
        case let .template(id): return "启用模板“\(TemplateInfo.of(id).title)”"
        case let .file(path, kind, access): return "\(access == .readWrite ? "读写" : "读取")\(kind == .directory ? "目录" : "文件") \(path)"
        case let .exec(path): return "执行 \(path)"
        case let .loopbackPort(port): return "连接本机端口 \(port)"
        case .outboundTCP: return "对外 TCP 连接"
        case .listen: return "监听端口"
        }
    }
}
#endif
