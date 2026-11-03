public enum PolicyChange: Hashable, Sendable {
    case modeChanged(from: Mode, to: Mode)
    case fileAdded(EffectiveFileGrant)
    case fileRemoved(EffectiveFileGrant)
    case fileAccessChanged(path: String, from: Access, to: Access)
    case fileKindChanged(path: String, from: PathKind, to: PathKind)
    case fileSecretsFlagChanged(path: String, to: Bool)
    case execAdded(EffectiveExecGrant)
    case execRemoved(EffectiveExecGrant)
    case execHashChanged(path: String, from: String?, to: String?)
    case loopbackPortAdded(Int)
    case loopbackPortRemoved(Int)
    case outboundTCPChanged(to: Toggle)
    case listenChanged(to: Toggle)
    case udpChanged(to: Toggle)
    case unrestrictedExecChanged(to: Bool)
    case extraRuleAdded(String)
    case extraRuleRemoved(String)
    case launchChanged(to: LaunchSettings?)
    case programAdded(String)
    case programRemoved(String)

    /// Whether this change gives the managed software more capability than before.
    public var expands: Bool {
        switch self {
        case let .modeChanged(from, to): return !from.liftsBoundary && to.liftsBoundary
        case .fileAdded, .execAdded, .loopbackPortAdded, .extraRuleAdded: return true
        case .fileRemoved, .execRemoved, .loopbackPortRemoved, .fileSecretsFlagChanged, .extraRuleRemoved: return false
        // Only marks what to watch; the program's exec and read grants carry the widening.
        case .programAdded, .programRemoved: return false
        case let .unrestrictedExecChanged(to): return to
        case let .launchChanged(to): return to != nil
        case let .fileAccessChanged(_, _, to): return to == .readWrite
        case let .fileKindChanged(_, _, to): return to == .directory
        // Dropping a hash or swapping it for another both admit a binary that was not admitted before.
        case let .execHashChanged(_, from, _): return from != nil
        case let .outboundTCPChanged(to), let .listenChanged(to), let .udpChanged(to): return to == .allowed
        }
    }
}

public struct PolicyDiff: Hashable, Sendable {
    public let changes: [PolicyChange]

    public init(from old: EffectivePolicy, to new: EffectivePolicy) {
        var changes: [PolicyChange] = []
        if old.mode != new.mode { changes.append(.modeChanged(from: old.mode, to: new.mode)) }
        changes += Self.fileChanges(old.files, new.files)
        if old.launch != new.launch { changes.append(.launchChanged(to: new.launch)) }
        let oldPrograms = Set(old.programs), newPrograms = Set(new.programs)
        changes += newPrograms.subtracting(oldPrograms).sorted().map(PolicyChange.programAdded)
        changes += oldPrograms.subtracting(newPrograms).sorted().map(PolicyChange.programRemoved)
        if old.unrestrictedExec != new.unrestrictedExec { changes.append(.unrestrictedExecChanged(to: new.unrestrictedExec)) }
        changes += Self.execChanges(old.exec, new.exec)
        let oldPorts = Set(old.network.loopbackTCPConnect), newPorts = Set(new.network.loopbackTCPConnect)
        changes += newPorts.subtracting(oldPorts).sorted().map(PolicyChange.loopbackPortAdded)
        changes += oldPorts.subtracting(newPorts).sorted().map(PolicyChange.loopbackPortRemoved)
        if old.network.outboundTCP != new.network.outboundTCP { changes.append(.outboundTCPChanged(to: new.network.outboundTCP)) }
        if old.network.listen != new.network.listen { changes.append(.listenChanged(to: new.network.listen)) }
        if old.network.udp != new.network.udp { changes.append(.udpChanged(to: new.network.udp)) }
        let oldRules = Set(old.extraRules), newRules = Set(new.extraRules)
        changes += newRules.subtracting(oldRules).sorted().map(PolicyChange.extraRuleAdded)
        changes += oldRules.subtracting(newRules).sorted().map(PolicyChange.extraRuleRemoved)
        self.changes = changes
    }

    public var requiresAuthorization: Bool { changes.contains { $0.expands } }

    /// Binds an approval to exactly these changes.
    public var digest: String { SHA256.hex(of: changes.map(Self.canonicalLine).joined(separator: "\n")) }

    public var summaryLines: [String] { changes.map(Self.summary) }

    private static func fileChanges(_ old: [EffectiveFileGrant], _ new: [EffectiveFileGrant]) -> [PolicyChange] {
        let before = Dictionary(old.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        let after = Dictionary(new.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var changes: [PolicyChange] = []
        for path in Set(before.keys).union(after.keys).sorted() {
            switch (before[path], after[path]) {
            case let (nil, added?): changes.append(.fileAdded(added))
            case let (removed?, nil): changes.append(.fileRemoved(removed))
            case let (a?, b?):
                if a.kind != b.kind { changes.append(.fileKindChanged(path: path, from: a.kind, to: b.kind)) }
                if a.access != b.access { changes.append(.fileAccessChanged(path: path, from: a.access, to: b.access)) }
                if a.readsSecrets != b.readsSecrets { changes.append(.fileSecretsFlagChanged(path: path, to: b.readsSecrets)) }
            case (nil, nil): break
            }
        }
        return changes
    }

    private static func execChanges(_ old: [EffectiveExecGrant], _ new: [EffectiveExecGrant]) -> [PolicyChange] {
        let before = Dictionary(old.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        let after = Dictionary(new.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        var changes: [PolicyChange] = []
        for path in Set(before.keys).union(after.keys).sorted() {
            switch (before[path], after[path]) {
            case let (nil, added?): changes.append(.execAdded(added))
            case let (removed?, nil): changes.append(.execRemoved(removed))
            case let (a?, b?) where a.sha256 != b.sha256: changes.append(.execHashChanged(path: path, from: a.sha256, to: b.sha256))
            default: break
            }
        }
        return changes
    }

    private static func canonicalLine(_ change: PolicyChange) -> String {
        func file(_ g: EffectiveFileGrant) -> String { "\(g.path)|\(g.kind.rawValue)|\(g.access.rawValue)|\(g.readsSecrets)" }
        switch change {
        case let .modeChanged(from, to): return "mode|\(from.rawValue)|\(to.rawValue)"
        case let .fileAdded(g): return "file+|\(file(g))"
        case let .fileRemoved(g): return "file-|\(file(g))"
        case let .fileAccessChanged(path, from, to): return "file-access|\(path)|\(from.rawValue)|\(to.rawValue)"
        case let .fileKindChanged(path, from, to): return "file-kind|\(path)|\(from.rawValue)|\(to.rawValue)"
        case let .fileSecretsFlagChanged(path, to): return "file-secrets|\(path)|\(to)"
        case let .execAdded(g): return "exec+|\(g.path)|\(g.sha256 ?? "-")"
        case let .execRemoved(g): return "exec-|\(g.path)|\(g.sha256 ?? "-")"
        case let .execHashChanged(path, from, to): return "exec-hash|\(path)|\(from ?? "-")|\(to ?? "-")"
        case let .loopbackPortAdded(port): return "port+|\(port)"
        case let .loopbackPortRemoved(port): return "port-|\(port)"
        case let .outboundTCPChanged(to): return "outbound|\(to.rawValue)"
        case let .listenChanged(to): return "listen|\(to.rawValue)"
        case let .udpChanged(to): return "udp|\(to.rawValue)"
        case let .unrestrictedExecChanged(to): return "exec-any|\(to)"
        case let .extraRuleAdded(rule): return "rule+|\(rule)"
        case let .extraRuleRemoved(rule): return "rule-|\(rule)"
        case let .launchChanged(to):
            guard let to else { return "launch|-" }
            return "launch|\(to.executable)|\(to.arguments.joined(separator: "\u{1f}"))|\(to.workingDirectory ?? "-")|\(to.originalLabel ?? "-")|\(to.restartOnCleanExit)"
        case let .programAdded(path): return "program+|\(path)"
        case let .programRemoved(path): return "program-|\(path)"
        }
    }

    private static func summary(_ change: PolicyChange) -> String {
        func label(_ g: EffectiveFileGrant) -> String {
            let base: String
            switch (g.kind, g.access) {
            case (.directory, .readOnly): base = "只读目录"
            case (.directory, .readWrite): base = "读写目录"
            case (.file, .readOnly): base = "只读文件"
            case (.file, .readWrite): base = "读写文件"
            }
            return "\(base) \(g.path)" + (g.readsSecrets ? "（允许读取凭证）" : "")
        }
        func access(_ a: Access) -> String { a == .readWrite ? "读写" : "只读" }
        func kind(_ k: PathKind) -> String { k == .directory ? "目录" : "文件" }
        func toggle(_ t: Toggle) -> String { t == .allowed ? "允许" : "禁止" }
        func mode(_ m: Mode) -> String {
            switch m {
            case .enforce: return "强制保护"
            case .restrictedLearning: return "受限学习"
            case .unprotectedObserve: return "无保护观察"
            }
        }
        switch change {
        case let .modeChanged(from, to): return "~ 模式：\(mode(from)) → \(mode(to))"
        case let .fileAdded(g): return "+ \(label(g))"
        case let .fileRemoved(g): return "- \(label(g))"
        case let .fileAccessChanged(path, from, to): return "~ \(path)：\(access(from)) → \(access(to))"
        case let .fileKindChanged(path, from, to): return "~ \(path)：\(kind(from)) → \(kind(to))"
        case let .fileSecretsFlagChanged(path, to): return "~ \(path)：" + (to ? "标记为凭证" : "取消凭证标记")
        case let .execAdded(g): return "+ 可执行 \(g.path)" + (g.sha256 == nil ? "" : "（限定 SHA-256）")
        case let .execRemoved(g): return "- 可执行 \(g.path)"
        case let .execHashChanged(path, from, to):
            if to == nil { return "~ 可执行 \(path)：取消哈希限定" }
            return from == nil ? "~ 可执行 \(path)：改为限定哈希" : "~ 可执行 \(path)：更换哈希"
        case let .loopbackPortAdded(port): return "+ 本机 TCP 端口 \(port)"
        case let .loopbackPortRemoved(port): return "- 本机 TCP 端口 \(port)"
        case let .outboundTCPChanged(to): return "~ 对外 TCP 连接：\(toggle(to))"
        case let .listenChanged(to): return "~ 监听端口：\(toggle(to))"
        case let .udpChanged(to): return "~ UDP：\(toggle(to))"
        case let .unrestrictedExecChanged(to): return (to ? "+" : "-") + " 允许执行任意程序"
        case let .extraRuleAdded(rule): return "+ 原样规则 \(rule)"
        case let .extraRuleRemoved(rule): return "- 原样规则 \(rule)"
        case let .launchChanged(to):
            guard let to else { return "- 启动程序" }
            return "~ 启动程序：" + ([to.executable] + to.arguments).joined(separator: " ")
        case let .programAdded(path): return "+ 受管程序 \(path)"
        case let .programRemoved(path): return "- 受管程序 \(path)"
        }
    }
}
