import Foundation

public struct ImportResult: Equatable, Sendable {
    public var profile: Profile
    /// Base rules such as `(import "bsd.sb")` found in the old profile; they belong in the compile environment.
    public var baseRules: [String]
    /// Rules the new model cannot express. Shown to the user; never silently dropped.
    public var unimportedRules: [String]
}

/// Imports the hand-built Knodo sandbox (allowlist.json + generated policy.sb) as revision 1,
/// keeping every grant it already had so migration never runs unprotected or silently narrows.
public enum LegacyImporter {
    private struct Allowlist: Decodable {
        let readWriteRoots: [String]
        let readOnlyRoots: [String]

        enum CodingKeys: String, CodingKey {
            case readWriteRoots = "read_write_roots"
            case readOnlyRoots = "read_only_roots"
        }
    }

    public static func importInstallation(profileID: String, allowlistJSON: Data, policySBPL: String) throws -> ImportResult {
        let allowlist = try JSONDecoder().decode(Allowlist.self, from: allowlistJSON)
        var files = allowlist.readWriteRoots.map { FileGrant(path: $0, kind: .directory, access: .readWrite) }
            + allowlist.readOnlyRoots.map { FileGrant(path: $0, kind: .directory, access: .readOnly) }
        var exec: [ExecGrant] = []
        var network = NetworkPolicy()
        var unrestrictedExec = false
        var extraRules: [String] = []
        var baseRules: [String] = []
        var unimported: [String] = []

        for raw in policySBPL.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix(";") || line == "(version 1)" || line == "(deny default)"
                || line == "(deny network-outbound (remote tcp \"localhost:*\"))" {
                continue
            }
            if line.hasPrefix("(import ") {
                baseRules.append(line)
            } else if let grant = fileGrant(line) {
                files.append(grant)
            } else if line == "(allow process-exec)" {
                unrestrictedExec = true
            } else if let path = quotedArgument(line, prefix: "(allow process-exec (literal ", suffix: "))") {
                exec.append(ExecGrant(path: path))
            } else if line == "(allow network-outbound (remote tcp))" {
                network.outboundTCP = .allowed
            } else if let portText = quotedArgument(line, prefix: "(allow network-outbound (remote tcp ", suffix: "))"),
                      portText.hasPrefix("localhost:"), let port = Int(portText.dropFirst("localhost:".count)) {
                network.loopbackTCPConnect.append(port)
            } else if PolicyCompiler.isSingleAllowForm(line) {
                extraRules.append(line)
            } else {
                unimported.append(line)
            }
        }

        var seen = Set<FileGrant>()
        files = files.filter { seen.insert($0).inserted }
        let profile = Profile(id: profileID, revision: 1, mode: .enforce, templates: [], files: files, exec: exec, network: network,
                              unrestrictedExec: unrestrictedExec, extraRules: extraRules)
        return ImportResult(profile: profile, baseRules: baseRules, unimportedRules: unimported)
    }

    private static func fileGrant(_ line: String) -> FileGrant? {
        for (operations, access) in [("file-read* file-write*", Access.readWrite), ("file-write*", .readWrite), ("file-read*", .readOnly)] {
            for (filter, kind) in [("subpath", PathKind.directory), ("literal", .file)] {
                if let path = quotedArgument(line, prefix: "(allow \(operations) (\(filter) ", suffix: "))") {
                    return FileGrant(path: path, kind: kind, access: access)
                }
            }
        }
        return nil
    }

    /// Extracts and unescapes the single SBPL string between `prefix` and `suffix`.
    private static func quotedArgument(_ line: String, prefix: String, suffix: String) -> String? {
        guard line.hasPrefix(prefix + "\""), line.hasSuffix("\"" + suffix) else { return nil }
        let body = line.dropFirst(prefix.count + 1).dropLast(suffix.count + 1)
        var result = ""
        var escaped = false
        for char in body {
            if escaped {
                result.append(char)
                escaped = false
            } else if char == "\\" {
                escaped = true
            } else if char == "\"" {
                return nil
            } else {
                result.append(char)
            }
        }
        return escaped ? nil : result
    }
}

/// What a migration will keep, change and leave unhandled, shown before anything is saved.
public enum MigrationPreview {
    public static func lines(for result: ImportResult, templates: [Template], environment: CompileEnvironment) -> [String] {
        let profile = result.profile
        let overview = EffectivePermissions.overview(of: profile, templates: templates, environment: environment)
        var lines = ["保留现有的全部访问权限，不会扩大，也不会悄悄收窄："]
        for entry in overview.files {
            let source: String
            switch entry.sources.first?.source {
            case .legacy?: source = "（旧规则）"
            case .program?: source = "（启动需要）"
            default: source = ""
            }
            lines.append("  \(entry.ownAccess == .readWrite ? "读写" : "只读") \(entry.path)\(source)")
        }
        if profile.unrestrictedExec { lines.append("  允许运行任意程序（原安装就是这样）") }
        for exec in overview.exec where !profile.unrestrictedExec { lines.append("  运行 \(exec.path)") }
        if profile.network.outboundTCP == .allowed { lines.append("  允许对外 TCP 连接") }
        if !profile.network.loopbackTCPConnect.isEmpty {
            lines.append("  连接本机端口 \(profile.network.loopbackTCPConnect.map(String.init).joined(separator: "、"))")
        }
        if !overview.unverifiedLegacy.isEmpty {
            lines.append("以下旧规则无法核对，会原样保留，迁移后会提示逐条处理：")
            lines += overview.unverifiedLegacy.map { "  " + $0 }
        }
        if !result.unimportedRules.isEmpty {
            lines.append("以下规则无法导入，不会生效，请在迁移后手动核对：")
            lines += result.unimportedRules.map { "  " + $0 }
        }
        if let launch = profile.launch {
            if let original = launch.originalLabel {
                lines.append("启动方式：点“启动程序”时，先备份原启动项 \(original)，再由 AgentGuard 启动 \(launch.executable)；以后可以随时恢复原启动方式")
            } else {
                lines.append("启动方式：由 AgentGuard 启动 \(launch.executable)")
            }
        }
        lines.append("原安装留下的运行记录不会作为可信来源，只保留用于诊断")
        return lines
    }
}
