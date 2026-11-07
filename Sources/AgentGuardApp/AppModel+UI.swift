#if os(macOS)
import AppKit
import SwiftUI
import Foundation
import GuardCore

/// View-facing helpers kept out of AppModel.swift.
extension AppModel {
    func status(for id: String) -> ProfileStatusReport? {
        report?.profiles.first { $0.profileID == id }
    }

    func legacyAnalysis(_ profile: Profile) -> LegacyRuleAnalysis {
        LegacyRuleAnalysis(rules: profile.extraRules, resolver: config.environment.resolver, caseInsensitive: config.environment.caseInsensitive)
    }

    var helperProblems: [String] {
        report?.collectorProblems ?? []
    }

    var needsFullDiskAccess: Bool {
        helperProblems.contains { $0.contains("未授权") }
    }

    /// Accepts several pending items as one change, so they need a single confirmation.
    /// The confirmation lists every permission actually added. Saving does not redo what already failed.
    func acceptAll(_ items: [PendingItem], for id: String) {
        guard !items.isEmpty, var profile = profile(id) else { return }
        for item in items { Self.apply(item, to: &profile, templates: templates) }
        profile.files = normalizedFileGrants(profile.files)
        profile.revision += 1
        let running = !(status(for: id)?.runningInstances.isEmpty ?? true)
        Task {
            guard case .applied = await submitAsync(profile) else { return }
            lastNotice = running ? "新权限已保存。重启 \(id) 后生效；之前失败的操作不会自动重做，重启后请重新尝试。"
                                 : "新权限已保存，下次启动 \(id) 时生效。"
        }
    }

    /// Revokes a file grant together with everything else of the user's that reaches only inside it,
    /// and legacy rules at or below it. Grants that keep access from elsewhere (a parent directory,
    /// a template, migrated rules) are named in the confirmation, so it is not taken for a full revocation.
    func removeFile(_ grant: FileGrant, from id: String) {
        guard let profile = profile(id) else { return }
        let check = try? EffectivePermissions.remaining(at: grant.path, kind: grant.kind, keeping: nil, excluding: grant, in: profile,
                                                        templates: templates, environment: config.environment)
        // Legacy rules are compared with literal paths; a pattern's reach is shown by the sandbox check instead.
        let legacy = grant.pattern ? nil : try? legacyRevocation(grant.path, keeping: nil, in: profile)
        var warnings: [String] = []
        if check == nil {
            // A grant whose path cannot be read is exactly the one to delete, so it is removed without the analysis.
            warnings.append("注意：\(grant.path) 不是可用的路径，无法核对其他授权是否仍允许访问它")
        }
        let inner = check?.innerUserGrants ?? []
        warnings += inner.map { "- 同时移除 \($0.path)（在 \(grant.path) 之内）" }
        warnings += Self.remainingWarnings(check, path: grant.path, revoked: "访问")
        if let legacy { warnings += Self.legacyWarnings(legacy, path: grant.path, revoked: "访问") }
        edit(id, warnings: warnings) { profile in
            profile.files.removeAll { $0 == grant || inner.contains($0) }
            if let legacy { profile.extraRules = legacy.extraRules }
        }
    }

    /// Legacy rules at or below the path are dropped with it; any that reach it from above, or whose
    /// reach is unknown, are named before the change so it is not mistaken for a full revocation.
    private func legacyRevocation(_ path: String, keeping access: Access?, in profile: Profile) throws -> LegacyRevocation {
        try LegacyRevocation.revoke(path, keeping: access, from: profile.extraRules, resolver: config.environment.resolver,
                                    caseInsensitive: config.environment.caseInsensitive)
    }

    nonisolated static func legacyWarnings(_ legacy: LegacyRevocation, path: String, revoked: String) -> [String] {
        guard !legacy.stillGranting.isEmpty else { return [] }
        return ["注意：以下旧规则可能仍允许\(revoked) \(path)，这次修改不能保证收回："] + legacy.stillGranting.map { "  " + $0 }
    }

    nonisolated static func remainingWarnings(_ check: RevocationCheck?, path: String, revoked: String) -> [String] {
        guard let check, !check.isComplete else { return [] }
        var lines = ["注意：以下授权仍允许\(revoked) \(path) 或其中的内容，这次修改不能完全收回："]
        lines += check.outerUserGrants.map { "  \($0.path)（你添加的\($0.access == .readWrite ? "读写" : "只读")授权，需要单独修改）" }
        lines += check.fixed.map { "  \($0.path)（\($0.source.displayName)）" }
        lines += check.unverifiedRules.map { "  尚未核对的旧规则：\($0)" }
        return lines
    }

    /// 切换单条文件授权的读写级别。放宽（只读 → 读写）会走正常的修订流程：
    /// 变更预览 + 确认，必要时要求系统授权。收回写权限时，只在它之内的其他写授权一并改为只读。
    func setFileAccess(_ grant: FileGrant, to access: Access, in id: String) {
        guard grant.access != access, let profile = profile(id) else { return }
        do {
            var files = try FileGrantMerger.changingAccess(of: grant, to: access, in: profile.files,
                                                           resolver: config.environment.resolver,
                                                           caseInsensitive: config.environment.caseInsensitive)
            guard access == .readOnly else {
                edit(id) { $0.files = files }
                return
            }
            let check = try? EffectivePermissions.remaining(at: grant.path, kind: grant.kind, keeping: .readOnly, excluding: grant, in: profile,
                                                            templates: templates, environment: config.environment)
            let inner = check?.innerUserGrants ?? []
            for index in files.indices where inner.contains(files[index]) { files[index].access = .readOnly }
            var warnings = inner.map { "~ 同时改为只读 \($0.path)（在 \(grant.path) 之内）" }
            warnings += Self.remainingWarnings(check, path: grant.path, revoked: "写入")
            let legacy = grant.pattern ? nil : try legacyRevocation(grant.path, keeping: .readOnly, in: profile)
            if let legacy { warnings += Self.legacyWarnings(legacy, path: grant.path, revoked: "写入") }
            let hint = check?.isComplete == false ? "没有变化：\(grant.path) 的写权限还来自其他授权，见上方说明" : nil
            edit(id, unchangedHint: hint, warnings: warnings) {
                $0.files = files
                if let legacy { $0.extraRules = legacy.extraRules }
            }
        } catch {
            lastError = "没有保存：" + ((error as? PathError)?.displayText ?? String(describing: error))
        }
    }

    /// Adds a wildcard grant such as `~/.claude*.jsonl`. Returns the message to show in the sheet when
    /// the text is not a usable pattern, so the sheet stays open with the input intact.
    func addPattern(_ text: String, kind: PathKind, access: Access, to id: String) -> String? {
        let expanded = text == "~" ? config.home : text.hasPrefix("~/") ? config.home + text.dropFirst(1) : text
        let environment = config.environment
        do {
            let pattern = try PathPattern(expanded, resolver: environment.resolver)
            try pattern.validateBreadth(home: try CanonicalPath(config.home, resolver: environment.resolver), caseInsensitive: environment.caseInsensitive)
            let sensitive = SensitivePaths(home: config.home).overlapsSensitive(pattern, kind: kind, caseInsensitive: environment.caseInsensitive)
            let grant = FileGrant(path: expanded, kind: kind, access: access, readsSecrets: sensitive, pattern: true)
            edit(id) { profile in profile.files = normalizedFileGrants(profile.files + [grant]) }
            return nil
        } catch let error as PatternError {
            return error.displayText
        } catch let error as PathError {
            return error.displayText
        } catch {
            return String(describing: error)
        }
    }

    /// 按路径添加受管程序。校验不通过时返回要在弹窗里显示的原因，弹窗不关、输入不丢。
    func addProgram(path: String, to id: String) -> String? {
        switch validateProgram(path) {
        case let .failure(error):
            return ProgramPath.message(for: error)
        case let .success(real):
            edit(id) { profile in
                if !profile.programs.contains(real) { profile.programs.append(real) }
            }
            return nil
        }
    }

    func setTemplate(_ template: Template, enabled: Bool, in id: String) {
        edit(id) { profile in
            profile.templates.removeAll { $0.id == template.id }
            if enabled { profile.templates.append(TemplateRef(id: template.id, version: template.version)) }
        }
    }

    nonisolated static func apply(_ item: PendingItem, to profile: inout Profile, templates: [Template]) {
        switch item.suggestion {
        case let .template(templateID):
            if let template = templates.first(where: { $0.id == templateID }), !profile.templates.contains(where: { $0.id == templateID }) {
                profile.templates.append(TemplateRef(id: template.id, version: template.version))
            }
        case let .file(path, kind, access):
            profile.files.append(FileGrant(path: path, kind: kind, access: access, readsSecrets: item.sensitive))
        case let .exec(path):
            profile.exec.append(ExecGrant(path: path))
        case let .loopbackPort(port):
            if !profile.network.loopbackTCPConnect.contains(port) { profile.network.loopbackTCPConnect.append(port) }
        case .outboundTCP:
            profile.network.outboundTCP = .allowed
        case .listen:
            profile.network.listen = .allowed
        }
    }
}

extension PermissionSource {
    var displayName: String {
        switch self {
        case .user: return "你添加的"
        case let .template(id): return "推荐权限组“\(TemplateInfo.of(id).title)”"
        case .program: return "程序启动所需"
        case .stateDirectory: return "程序的工作目录"
        case .legacy: return "从旧安装迁移的规则"
        }
    }
}
#endif
