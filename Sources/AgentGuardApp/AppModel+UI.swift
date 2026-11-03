#if os(macOS)
import AppKit
import Foundation
import GuardCore

/// View-facing helpers kept out of AppModel.swift.
extension AppModel {
    func status(for id: String) -> ProfileStatusReport? {
        report?.profiles.first { $0.profileID == id }
    }

    var helperProblems: [String] {
        report?.collectorProblems ?? []
    }

    var needsFullDiskAccess: Bool {
        helperProblems.contains { $0.contains("未授权") }
    }

    /// Accepts several pending items as one change, so they need a single confirmation.
    func acceptAll(_ items: [PendingItem], for id: String) {
        guard !items.isEmpty else { return }
        let templates = self.templates
        edit(id) { profile in
            for item in items { Self.apply(item, to: &profile, templates: templates) }
        }
    }

    func removeFile(_ grant: FileGrant, from id: String) {
        edit(id) { profile in profile.files.removeAll { $0 == grant } }
    }

    /// 切换单条文件授权的读写级别。放宽（只读 → 读写）会走正常的修订流程：
    /// 变更预览 + 确认，必要时要求系统授权。
    func setFileAccess(_ grant: FileGrant, to access: Access, in id: String) {
        guard grant.access != access else { return }
        // 同一路径的写权限也可能来自运行时模板或状态目录，编译结果取最宽的那条，收回这一条不会生效。
        let hint = access == .readOnly ? "没有变化：\(grant.path) 的写权限还来自已启用的运行时模板或其他授权，要收回请先停用对应模板" : nil
        edit(id, unchangedHint: hint) { profile in
            guard let index = profile.files.firstIndex(of: grant) else { return }
            profile.files[index].access = access
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
#endif
