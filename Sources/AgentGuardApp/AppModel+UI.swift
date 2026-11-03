#if os(macOS)
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
        edit(id) { profile in
            guard let index = profile.files.firstIndex(of: grant) else { return }
            profile.files[index].access = access
        }
    }

    /// 按路径添加受管程序（界面上的输入框用；文件选择框仍保留）。
    func addProgram(path: String, to id: String) {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let expanded = (trimmed as NSString).expandingTildeInPath
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isDirectory), !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: expanded) else {
            lastError = "\(trimmed) 不是可执行文件。脚本请填它实际启动的程序（例如 node、python3）。"
            return
        }
        edit(id) { profile in
            if !profile.programs.contains(expanded) { profile.programs.append(expanded) }
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
