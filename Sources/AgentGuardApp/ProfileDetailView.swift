#if os(macOS)
import GuardCore
import SwiftUI

struct ProfileDetailView: View {
    @EnvironmentObject var model: AppModel
    let profileID: String

    var body: some View {
        if let profile = model.profile(profileID) {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 14) {
                    ProfileHeader(profile: profile, status: model.status(for: profileID))
                    HStack(spacing: 12) {
                        Text("保护模式").font(.callout.weight(.medium))
                        Picker("保护模式", selection: Binding(get: { profile.mode }, set: { mode in model.edit(profileID) { $0.mode = mode } })) {
                            Text(Mode.restrictedLearning.displayName).tag(Mode.restrictedLearning)
                            Text(Mode.enforce.displayName).tag(Mode.enforce)
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(maxWidth: 260)
                        .help("受限学习：未允许的访问被拒绝并记为待定项。强制保护：只放行已允许的访问。")
                        Spacer(minLength: 0)
                    }
                }
                .padding(20)
                .frame(maxWidth: 900, alignment: .leading)
                .frame(maxWidth: .infinity)

                Divider()

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        PendingCard(profileID: profileID, items: model.pending[profileID] ?? [])
                        FilesCard(profile: profile)
                        TemplatesCard(profile: profile)
                        ProgramsAndNetworkCard(profile: profile)
                        if profile.launch != nil { LaunchCard(profile: profile) }
                    }
                    .padding(20)
                    .frame(maxWidth: 900, alignment: .leading)
                    .frame(maxWidth: .infinity)
                }
                .clipped()
            }
            .background(Color(nsColor: .windowBackgroundColor))
            .navigationTitle(profileID)
        }
    }
}

private struct ProfileHeader: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let status: ProfileStatusReport?
    @State private var copied = false

    private var command: String { "guard run \(profile.id) -- <命令>" }

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            IconTile(systemImage: profile.mode.symbol, tint: profile.mode.tint, size: 40)
            VStack(alignment: .leading, spacing: 8) {
                Text(profile.id).font(.title2.weight(.semibold)).lineLimit(2)
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 6) { statusChips }
                    VStack(alignment: .leading, spacing: 6) { statusChips }
                }
                Text(profile.mode.explanation).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Text(command).font(.system(.callout, design: .monospaced))
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    Button {
                        Pasteboard.copy("guard run \(profile.id) -- ")
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("复制启动命令")
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.05)))
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder private var statusChips: some View {
        Chip(text: profile.mode.displayName, systemImage: profile.mode.symbol, tint: profile.mode.tint)
        if model.restartingProfiles.contains(profile.id) {
            // 状态从“已停止/待生效”跳到“运行”中间有几秒，这里给出明确的过渡提示。
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("正在启动…").font(.callout).foregroundStyle(.secondary)
            }
        } else if let status {
            Chip(text: status.revisionState.displayText, tint: status.revisionState.tint)
            Chip(text: "修订 \(status.savedRevision)")
            if !status.runningInstances.isEmpty {
                Chip(text: "\(status.runningInstances.count) 个运行实例", systemImage: "bolt.fill", tint: .green)
            }
            if !status.detachedInstances.isEmpty {
                Chip(text: "已脱离 launchd 看护", systemImage: "exclamationmark.triangle.fill", tint: .orange)
            }
        }
    }
}

private struct PendingCard: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    let items: [PendingItem]

    var body: some View {
        if !items.isEmpty {
            let ordinary = items.filter { !$0.sensitive }
            Card(title: "待定项", systemImage: "tray.full.fill",
                 subtitle: "受管程序尝试过、但当前未允许的访问。这里只列出已观测到的行为，不代表全部。") {
                if ordinary.count > 1 {
                    Button("允许全部非敏感项（\(ordinary.count)）") { model.acceptAll(ordinary, for: profileID) }
                        .controlSize(.small)
                }
            } content: {
                VStack(spacing: 2) {
                    ForEach(items, id: \.self) { item in
                        HStack(spacing: 10) {
                            IconTile(systemImage: item.suggestion.symbol, tint: item.sensitive ? .red : .accentColor)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.suggestion.title).lineLimit(2).truncationMode(.middle)
                                HStack(spacing: 6) {
                                    Text("\(item.evidence) 次").font(.caption).foregroundStyle(.secondary)
                                    if item.sensitive { Chip(text: "敏感位置", systemImage: "exclamationmark.triangle.fill", tint: .red) }
                                }
                            }
                            Spacer(minLength: 8)
                            Button("允许") { model.acceptAll([item], for: profileID) }
                                .controlSize(.small)
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 8)
                        .help(item.samples.joined(separator: "\n"))
                    }
                }
            }
        }
    }
}

private struct FilesCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile

    var body: some View {
        Card(title: "文件访问", systemImage: "folder.fill",
             subtitle: "沙箱只放行这里列出的目录和文件；系统库由“系统基础”模板提供。") {
            Menu {
                Button("只读…") { model.addFolder(to: profile.id, access: .readOnly) }
                Button("读写…") { model.addFolder(to: profile.id, access: .readWrite) }
            } label: {
                Label("添加", systemImage: "plus")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        } content: {
            if profile.files.isEmpty {
                Text("还没有手动添加的目录").font(.callout).foregroundStyle(.secondary).padding(.vertical, 4)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(profile.files.enumerated()), id: \.offset) { index, grant in
                        if index > 0 { Divider().padding(.leading, 46) }
                        FileRow(grant: grant) { model.removeFile(grant, from: profile.id) }
                    }
                }
            }
        }
    }
}

/// Path on the left, labels and the hover-revealed remove button on the right, laid out side by side
/// so a long path is truncated instead of being covered.
private struct FileRow: View {
    let grant: FileGrant
    let remove: () -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: grant.kind == .directory ? "folder.fill" : "doc.fill",
                     tint: grant.access == .readWrite ? .orange : .blue)
            PathLabel(path: grant.path)
                .frame(maxWidth: .infinity, alignment: .leading)
                .layoutPriority(1)
            HStack(spacing: 6) {
                if grant.readsSecrets { Chip(text: "可读取凭证", systemImage: "key.fill", tint: .red) }
                Chip(text: grant.access == .readWrite ? "读写" : "只读", tint: grant.access == .readWrite ? .orange : .blue)
            }
            .fixedSize()
            Button(role: .destructive, action: remove) { Image(systemName: "trash") }
                .buttonStyle(.borderless)
                .help("移除")
                .opacity(hovering ? 1 : 0)
                .allowsHitTesting(hovering)
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(hovering ? Color.primary.opacity(0.05) : .clear))
        .onHover { hovering = $0 }
    }
}

private struct TemplatesCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile

    var body: some View {
        Card(title: "运行时模板", systemImage: "square.stack.3d.up.fill",
             subtitle: "常见工具运行所需的一组权限，可整体开关。") {
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                ForEach(model.templates, id: \.id) { template in
                    TemplateTile(template: template, enabled: profile.templates.contains { $0.id == template.id }) { enabled in
                        model.setTemplate(template, enabled: enabled, in: profile.id)
                    }
                }
            }
        }
    }
}

private struct TemplateTile: View {
    let template: Template
    let enabled: Bool
    let toggle: (Bool) -> Void

    var body: some View {
        let info = TemplateInfo.of(template.id)
        Button { toggle(!enabled) } label: {
            HStack(alignment: .top, spacing: 10) {
                IconTile(systemImage: info.symbol, tint: enabled ? .accentColor : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(info.title).font(.body.weight(.medium)).foregroundStyle(.primary)
                    Text(info.detail).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
                Image(systemName: enabled ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(enabled ? Color.accentColor : Color.secondary)
                    .font(.title3)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(enabled ? Color.accentColor.opacity(0.08) : Color.primary.opacity(0.03)))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(enabled ? Color.accentColor.opacity(0.5) : Color.primary.opacity(0.08)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct ProgramsAndNetworkCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var newPort = ""

    var body: some View {
        Card(title: "程序与网络", systemImage: "network",
             subtitle: "允许执行的程序和可连接的本机端口。允许某个端口不代表授权该服务替它做的事。") {
            VStack(alignment: .leading, spacing: 14) {
                if profile.unrestrictedExec {
                    Notice(kind: .warning, text: "允许执行任意程序（从现有安装迁移时保留）。")
                }
                if !profile.exec.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("可执行程序").font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
                        ForEach(profile.exec, id: \.path) { grant in
                            HStack(spacing: 8) {
                                Image(systemName: "play.square").foregroundStyle(.secondary)
                                Text(PathLabel.abbreviate(grant.path)).font(.system(.callout, design: .monospaced))
                                    .lineLimit(2).truncationMode(.middle).textSelection(.enabled).help(grant.path)
                                if grant.sha256 != nil { Chip(text: "限定哈希", systemImage: "number") }
                            }
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("本机 TCP 端口").font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 84), alignment: .leading)], alignment: .leading, spacing: 8) {
                        ForEach(profile.network.loopbackTCPConnect, id: \.self) { port in
                            HStack(spacing: 4) {
                                Text(verbatim: String(port)).font(.system(.callout, design: .monospaced)).lineLimit(1)
                                Button {
                                    model.edit(profile.id) { $0.network.loopbackTCPConnect.removeAll { $0 == port } }
                                } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.borderless)
                                .foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Capsule().fill(Color.primary.opacity(0.06)))
                            .fixedSize()
                        }
                    }
                    HStack(spacing: 8) {
                        TextField("端口", text: $newPort)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 80)
                            .onSubmit(addPort)
                        Button("添加", action: addPort).disabled(Int(newPort).map { !(1...65535).contains($0) } ?? true)
                    }
                }

                Divider()

                Toggle(isOn: Binding(
                    get: { profile.network.outboundTCP == .allowed },
                    set: { allowed in model.edit(profile.id) { $0.network.outboundTCP = allowed ? .allowed : .denied } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("允许对外 TCP 连接")
                        Text("Agent 连接模型服务通常需要打开").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.switch)
            }
        }
    }

    private func addPort() {
        guard let port = Int(newPort), (1...65535).contains(port) else { return }
        model.edit(profile.id) { $0.network.loopbackTCPConnect.append(port) }
        newPort = ""
    }
}

private struct LaunchCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile

    var body: some View {
        if let launch = profile.launch {
            Card(title: "启动项", systemImage: "power",
                 subtitle: "接管后由 AgentGuard 启动器在沙箱内启动，登录自启和异常重启都经过同一入口。") {
                VStack(alignment: .leading, spacing: 12) {
                    Text(([PathLabel.abbreviate(launch.executable)] + launch.arguments).joined(separator: " "))
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.05)))
                    if !(model.status(for: profile.id)?.detachedInstances.isEmpty ?? true) {
                        Notice(kind: .warning,
                               text: "启动入口已经退出，但它启动的进程还在运行。launchd 只看护入口进程，这些进程崩溃后不会被自动拉起。请让入口脚本用 exec 在前台运行目标程序，不要用 & 或 nohup 把它放到后台。")
                    }
                    if let original = launch.originalLabel {
                        Label("原启动项：\(original)", systemImage: "arrow.uturn.backward").font(.callout).foregroundStyle(.secondary)
                    }
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 12) { actions }
                        VStack(alignment: .leading, spacing: 10) { actions }
                    }
                }
            }
        }
    }

    private var isRestarting: Bool { model.restartingProfiles.contains(profile.id) }

    @ViewBuilder private var actions: some View {
        if isRestarting {
            // 重启是“杀进程 → 重新 bootstrap → 等实例注册”的一整段，中间界面必须说话。
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("正在重启：结束旧实例，等待新实例注册…").foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
        } else {
            Button("接管启动项") { model.installLaunchAgent(profile.id) }
            Button("重启受管实例") { model.restartManaged(profile.id) }
                .buttonStyle(.borderedProminent)
            Button("停止并移除管控") { model.removeManagement(profile.id, restoreOriginal: false) }
            Button("恢复原启动项…", role: .destructive) { model.removeManagement(profile.id, restoreOriginal: true) }
        }
    }
}
#endif
