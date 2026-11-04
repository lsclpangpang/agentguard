#if os(macOS)
import GuardCore
import SwiftUI

struct ProfileDetailView: View {
    @EnvironmentObject var model: AppModel
    let profileID: String

    var body: some View {
        if let profile = model.profile(profileID) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
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
                    .padding(.bottom, 4)

                    PendingCard(profileID: profileID, items: model.pending[profileID] ?? [])
                    ManagedProgramsCard(profile: profile, unmanaged: model.status(for: profileID)?.unmanagedProcesses ?? [])
                    FilesCard(profile: profile)
                    TemplatesCard(profile: profile)
                    ProgramsAndNetworkCard(profile: profile)
                    LaunchCard(profile: profile)
                    DeleteCard(profile: profile, running: !(model.status(for: profileID)?.runningInstances.isEmpty ?? true))
                }
                .padding(20)
                .frame(maxWidth: 900, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            .overlay(alignment: .top) { ScrollTopFade() }
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
            if !status.unmanagedProcesses.isEmpty {
                Chip(text: "\(status.unmanagedProcesses.count) 个未受管进程", systemImage: "exclamationmark.octagon.fill", tint: .red)
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
                    // 用条目本身做标识：按下标的话，插到中间会让它后面的每一行都被当成新行重建。
                    ForEach(Array(profile.files.enumerated()), id: \.element) { index, grant in
                        if index > 0 { Divider().padding(.leading, 46) }
                        FileRow(grant: grant,
                                remove: { model.removeFile(grant, from: profile.id) },
                                setAccess: { model.setFileAccess(grant, to: $0, in: profile.id) })
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
    let setAccess: (Access) -> Void
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
                // 直接在这里切换读写级别：授权项常常先按只读加进来，用起来才发现要写。
                AccessControl(access: grant.access, change: setAccess)
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

/// The executables this profile manages, and copies of them found running outside AgentGuard.
private struct ManagedProgramsCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let unmanaged: [Int32]
    @State private var adding = false

    var body: some View {
        Card(title: "受管程序", systemImage: "app.badge.checkmark",
             subtitle: "这个配置档管控的可执行文件，会自动获得读取和执行权限。不经过 AgentGuard 直接运行的副本不受沙箱限制，会在这里报告。") {
            Button { adding = true } label: { Label("添加", systemImage: "plus") }
                .buttonStyle(.borderless)
        } content: {
            VStack(alignment: .leading, spacing: 10) {
                if !unmanaged.isEmpty {
                    Notice(kind: .error,
                           text: "发现 \(unmanaged.count) 个没有经过 AgentGuard 启动的进程（PID \(unmanaged.map(String.init).joined(separator: "、"))），它们不受沙箱限制。请结束这些进程，改用 guard run \(profile.id) -- <命令> 或接管启动项来启动。")
                }
                Text("如果程序是脚本（例如 npm 安装的 claude），实际运行的是解释器，直接运行它不会被检测到。")
                    .font(.caption).foregroundStyle(.secondary)
                if profile.programs.isEmpty {
                    Text(profile.launch == nil
                         ? "还没有指定程序。指定后，直接运行它（没有经过 guard run）会被报告。"
                         : "启动项的入口程序会被检测；如果入口是脚本，请把它实际启动的程序也加进来。")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(profile.programs.enumerated()), id: \.offset) { index, path in
                            if index > 0 { Divider().padding(.leading, 46) }
                            ProgramRow(path: path) { model.removeProgram(path, from: profile.id) }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $adding) {
            // 输入框不能放在 ScrollView 里：一提交，AppKit 把焦点落在它身上，SwiftUI 就为
            // 了让输入框可见而滚动，详情页看起来“飘”一下。放进 sheet 就没有这个副作用。
            AddProgramSheet(profileID: profile.id) { adding = false }
                .environmentObject(model)
        }
    }
}

private struct AddProgramSheet: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    let dismiss: () -> Void
    @State private var path = ""
    @State private var error: String?

    private var trimmed: String { path.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func submit() {
        guard !trimmed.isEmpty else { return }
        error = model.addProgram(path: trimmed, to: profileID)
        if error == nil { dismiss() }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("添加受管程序").font(.headline)
            Text("填真正在跑的可执行文件，不是启动它的脚本。例如 /opt/homebrew/bin/claude、/Library/KnodoRestricted/release/knodo-agentd。")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("/path/to/executable", text: $path)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
                .onChange(of: path) { error = nil }
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("选择文件…") {
                    Task { if let picked = await model.pickFile() { path = picked } }
                }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("添加", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

private struct ProgramRow: View {
    let path: String
    let remove: () -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: "terminal.fill", tint: .indigo)
            PathLabel(path: path)
                .frame(maxWidth: .infinity, alignment: .leading)
                .layoutPriority(1)
            Button(role: .destructive, action: remove) { Image(systemName: "trash") }
                .buttonStyle(.borderless)
                .help("不再管控这个程序")
                .opacity(hovering ? 1 : 0)
                .allowsHitTesting(hovering)
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(hovering ? Color.primary.opacity(0.05) : .clear))
        .onHover { hovering = $0 }
    }
}

private struct DeleteCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let running: Bool

    var body: some View {
        Card(title: "删除配置档", systemImage: "trash",
             subtitle: "删除全部权限设置和 AgentGuard 安装的启动项，名称可以重新使用。已批准的历史修订和它的状态目录会归档到只有 root 能访问的位置。") {
            HStack(spacing: 12) {
                if profile.launch?.originalLabel != nil {
                    Button("删除并恢复原启动项…", role: .destructive) { model.deleteProfile(profile.id, restoreOriginal: true) }
                        .disabled(running)
                    Button("删除，不恢复…", role: .destructive) { model.deleteProfile(profile.id) }
                        .disabled(running)
                } else {
                    Button("删除配置档…", role: .destructive) { model.deleteProfile(profile.id) }
                        .disabled(running)
                }
                if running {
                    Text("还有运行中的实例，先停止它再删除").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct ProgramsAndNetworkCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var addingPort = false

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
                    Button("添加端口…") { addingPort = true }
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
        // Keep text fields out of the scrolling detail: AppKit restores focus after a file panel
        // or confirmation sheet closes and scrolls the detail to reveal the field.
        .sheet(isPresented: $addingPort) {
            AddPortSheet { port in
                addingPort = false
                model.edit(profile.id) { $0.network.loopbackTCPConnect.append(port) }
            }
        }
    }
}

private struct AddPortSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    let add: (Int) -> Void

    private var port: Int? {
        guard let value = Int(input.trimmingCharacters(in: .whitespacesAndNewlines)),
              (1...65535).contains(value) else { return nil }
        return value
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("添加本机 TCP 端口").font(.headline)
            Text("允许连接这个端口上的本机服务。端口范围为 1–65535。")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("端口，例如 8080", text: $input)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("添加", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(port == nil)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private func submit() {
        guard let port else { return }
        add(port)
    }
}

/// 滚动内容在视口上沿会被硬切一半，正对工具栏下沿时尤其明显。macOS 只在内容滚到工具栏下面时
/// 才画那层模糊，而这里的滚动视图被安全区挡住了，于是补一条同样的边缘淡化：顶部材质、向下渐隐，
/// 滚动到顶时它压在页面上方的留白里，看不出来。
private struct ScrollTopFade: View {
    var body: some View {
        Rectangle()
            .fill(.regularMaterial)
            .frame(height: 24)
            .mask(
                LinearGradient(
                    stops: [
                        .init(color: .black, location: 0),
                        .init(color: .black.opacity(0.55), location: 0.55),
                        .init(color: .clear, location: 1),
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
            .allowsHitTesting(false)
    }
}
#endif
