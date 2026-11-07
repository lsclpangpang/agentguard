#if os(macOS)
import GuardCore
import SwiftUI

enum DetailTab: String, CaseIterable, Identifiable {
    case overview = "概况"
    case permissions = "权限"
    case activity = "最近活动"
    case advanced = "高级"

    var id: String { rawValue }
}

struct ProfileDetailView: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    @State private var tab: DetailTab = .overview

    var body: some View {
        if let profile = model.profile(profileID) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ProfileHeader(profile: profile, status: model.status(for: profileID))
                    Picker("", selection: $tab) {
                        ForEach(DetailTab.allCases) { tab in
                            if tab == .activity, let count = model.status(for: profileID)?.pendingCount, count > 0 {
                                Text("\(tab.rawValue)（\(count)）").tag(tab)
                            } else {
                                Text(tab.rawValue).tag(tab)
                            }
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(maxWidth: 420)
                    switch tab {
                    case .overview:
                        StatusCard(profile: profile, status: model.status(for: profileID)) { tab = $0 }
                        TrustNotices(profile: profile, status: model.status(for: profileID))
                        LaunchCard(profile: profile)
                        ManagedProgramsCard(profile: profile, unmanaged: model.status(for: profileID)?.unmanagedProcesses ?? [])
                    case .permissions:
                        EffectivePermissionsCard(profile: profile)
                        FilesCard(profile: profile)
                        TemplatesCard(profile: profile)
                        ProgramsAndNetworkCard(profile: profile)
                        RecordMoreCard(profile: profile)
                    case .activity:
                        ActivityTab(profileID: profileID)
                    case .advanced:
                        AdvancedCard(profile: profile, status: model.status(for: profileID))
                        DeleteCard(profile: profile, running: !(model.status(for: profileID)?.runningInstances.isEmpty ?? true))
                    }
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

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            IconTile(systemImage: "app.badge.checkmark", tint: tint, size: 40)
            VStack(alignment: .leading, spacing: 8) {
                Text(profile.id).font(.title2.weight(.semibold)).lineLimit(2)
                HStack(spacing: 6) {
                    if model.restartingProfiles.contains(profile.id) {
                        ProgressView().controlSize(.small)
                        Text("正在启动…").font(.callout).foregroundStyle(.secondary)
                    } else {
                        Chip(text: summary.headline, tint: tint)
                    }
                }
                if let command = model.command(for: profile) {
                    HStack(spacing: 8) {
                        Text(command).font(.system(.callout, design: .monospaced))
                            .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                        Button {
                            Pasteboard.copy(command)
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                        } label: {
                            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("复制命令：在终端中粘贴即可在这份权限下运行")
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.05)))
                } else if profile.launch == nil {
                    Text("在“受管程序”中指定程序后，这里会给出可以直接复制运行的完整命令。")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    private var summary: ProgramStatusSummary {
        ProgramStatusSummary.evaluate(status, freshness: model.freshness, programName: profile.id, hasLaunch: profile.launch != nil)
    }

    private var tint: Color { Theme.color(summary.level) }
}

/// What is happening, what it means and what to do, with the one action that resolves it.
private struct StatusCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let status: ProfileStatusReport?
    let showTab: (DetailTab) -> Void

    var body: some View {
        let summary = ProgramStatusSummary.evaluate(status, freshness: model.freshness, programName: profile.id, hasLaunch: profile.launch != nil)
        Card(title: summary.headline, systemImage: Theme.symbol(summary.level)) {
            VStack(alignment: .leading, spacing: 10) {
                Text(summary.impact).font(.callout).fixedSize(horizontal: false, vertical: true)
                if let confirmed = model.statusConfirmedAt {
                    Text("最近确认：\(confirmed.formatted(date: .omitted, time: .standard))").font(.caption).foregroundStyle(.secondary)
                }
                HStack(spacing: 10) {
                    if let next = summary.next { action(next) }
                    if let pending = status?.pendingCount, pending > 0 {
                        Button("查看 \(pending) 项需要处理的活动") { showTab(.activity) }
                    }
                }
                .disabled(!model.helperReachable || model.restartingProfiles.contains(profile.id))
            }
        }
    }

    @ViewBuilder private func action(_ next: ProgramStatusSummary.Next) -> some View {
        switch next {
        case .start:
            Button(next.title) { model.installLaunchAgent(profile.id) }.buttonStyle(.borderedProminent)
        case .restartAndApply, .restart:
            if profile.launch != nil {
                Button(next.title) { model.restartManaged(profile.id) }.buttonStyle(.borderedProminent)
            } else {
                Text("在终端里结束正在运行的 \(profile.id)，再用上面的命令重新运行。").font(.callout).foregroundStyle(.secondary)
            }
        case .checkAndRecover:
            Button(next.title) { model.refresh() }
        case .stopUnmanaged:
            Text("在下方“受管程序”中查看这些副本。").font(.callout).foregroundStyle(.secondary)
        }
    }
}

/// Reasons the status above cannot be taken at face value: a failed sandbox check of the running
/// program, and legacy rules whose effect on the listed permissions nobody has verified.
private struct TrustNotices: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let status: ProfileStatusReport?

    var body: some View {
        let legacy = model.legacyAnalysis(profile)
        let issues = status?.verificationIssues ?? []
        if !issues.isEmpty || legacy.hasUnverifiedFileRules || !(status?.untrackedInstances.isEmpty ?? true) {
            VStack(alignment: .leading, spacing: 8) {
                if !issues.isEmpty {
                    Notice(kind: .error, text: "运行中的程序没有通过保护确认，权限页列出的不代表它实际受到的限制：\n" + issues.joined(separator: "\n"))
                }
                if let untracked = status?.untrackedInstances, !untracked.isEmpty {
                    Notice(kind: .warning, text: "暂时无法确认所有运行副本的保护状态：副本 #\(untracked.map(String.init).joined(separator: "、#")) 在 Helper 重启或活动记录中断前启动的子程序可能没有被跟踪。重启程序后恢复完整跟踪。")
                }
                if legacy.hasUnverifiedFileRules {
                    Notice(kind: .warning, text: "存在 \(legacy.unverified.count) 条尚未核对的旧规则，它们可能放开权限页没有列出的访问。详见“高级”。")
                }
            }
        }
    }
}

/// Everything the program can access, merged from all sources, with where each grant comes from.
private struct EffectivePermissionsCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var expanded = false

    var body: some View {
        let overview = model.overview(profile)
        Card(title: "实际权限", systemImage: "checklist",
             subtitle: overview.complete ? "下面合并了你添加的授权、推荐权限组、程序启动所需和已核对的迁移规则。"
                                         : "部分旧规则或系统基础规则尚未逐项核对，下面列出已知授权。") {
            Button(expanded ? "收起" : "展开全部（\(overview.files.count)）") { expanded.toggle() }.buttonStyle(.borderless)
        } content: {
            VStack(alignment: .leading, spacing: 6) {
                if !overview.unverifiedLegacy.isEmpty {
                    Notice(kind: .warning, text: "以下旧规则无法核对，它们可能放开没有列出的访问：\n" + overview.unverifiedLegacy.joined(separator: "\n"))
                }
                if !overview.unverifiedBaseRules.isEmpty {
                    Notice(kind: .warning, text: "系统基础规则还提供程序运行所需的访问，尚未逐项列入此表：\n" + overview.unverifiedBaseRules.joined(separator: "\n"))
                }
                let shown = expanded ? overview.files : Array(overview.files.filter { !$0.redundant }.prefix(8))
                ForEach(shown, id: \.self) { entry in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: entry.access == .readWrite ? "pencil.circle.fill" : "eye.circle.fill")
                            .foregroundStyle(entry.access == .readWrite ? Color.orange : Color.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(PathLabel.abbreviate(entry.path)).font(.system(.callout, design: .monospaced)).lineLimit(2).truncationMode(.middle)
                                .textSelection(.enabled)
                            Text(describe(entry)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 4)
                        if entry.readsSecrets { Chip(text: "可读取凭证", systemImage: "key.fill", tint: .red) }
                        Text(entry.access == .readWrite
                             ? (entry.ownAccess == .readOnly && !entry.overlapping.isEmpty ? "部分可修改" : "可修改")
                             : "仅查看").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if !expanded && overview.files.count > shown.count {
                    Text("还有 \(overview.files.count - shown.count) 项（包括已被上层目录覆盖的）").font(.caption).foregroundStyle(.secondary)
                }
                Divider().padding(.vertical, 4)
                Text(networkLine(overview)).font(.callout)
                Text(execLine(overview)).font(.callout).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func describe(_ entry: PermissionEntry) -> String {
        var parts = entry.sources.map { source -> String in
            "\(source.source.displayName)\(entry.sources.count > 1 ? (source.access == .readWrite ? "（读写）" : "（只读）") : "")"
        }
        if let wider = entry.inherited.first(where: { $0.access > entry.ownAccess }) {
            parts.append("但上层的 \(PathLabel.abbreviate(wider.path))（\(wider.source.displayName)）允许修改")
        } else if entry.redundant, let parent = entry.inherited.first {
            parts.append("已被 \(PathLabel.abbreviate(parent.path)) 覆盖")
        }
        if !entry.overlapping.isEmpty {
            parts.append("部分匹配位置也受这些授权影响：" + entry.overlapping.map { PathLabel.abbreviate($0.path) }.joined(separator: "、"))
        }
        return "来源：" + parts.joined(separator: "、")
    }

    private func networkLine(_ overview: PermissionOverview) -> String {
        if !overview.unverifiedNetwork.isEmpty { return "网络：旧规则或系统基础规则仍有未核对的网络授权，最终范围待确认；下方开关只表示显式设置。" }
        var parts: [String] = [overview.network.outboundTCP == .allowed ? "可以联网（对外 TCP）" : "对外 TCP 未授权"]
        if !overview.ports.isEmpty { parts.append("可连接本机端口 " + overview.ports.map { String($0.port) }.joined(separator: "、")) }
        if overview.network.listen == .allowed { parts.append("可以接收连接") }
        if overview.network.udp == .allowed { parts.append("可以使用 UDP") }
        return "网络：" + parts.joined(separator: "；")
    }

    private func execLine(_ overview: PermissionOverview) -> String {
        if !overview.unverifiedExec.isEmpty { return "运行其他程序：旧规则或系统基础规则的授权范围待确认，程序列表可能不完整。" }
        if overview.unrestrictedExec { return "运行其他程序：任意程序（从旧安装迁移时保留）" }
        guard !overview.exec.isEmpty else { return "运行其他程序：不允许" }
        return "运行其他程序：" + overview.exec.map { PathLabel.abbreviate($0.path) }.joined(separator: "、")
    }
}

/// Optional extra activity collection; it never loosens what is blocked.
private struct RecordMoreCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile

    var body: some View {
        Card(title: "记录更多活动", systemImage: "waveform.path.ecg") {
            SwiftUI.Toggle(isOn: Binding(get: { profile.mode == .restrictedLearning }, set: { model.setRecordsMoreActivity($0, in: profile.id) })) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("记录程序成功完成的文件访问，帮助完善权限")
                    Text("未允许的访问仍会被阻止。开启后会记录这个程序的文件打开、创建和删除，只用于本机的权限建议；关闭后停止记录。根据这些记录给出的建议不代表程序的全部需求。")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(.switch)
            .disabled(profile.mode == .unprotectedObserve || !model.helperReachable)
        }
    }
}

/// Diagnostic details kept off the main screens: revision numbers, raw legacy rules, launch labels.
private struct AdvancedCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let status: ProfileStatusReport?

    var body: some View {
        let legacy = model.legacyAnalysis(profile)
        Card(title: "诊断信息", systemImage: "stethoscope") {
            VStack(alignment: .leading, spacing: 6) {
                row("已保存的修订", status.map { String($0.savedRevision) } ?? String(profile.revision))
                row("运行状态", status?.revisionState.displayText ?? "未知")
                row("运行副本", (status?.runningInstances ?? []).map { "#\($0)" }.joined(separator: "、").ifEmpty("无"))
                row("保护模式", profile.mode.displayName)
                if let launch = profile.launch {
                    row("启动入口", launch.executable)
                    row("原启动项", launch.originalLabel ?? "无")
                }
                if !profile.extraRules.isEmpty {
                    Divider()
                    Text("从旧安装迁移的规则（\(profile.extraRules.count) 条）").font(.subheadline.weight(.medium))
                    ForEach(legacy.fileRules, id: \.rule) { rule in
                        Text(rule.rule).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                    ForEach(legacy.unverified, id: \.self) { rule in
                        Label(rule, systemImage: "exclamationmark.triangle.fill").font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.orange).textSelection(.enabled)
                    }
                    ForEach(legacy.other, id: \.self) { rule in
                        Text(rule).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(value).textSelection(.enabled)
        }
        .font(.callout)
    }
}

extension String {
    func ifEmpty(_ replacement: String) -> String { isEmpty ? replacement : self }
}

private struct FilesCard: View {
    @State private var addingPattern = false

    /// Legacy rules that keep a read-only grant (or part of it) writable: they are rendered after it.
    private func legacyWriters(_ grant: FileGrant, _ legacy: LegacyRuleAnalysis) -> [String] {
        guard grant.access == .readOnly, !grant.pattern,
              let path = try? CanonicalPath(grant.path, resolver: model.config.environment.resolver) else { return [] }
        return legacy.rulesAbove(path, access: .readWrite) + legacy.rulesWithin(path, access: .readWrite)
    }

    @EnvironmentObject var model: AppModel
    let profile: Profile

    var body: some View {
        Card(title: "你添加的文件访问", systemImage: "folder.fill",
             subtitle: "程序只能访问这里和上方“实际权限”列出的位置。移除或改为仅查看时，会一并处理只在它之内的授权，并说明仍保留访问的其他来源。") {
            Menu {
                Button("只读…") { model.addFolder(to: profile.id, access: .readOnly) }
                Button("读写…") { model.addFolder(to: profile.id, access: .readWrite) }
                Divider()
                Button("通配路径…") { addingPattern = true }
            } label: {
                Label("添加", systemImage: "plus")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        } content: {
            if profile.files.isEmpty {
                Text("还没有手动添加的目录").font(.callout).foregroundStyle(.secondary).padding(.vertical, 4)
            } else {
                let legacy = model.legacyAnalysis(profile)
                VStack(spacing: 0) {
                    // 用条目本身做标识：按下标的话，插到中间会让它后面的每一行都被当成新行重建。
                    ForEach(Array(profile.files.enumerated()), id: \.element) { index, grant in
                        if index > 0 { Divider().padding(.leading, 46) }
                        FileRow(grant: grant, legacyWriters: legacyWriters(grant, legacy),
                                remove: { model.removeFile(grant, from: profile.id) },
                                setAccess: { model.setFileAccess(grant, to: $0, in: profile.id) })
                    }
                }
            }
        }
        .sheet(isPresented: $addingPattern) {
            AddPatternSheet(profileID: profile.id) { addingPattern = false }
                .environmentObject(model)
        }
    }
}

/// Path on the left, labels and the hover-revealed remove button on the right, laid out side by side
/// so a long path is truncated instead of being covered.
private struct FileRow: View {
    let grant: FileGrant
    let legacyWriters: [String]
    let remove: () -> Void
    let setAccess: (Access) -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: grant.pattern ? "asterisk" : grant.kind == .directory ? "folder.fill" : "doc.fill",
                     tint: grant.access == .readWrite ? .orange : .blue)
            PathLabel(path: grant.path)
                .frame(maxWidth: .infinity, alignment: .leading)
                .layoutPriority(1)
            HStack(spacing: 6) {
                if grant.pattern {
                    Chip(text: grant.kind == .directory ? "通配·含子内容" : "通配")
                        .help("* 匹配一级名称中的任意字符，? 匹配一个字符，** 匹配任意层目录")
                }
                if grant.readsSecrets { Chip(text: "可读取凭证", systemImage: "key.fill", tint: .red) }
                if !legacyWriters.isEmpty {
                    Chip(text: "旧规则仍可写入", systemImage: "exclamationmark.triangle.fill", tint: .orange)
                        .help("以下旧规则在仅查看之后生效，仍允许写入：\n" + legacyWriters.joined(separator: "\n"))
                }
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
        Card(title: "推荐权限组", systemImage: "square.stack.3d.up.fill",
             subtitle: "常见工具运行所需的一组权限，整体开关。每组实际放开的位置见上方“实际权限”。") {
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
             subtitle: "这些可执行文件会自动获得读取和运行权限。没有经过 AgentGuard 运行的副本不受限制，会在这里报告。") {
            Button { adding = true } label: { Label("添加", systemImage: "plus") }
                .buttonStyle(.borderless)
        } content: {
            VStack(alignment: .leading, spacing: 10) {
                if !unmanaged.isEmpty {
                    Notice(kind: .error,
                           text: "发现 \(unmanaged.count) 个没有经过 AgentGuard 运行的副本（PID \(unmanaged.map(String.init).joined(separator: "、"))），它们不受这份权限限制。请结束这些进程，改从 AgentGuard 启动；如果是其他启动项拉起的，可以在“整理现有安装”中停用它。")
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

private struct AddPatternSheet: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    let dismiss: () -> Void
    @State private var text = ""
    @State private var access: Access = .readOnly
    @State private var includesContents = false
    @State private var error: String?

    private var trimmed: String { text.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func submit() {
        guard !trimmed.isEmpty else { return }
        error = model.addPattern(trimmed, kind: includesContents ? .directory : .file, access: access, to: profileID)
        if error == nil { dismiss() }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("添加通配路径").font(.headline)
            Text("* 匹配一级名称里的任意字符，? 匹配一个字符，单独一级的 ** 匹配任意层目录。例如 ~/.claude*.jsonl、~/.claude/projects/**/*.jsonl。")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("~/.claude*.jsonl", text: $text)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
                .onChange(of: text) { error = nil }
            Picker("访问", selection: $access) {
                Text("仅查看").tag(Access.readOnly)
                Text("允许修改").tag(Access.readWrite)
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 240)
            Toggle("匹配到目录时，也放行其中的全部内容", isOn: $includesContents)
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
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
        Card(title: "移除这个程序的保护", systemImage: "trash",
             subtitle: "先停止受管副本，再删除全部权限设置和 AgentGuard 安装的启动项。是否恢复原启动方式由你选择；恢复后程序将不受限制地运行。历史修订和工作目录会归档保留。") {
            HStack(spacing: 12) {
                if profile.launch?.originalLabel != nil {
                    Button("移除并恢复原启动方式…", role: .destructive) { model.deleteProfile(profile.id, restoreOriginal: true) }
                    Button("移除，不恢复…", role: .destructive) { model.deleteProfile(profile.id) }
                } else {
                    Button("移除保护…", role: .destructive) { model.deleteProfile(profile.id) }
                }
                if running {
                    Text("会先停止正在运行的副本").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct ProgramsAndNetworkCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var addingPort = false

    private func networkToggle(_ title: String, detail: String, keyPath: WritableKeyPath<NetworkPolicy, GuardCore.Toggle>) -> some View {
        SwiftUI.Toggle(isOn: Binding(
            get: { profile.network[keyPath: keyPath] == .allowed },
            set: { allowed in model.edit(profile.id) { $0.network[keyPath: keyPath] = allowed ? .allowed : .denied } })) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.switch)
    }

    var body: some View {
        Card(title: "运行其他程序与网络", systemImage: "network",
             subtitle: "允许运行的其他程序、可连接的本机端口和网络范围。允许某个端口不代表授权该服务替它做的事。") {
            VStack(alignment: .leading, spacing: 14) {
                let overview = model.overview(profile)
                if !overview.unverifiedNetwork.isEmpty || !overview.unverifiedExec.isEmpty {
                    Notice(kind: .warning, text: "下方列表和开关是显式设置。旧规则或系统基础规则可能继续授权，关闭开关或移除列表项不能保证完全收回。")
                }
                if profile.unrestrictedExec {
                    Notice(kind: .warning, text: "允许运行任意程序（从现有安装迁移时保留）。")
                }
                let execs = model.overview(profile).exec
                if !execs.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("可以运行的程序").font(.subheadline.weight(.medium)).foregroundStyle(.secondary)
                        ForEach(execs, id: \.path) { exec in
                            HStack(spacing: 8) {
                                Image(systemName: "play.square").foregroundStyle(.secondary)
                                Text(PathLabel.abbreviate(exec.path)).font(.system(.callout, design: .monospaced))
                                    .lineLimit(2).truncationMode(.middle).textSelection(.enabled).help(exec.path)
                                Spacer(minLength: 4)
                                Text(exec.sources.map(\.displayName).joined(separator: "、")).font(.caption).foregroundStyle(.secondary)
                                if exec.sources.contains(.user) {
                                    Button { model.removeExec(exec.path, from: profile.id) } label: { Image(systemName: "xmark.circle.fill") }
                                        .buttonStyle(.borderless).foregroundStyle(.secondary).help("撤回运行这个程序的权限")
                                }
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

                networkToggle("允许对外 TCP 连接", detail: "Agent 连接模型服务通常需要打开", keyPath: \.outboundTCP)
                networkToggle("允许接收连接（监听端口）", detail: "只有提供本地服务的程序需要", keyPath: \.listen)
                networkToggle("允许 UDP", detail: "例如 DNS 以外的直接 UDP 通信，通常不需要", keyPath: \.udp)
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
