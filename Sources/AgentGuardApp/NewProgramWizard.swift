#if os(macOS)
import AppKit
import GuardCore
import GuardPlatform
import SwiftUI

/// A program the app knows how to set up, with the permission group it needs.
struct KnownProgram: Identifiable, Equatable {
    let id: String
    let title: String
    let detail: String
    let candidates: [String]
    let templates: [String]
    let needsNetwork: Bool

    static let all = [
        KnownProgram(id: "claude", title: "Claude Code", detail: "命令行，连接 Anthropic 的模型服务",
                     candidates: ["/opt/homebrew/bin/claude", "/usr/local/bin/claude"], templates: ["system-base", "claude-code"], needsNetwork: true),
        KnownProgram(id: "codex", title: "Codex", detail: "命令行，连接 OpenAI 的模型服务",
                     candidates: ["/opt/homebrew/bin/codex", "/usr/local/bin/codex"], templates: ["system-base", "codex"], needsNetwork: true),
    ]

    var installedPath: String? { candidates.first { FileManager.default.isExecutableFile(atPath: $0) } }
}

/// First-time setup in four steps: the program, where it works, a summary of what it may do, then
/// starting it and confirming the result. Nothing is saved before the last step, and a failure
/// keeps everything entered so the user can fix it and retry.
struct NewProgramWizard: View {
    @EnvironmentObject var model: AppModel
    @Binding var isPresented: Bool
    var onCreated: (String) -> Void = { _ in }

    enum Step: Int, CaseIterable { case program, workplace, summary, start }

    @State private var step: Step = .program
    @State private var known: KnownProgram?
    @State private var programPath = ""
    @State private var plan: ProgramSetupPlan?
    @State private var planError: String?
    @State private var name = ""
    @State private var runsInBackground = false
    @State private var runAtLogin = false
    @State private var arguments = ""
    @State private var folder: String?
    @State private var folderAccess: Access = .readWrite
    @State private var allowNetwork = false
    @State private var recordMore = false
    @State private var templateIDs: Set<String> = ["system-base"]
    @State private var saving = false
    @State private var saveError: String?
    @State private var created = false

    private var knodoInstalled: Bool { FileManager.default.fileExists(atPath: "/Library/KnodoRestricted/allowlist.json") }
    private var nameTaken: Bool { model.report?.profiles.contains { $0.profileID == name } ?? false }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            Group {
                switch step {
                case .program: programStep
                case .workplace: workplaceStep
                case .summary: summaryStep
                case .start: startStep
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            footer
        }
        .padding(24)
        .frame(width: 600)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("添加程序").font(.title2.weight(.semibold))
            HStack(spacing: 6) {
                ForEach(Step.allCases, id: \.self) { item in
                    Text("\(item.rawValue + 1). \(title(item))")
                        .font(.caption.weight(item == step ? .semibold : .regular))
                        .foregroundStyle(item == step ? Color.primary : Color.secondary)
                    if item != .start { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary) }
                }
            }
        }
    }

    private func title(_ step: Step) -> String {
        switch step {
        case .program: return "选择程序"
        case .workplace: return "工作位置"
        case .summary: return "权限摘要"
        case .start: return "启动并确认"
        }
    }

    // MARK: Step 1

    private var programStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("要保护哪个程序？").font(.headline)
            ForEach(KnownProgram.all) { program in
                Button { choose(program) } label: {
                    HStack(spacing: 10) {
                        IconTile(systemImage: "terminal.fill", size: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(program.title).foregroundStyle(.primary)
                            Text(program.installedPath.map { "\(program.detail) · \($0)" } ?? "\(program.detail) · 本机没有找到")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if known == program { Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint) }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(program.installedPath == nil)
            }
            if knodoInstalled {
                Button {
                    isPresented = false
                    model.importKnodo()
                } label: {
                    Label("迁移现有的 Knodo 沙箱…", systemImage: "arrow.down.doc")
                }
                .buttonStyle(.borderless)
            }
            Divider()
            HStack {
                TextField("其他程序的完整路径，例如 /opt/homebrew/bin/aider", text: $programPath)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { analyze(programPath) }
                Button("选择…") { Task { if let picked = await model.pickFile() { programPath = picked; analyze(picked) } } }
            }
            if let planError {
                Label(planError, systemImage: "exclamationmark.circle.fill").font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let plan {
                VStack(alignment: .leading, spacing: 4) {
                    Text("将运行：\(LaunchArguments.format([plan.launchExecutable] + plan.launchArguments))").font(.callout).textSelection(.enabled)
                    if plan.program == nil {
                        Text("这是一个脚本，由解释器运行。直接在 AgentGuard 之外运行它的副本无法被检测。").font(.caption).foregroundStyle(.secondary)
                    }
                }
                TextField("名称", text: $name).textFieldStyle(.roundedBorder)
                if !ProfileID.isValid(name) { Text("名称只能使用小写字母、数字和 -").font(.caption).foregroundStyle(.red) }
                else if nameTaken { Text("已有同名程序，请换一个名称").font(.caption).foregroundStyle(.red) }
                Picker("怎样运行", selection: $runsInBackground) {
                    Text("在终端里使用（命令行工具）").tag(false)
                    Text("在后台运行（由 AgentGuard 启动）").tag(true)
                }
                .pickerStyle(.radioGroup)
                if runsInBackground {
                    TextField("启动参数（可选）", text: $arguments).textFieldStyle(.roundedBorder)
                    SwiftUI.Toggle("登录 Mac 时自动启动 \(name.isEmpty ? "这个程序" : name)", isOn: $runAtLogin)
                }
            }
            Text("暂不支持：需要 sudo 的程序、通过“打开”启动的图形界面 App、会再启动其他启动器的多层脚本。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func choose(_ program: KnownProgram) {
        known = program
        templateIDs = Set(program.templates)
        allowNetwork = program.needsNetwork
        if let path = program.installedPath { programPath = path; analyze(path, suggestedName: program.id) }
    }

    private func analyze(_ path: String, suggestedName: String? = nil) {
        guard !path.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        switch ProgramSetup.analyze(path, home: model.config.home, homebrewPrefix: model.config.homebrewPrefix, probe: LocalProgramFileProbe()) {
        case let .success(result):
            plan = result
            planError = nil
            if name.isEmpty || !ProfileID.isValid(name) { name = uniqueName(suggestedName ?? URL(fileURLWithPath: result.command).lastPathComponent) }
        case let .failure(error):
            plan = nil
            if case let .script(interpreter) = error {
                planError = "这是一个脚本，但找不到它的解释器\(interpreter.map { "（\($0)）" } ?? "")。请确认解释器已经安装在 /opt/homebrew/bin、/usr/local/bin 或 /usr/bin。"
            } else {
                planError = ProgramPath.message(for: error)
            }
        }
    }

    private func uniqueName(_ raw: String) -> String {
        var base = String(raw.lowercased().map { ("a"..."z").contains($0) || ("0"..."9").contains($0) ? $0 : "-" })
        while base.hasPrefix("-") { base.removeFirst() }
        if base.hasSuffix(".js") || base.hasSuffix("-js") { base = String(base.dropLast(3)) }
        if base.isEmpty { base = "program" }
        base = String(base.prefix(56))
        let taken = Set(model.report?.profiles.map(\.profileID) ?? [])
        var candidate = base, counter = 2
        while taken.contains(candidate) { candidate = "\(base)-\(counter)"; counter += 1 }
        return candidate
    }

    // MARK: Step 2

    private var workplaceStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(name) 在哪里工作？").font(.headline)
            Text("选择项目文件夹。程序只能访问这里，以及运行本身需要的位置（下一步会全部列出）。").font(.callout).foregroundStyle(.secondary)
            HStack {
                if let folder {
                    PathLabel(path: folder).frame(maxWidth: .infinity, alignment: .leading)
                    Button("更换…") { pickFolder() }
                    Button { self.folder = nil } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.borderless).foregroundStyle(.secondary)
                } else {
                    Text("还没有选择").foregroundStyle(.secondary)
                    Spacer()
                    Button("选择文件夹…") { pickFolder() }
                }
            }
            if folder != nil {
                Picker("访问", selection: $folderAccess) {
                    Text("仅查看").tag(Access.readOnly)
                    Text("允许修改").tag(Access.readWrite)
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 260)
                if let folder, SensitivePaths(home: model.config.home).overlapsSensitive(folder) {
                    Notice(kind: .warning, text: "这个位置包含敏感内容（例如文稿、桌面、下载或凭证目录）。建议只选具体的项目文件夹。")
                }
            } else {
                Text("也可以暂时不选，之后在“权限”中添加。").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func pickFolder() {
        Task {
            let panel = NSOpenPanel()
            panel.canChooseDirectories = true
            panel.canChooseFiles = false
            panel.allowsMultipleSelection = false
            panel.message = "选择项目文件夹"
            if let url = await AppModel.run(panel) { folder = url.path }
        }
    }

    // MARK: Step 3

    private var draft: Profile? {
        guard let plan, ProfileID.isValid(name) else { return nil }
        var files = plan.files
        if let folder {
            files.append(FileGrant(path: folder, kind: .directory, access: folderAccess,
                                   readsSecrets: SensitivePaths(home: model.config.home).overlapsSensitive(folder)))
        }
        let refs = model.templates.filter { templateIDs.contains($0.id) }.map { TemplateRef(id: $0.id, version: $0.version) }
        let launch = runsInBackground
            ? plan.launch(arguments: (try? LaunchArguments.parse(arguments)) ?? [], workingDirectory: folder, runAtLogin: runAtLogin)
            : nil
        return Profile(id: name, revision: 1, mode: recordMore ? .restrictedLearning : .enforce, templates: refs, files: files,
                       exec: plan.exec.filter { $0 != plan.program }.map { ExecGrant(path: $0) },
                       network: NetworkPolicy(outboundTCP: allowNetwork ? .allowed : .denied), launch: launch,
                       programs: plan.program.map { [$0] } ?? [])
    }

    private var summaryStep: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("\(name) 将可以：").font(.headline)
            if let draft {
                let overview = model.overview(draft)
                let sensitive = overview.files.filter(\.readsSecrets)
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("访问这些位置").font(.subheadline.weight(.medium))
                        ForEach(overview.files.filter { !$0.redundant && !$0.readsSecrets }, id: \.self) { entry in
                            Text("\(entry.access == .readWrite ? "修改" : "查看")  \(PathLabel.abbreviate(entry.path))  · \(entry.sources.map(\.source.displayName).joined(separator: "、"))")
                                .font(.system(.caption, design: .monospaced))
                        }
                        if !sensitive.isEmpty {
                            Text("敏感位置").font(.subheadline.weight(.medium)).foregroundStyle(.red).padding(.top, 4)
                            ForEach(sensitive, id: \.self) { entry in
                                Text("\(entry.access == .readWrite ? "修改" : "查看")  \(PathLabel.abbreviate(entry.path))  · \(entry.sources.map(\.source.displayName).joined(separator: "、"))，其中可能有凭证或个人资料")
                                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.red)
                            }
                        }
                        Text("运行其他程序").font(.subheadline.weight(.medium)).padding(.top, 4)
                        Text(overview.exec.isEmpty ? "不允许" : overview.exec.map { PathLabel.abbreviate($0.path) }.joined(separator: "、"))
                            .font(.system(.caption, design: .monospaced))
                        ForEach(plan?.reasons ?? [], id: \.self) { Text("· " + $0).font(.caption).foregroundStyle(.secondary) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 220)
                SwiftUI.Toggle(isOn: $allowNetwork) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("允许联网（对外 TCP 连接）")
                        Text(known?.needsNetwork == true ? "\(known?.title ?? "") 需要连接模型服务" : "不需要联网的工具请保持关闭").font(.caption).foregroundStyle(.secondary)
                    }
                }
                SwiftUI.Toggle(isOn: $recordMore) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("记录更多活动")
                        Text("未允许的访问仍会被阻止。开启后额外记录成功的文件访问，帮助完善权限；随时可以关闭。").font(.caption).foregroundStyle(.secondary)
                    }
                }
                DisclosureGroup("推荐权限组") {
                    ForEach(model.templates, id: \.id) { template in
                        SwiftUI.Toggle(isOn: Binding(get: { templateIDs.contains(template.id) },
                                                     set: { if $0 { templateIDs.insert(template.id) } else { templateIDs.remove(template.id) } })) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(TemplateInfo.of(template.id).title)
                                Text(TemplateInfo.of(template.id).detail).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                }
                .font(.callout)
            }
        }
    }

    // MARK: Step 4

    private var startStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !created {
                Text(saving ? "正在保存权限…" : "保存后，\(name) 才会按上一步的权限运行。").font(.callout)
                if saving { ProgressView().controlSize(.small) }
            } else if let profile = model.profile(name) {
                let status = model.status(for: name)
                let summary = ProgramStatusSummary.evaluate(status, freshness: model.freshness, programName: name, hasLaunch: profile.launch != nil)
                Label("权限已保存", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                if profile.launch != nil {
                    if model.restartingProfiles.contains(name) {
                        HStack { ProgressView().controlSize(.small); Text("正在启动，等待确认保护…") }
                    } else {
                        Label(summary.headline, systemImage: Theme.symbol(summary.level)).foregroundStyle(Theme.color(summary.level))
                        Text(summary.impact).font(.callout).foregroundStyle(.secondary)
                        if status?.runningInstances.isEmpty ?? true { Button("启动 \(name)") { model.installLaunchAgent(name) }.buttonStyle(.borderedProminent) }
                    }
                } else if let command = model.command(for: profile) {
                    Text("在终端中运行下面的命令。运行后这里会显示确认结果。").font(.callout)
                    HStack {
                        Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(3)
                        Button { Pasteboard.copy(command) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).help("复制命令")
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.05)))
                    if !(status?.runningInstances.isEmpty ?? true) {
                        Label(summary.headline, systemImage: Theme.symbol(summary.level)).foregroundStyle(Theme.color(summary.level))
                    } else {
                        Text("等待在终端中运行…").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if let saveError {
                Notice(kind: .error, text: "没有保存：\(saveError)。已填写的内容都保留着，可以返回修改后重试。")
            }
        }
    }

    // MARK: Navigation

    private var canContinue: Bool {
        switch step {
        case .program: return plan != nil && ProfileID.isValid(name) && !nameTaken && (!runsInBackground || (try? LaunchArguments.parse(arguments)) != nil)
        case .workplace, .summary: return draft != nil
        case .start: return true
        }
    }

    private var footer: some View {
        HStack {
            if step != .program && !created {
                Button("上一步") { step = Step(rawValue: step.rawValue - 1) ?? .program; saveError = nil }.disabled(saving)
            }
            Spacer()
            Button(created ? "完成" : "取消") {
                isPresented = false
                if created { onCreated(name) }
            }
            .keyboardShortcut(.cancelAction)
            switch step {
            case .summary:
                Button("保存") { save() }.keyboardShortcut(.defaultAction).disabled(!canContinue || saving)
            case .start:
                if !created { Button("重试") { save() }.keyboardShortcut(.defaultAction).disabled(saving) }
            default:
                Button("下一步") { step = Step(rawValue: step.rawValue + 1) ?? .summary }.keyboardShortcut(.defaultAction).disabled(!canContinue)
            }
        }
    }

    private func save() {
        guard let draft else { return }
        step = .start
        saving = true
        saveError = nil
        Task {
            let outcome = await model.createProfile(draft)
            saving = false
            switch outcome {
            case .applied:
                created = true
                model.lastError = nil
                if draft.launch != nil { model.installLaunchAgent(draft.id) }
            case .cancelled:
                saveError = "已取消确认"
            case .unchanged:
                saveError = "没有需要保存的变化"
            case let .failed(message):
                saveError = message
                model.lastError = nil
            }
        }
    }
}
#endif
