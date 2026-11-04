#if os(macOS)
import AppKit
import GuardCore
import GuardPlatform
import SwiftUI

struct LaunchCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var editing = false
    @State private var tips = false
    @State private var pendingSettings: LaunchSettings?

    private var status: ProfileStatusReport? { model.status(for: profile.id) }
    private var startup: LaunchAgentStatus? { status?.launchAgent }
    private var busy: Bool { model.restartingProfiles.contains(profile.id) }
    private var running: Bool { !(status?.runningInstances.isEmpty ?? true) }
    // Cached status may be pending or incomplete. Actions revalidate their exact targets, so a
    // failed background query must not remove the user's way to stop/repair a startup item.
    private var ready: Bool { model.helperReachable && !busy }
    private var needsApply: Bool {
        guard let launch = profile.launch, let startup, startup.problem == nil else { return false }
        return (startup.registered || startup.runAtLogin) && launch.runAtLogin != startup.runAtLogin
    }

    var body: some View {
        Card(title: "启动方式", systemImage: "power",
             subtitle: "由 AgentGuard 加载权限后启动程序，可选择登录时自动启动。") {
            HStack(spacing: 10) {
                Button { tips.toggle() } label: { Image(systemName: "info.circle") }
                    .buttonStyle(.borderless).help("启动方式说明")
                    .popover(isPresented: $tips) {
                        Text("设置启动方式后，点“启动程序”即可在已批准的权限下运行。登录自启开启后，每次登录 Mac 也会经过同样的启动过程。\n\n保存设置后，需要启动或重启程序才会应用。直接从其他入口打开的程序不受这份配置限制。")
                            .font(.callout).padding(16).frame(width: 300)
                    }
                Button(profile.launch == nil ? "设置启动方式…" : "编辑设置…") { editing = true }
                    .disabled(!model.helperReachable || busy)
            }
        } content: {
            VStack(alignment: .leading, spacing: 12) {
                if let startup, model.helperReachable {
                    HStack(spacing: 8) {
                        Chip(text: startup.displayText, systemImage: startup.running ? "checkmark.circle.fill" : "circle",
                             tint: startup.problem != nil ? .orange : startup.running ? .green : .secondary)
                        if startup.problem == nil { Chip(text: startup.runAtLogin ? "登录自启已开启" : "登录自启未开启") }
                    }
                    if let problem = startup.problem { Text(problem).foregroundStyle(.secondary).font(.callout) }
                } else {
                    Text("正在确认系统启动状态…").foregroundStyle(.secondary).font(.callout)
                }
                if let launch = profile.launch {
                    Text(LaunchArguments.format([PathLabel.abbreviate(launch.executable)] + launch.arguments))
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled).lineLimit(3).truncationMode(.middle)
                    if needsApply {
                        Text("登录自启设置尚未应用，启动或重启程序后生效。")
                            .font(.callout).foregroundStyle(.orange)
                    }
                    if !(status?.detachedInstances.isEmpty ?? true) {
                        Text("启动入口已退出，部分子程序仍在运行，异常后可能无法自动重启。请检查入口脚本的启动方式。")
                            .font(.callout).foregroundStyle(.orange)
                    }
                    if let original = launch.originalLabel {
                        Label("原启动方式已关联：\(original)", systemImage: "arrow.uturn.backward")
                            .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    if let problem = startup?.originalProblem {
                        Text("原启动方式暂不能恢复：" + problem).font(.caption).foregroundStyle(.orange)
                    }
                    if busy {
                        HStack { ProgressView().controlSize(.small); Text("正在启动，等待程序确认…").font(.callout) }
                    } else {
                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 12) { actions }
                            VStack(alignment: .leading, spacing: 10) { actions }
                        }
                        .disabled(!ready)
                    }
                } else {
                    Text("尚未设置。点“设置启动方式”，选择程序和参数；也可以继续使用页面上方的命令手动运行。")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
        }
        .sheet(isPresented: $editing, onDismiss: {
            if let settings = pendingSettings {
                pendingSettings = nil
                model.edit(profile.id) { $0.launch = settings }
            }
        }) {
            LaunchSettingsSheet(profile: profile, lockOriginal: startup?.canRestoreOriginal == true || startup?.registered == true || startup?.originalProblem != nil) { settings in
                pendingSettings = settings
                editing = false
            }
            .environmentObject(model)
        }
    }

    @ViewBuilder private var actions: some View {
        Button(running ? (needsApply ? "应用设置并重启" : "重启程序") : "启动程序") {
            if running { model.restartManaged(profile.id) } else { model.installLaunchAgent(profile.id) }
        }
        .buttonStyle(.borderedProminent)
        if startup?.registered == true || startup?.runAtLogin == true || startup?.problem != nil || running {
            Button("停止并取消自启…") { model.removeManagement(profile.id, restoreOriginal: false) }
        }
        if startup?.canRestoreOriginal == true {
            Button("恢复原启动方式…", role: .destructive) { model.removeManagement(profile.id, restoreOriginal: true) }
        }
    }
}

private struct LaunchSettingsSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let profile: Profile
    let lockOriginal: Bool
    let save: (LaunchSettings) -> Void
    @State private var executable: String
    @State private var arguments: String
    @State private var directory: String
    @State private var runAtLogin: Bool
    @State private var originalLabel: String?
    @State private var originalPath: String?
    @State private var items: [LaunchItem] = []
    @State private var scanError: String?

    init(profile: Profile, lockOriginal: Bool, save: @escaping (LaunchSettings) -> Void) {
        self.profile = profile; self.lockOriginal = lockOriginal; self.save = save
        _executable = State(initialValue: profile.launch?.executable ?? profile.programs.first ?? "")
        _arguments = State(initialValue: LaunchArguments.format(profile.launch?.arguments ?? []))
        _directory = State(initialValue: profile.launch?.workingDirectory ?? "")
        _runAtLogin = State(initialValue: profile.launch?.runAtLogin ?? false)
        _originalLabel = State(initialValue: profile.launch?.originalLabel)
        _originalPath = State(initialValue: profile.launch?.originalPath)
    }

    private func path(_ value: String) -> String {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.hasPrefix("~/") ? model.config.home + value.dropFirst() : value
    }

    private var error: String? {
        let file = path(executable)
        if file.isEmpty { return nil }
        var isDirectory: ObjCBool = false
        guard file.hasPrefix("/"), FileManager.default.fileExists(atPath: file, isDirectory: &isDirectory), !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: file) else { return "请选择存在的可执行文件；App 的程序通常位于 Contents/MacOS 目录。" }
        do { _ = try LaunchArguments.parse(arguments) } catch { return String(describing: error) }
        let folder = path(directory)
        if !folder.isEmpty {
            guard folder.hasPrefix("/"), FileManager.default.fileExists(atPath: folder, isDirectory: &isDirectory), isDirectory.boolValue else { return "工作目录不存在或不是文件夹" }
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("设置启动方式").font(.title2.weight(.semibold))
            Text("选择要启动的程序，AgentGuard 会先加载已批准的权限。需要终端输入的工具请继续使用 guard run。")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Menu("从已有自启任务读取…") {
                    if items.isEmpty { Text("没有找到可导入的自启任务") }
                    ForEach(items) { item in
                        Button(item.label + (item.unsupportedKeys.isEmpty ? "" : "（含额外设置，暂不能导入）")) {
                            executable = item.executable
                            arguments = LaunchArguments.format(item.arguments)
                            directory = item.workingDirectory ?? ""
                            originalLabel = item.label
                            originalPath = item.path
                        }
                        .disabled(!item.unsupportedKeys.isEmpty)
                    }
                }
                .disabled(lockOriginal)
                if originalLabel != nil && !lockOriginal {
                    Button("不替换原自启") { originalLabel = nil; originalPath = nil }
                }
            }
            if let scanError { Text(scanError).font(.caption).foregroundStyle(.secondary) }
            Text("启动程序").font(.headline)
            HStack {
                TextField("程序的完整路径", text: $executable).textFieldStyle(.roundedBorder)
                Button("选择…") { Task { if let picked = await model.pickFile() { executable = picked } } }
            }
            Text("启动参数").font(.headline)
            TextField("可选，例如 --data-dir \"/路径/包含 空格\"", text: $arguments).textFieldStyle(.roundedBorder)
            Text("工作目录").font(.headline)
            TextField("可选，留空使用此配置的工作区", text: $directory).textFieldStyle(.roundedBorder)
            Toggle("登录 Mac 时自动启动", isOn: $runAtLogin)
            Text(runAtLogin ? "点击启动后启用登录自启，异常退出后会尝试重新启动。" : "点击启动后仅在本次登录中运行，下次登录不会自动启动。")
                .font(.caption).foregroundStyle(.secondary)
            if let originalLabel {
                Text("将替换原自启任务：\(originalLabel)").font(.caption).foregroundStyle(.secondary)
                if lockOriginal { Text("原启动方式已有备份；如需更换关联任务，请先恢复原启动方式。").font(.caption).foregroundStyle(.secondary) }
            }
            if let error { Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存设置") {
                    guard let parsed = try? LaunchArguments.parse(arguments) else { return }
                    save(LaunchSettings(executable: path(executable), arguments: parsed, workingDirectory: path(directory).isEmpty ? nil : path(directory),
                                        originalLabel: originalLabel, restartOnCleanExit: profile.launch?.restartOnCleanExit ?? false,
                                        runAtLogin: runAtLogin, originalPath: originalPath))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(path(executable).isEmpty || error != nil)
            }
        }
        .padding(24).frame(width: 540)
        .task {
            let files = LaunchItemFiles(home: model.config.home, configRoot: model.config.configRoot,
                                        launcherPath: model.config.launcherPath, labelPrefix: AgentGuardConfig.labelPrefix)
            let result = await Task.detached { Result { try files.originals() } }.value
            switch result {
            case let .success(found):
                items = found.sorted { a, b in
                    let aMatches = a.executable == path(executable), bMatches = b.executable == path(executable)
                    return aMatches == bMatches ? a.label < b.label : aMatches
                }
            case .failure: scanError = "暂时无法读取部分自启任务，仍可手动填写启动程序和参数。"
            }
        }
    }
}
#endif
