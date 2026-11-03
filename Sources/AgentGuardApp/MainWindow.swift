#if os(macOS)
import GuardCore
import SwiftUI

struct MainWindow: View {
    static let selectionKey = "selectedProfile"

    @EnvironmentObject var model: AppModel
    @AppStorage(MainWindow.selectionKey) private var storedSelection = ""
    @State private var selection: String?
    @State private var creating = false
    @AppStorage(MainWindowBehavior.pinnedKey) private var pinned = false

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 220, ideal: 240, max: 320)
        } detail: {
            detail
        }
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $creating) {
            NewProfileSheet(isPresented: $creating).environmentObject(model)
        }
        // When a sheet closes AppKit hands focus to the window's first text field, the port field near
        // the bottom, and scrolls the detail view down to it.
        .sheet(item: $model.confirmation, onDismiss: { NSApp.keyWindow?.makeFirstResponder(nil) }) { pending in
            ConfirmationSheet(pending: pending) { model.answerConfirmation($0) }
        }
        .background(WindowAccessor { MainWindowBehavior.apply(pinned: pinned, to: $0) })
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Toggle(isOn: $pinned) {
                    Label(pinned ? "取消置顶" : "置顶窗口", systemImage: pinned ? "pin.fill" : "pin")
                }
                .toggleStyle(.button)
                .help(pinned ? "取消置顶：窗口恢复普通层级" : "置顶：窗口始终显示在其他应用之上")
            }
        }
        .onAppear {
            MainWindowBehavior.windowOpened()
            model.refresh()
            selection = storedSelection.isEmpty ? nil : storedSelection
        }
        .onDisappear { MainWindowBehavior.windowClosed() }
        .onChange(of: selection) { _, value in storedSelection = value ?? "" }
        .onChange(of: model.report?.profiles.map(\.profileID) ?? []) { _, ids in
            // 列表暂时为空（查询失败/正在刷新）时保持当前选择，别把详情页拆掉重建。
            guard !ids.isEmpty else { return }
            if selection == nil || !(ids.contains(selection ?? "")) { selection = ids.first }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.refresh() }
    }

    private var sidebar: some View {
        List(selection: $selection) {
            Section("配置档") {
                ForEach(model.report?.profiles ?? [], id: \.profileID) { profile in
                    SidebarRow(profile: profile)
                        .tag(profile.profileID)
                        .contextMenu {
                            if model.profile(profile.profileID)?.launch?.originalLabel != nil {
                                Button("删除并恢复原启动项…", role: .destructive) { model.deleteProfile(profile.profileID, restoreOriginal: true) }
                                    .disabled(!profile.runningInstances.isEmpty)
                            }
                            Button("删除配置档…", role: .destructive) { model.deleteProfile(profile.profileID) }
                                .disabled(!profile.runningInstances.isEmpty)
                        }
                        .badge(profile.pendingCount)
                }
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if model.helperReachable && (model.report?.profiles.isEmpty ?? true) {
                VStack(spacing: 8) {
                    Text("还没有配置档").foregroundStyle(.secondary)
                    Button("新建配置档") { creating = true }
                }
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    Button("新建配置档…") { creating = true }
                    Divider()
                    Button("导入现有 Knodo 沙箱") { model.importKnodo() }
                } label: {
                    Label("添加", systemImage: "plus")
                } primaryAction: {
                    creating = true
                }
                .disabled(!model.helperReachable)
                .help("新建配置档")
            }
        }
    }

    @ViewBuilder private var detail: some View {
        VStack(spacing: 0) {
            notices
            Group {
                if !model.helperReachable {
                    OnboardingView()
                } else if let selection, model.profile(selection) != nil {
                    ProfileDetailView(profileID: selection).id(selection)
                } else {
                    ContentUnavailableView("选择一个配置档", systemImage: "shield.lefthalf.filled",
                                           description: Text("或者点工具栏的 + 新建，开始为命令行工具或 Agent 设定权限。"))
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder private var notices: some View {
        let items = noticeItems
        if !items.isEmpty {
            VStack(spacing: 8) {
                ForEach(items.indices, id: \.self) { items[$0] }
            }
            .padding(.horizontal, 20)
            .padding(.top, 14)
        }
    }

    private var noticeItems: [Notice] {
        var items: [Notice] = []
        if let error = model.lastError {
            items.append(Notice(kind: .error, text: error, actionTitle: "关闭") { model.lastError = nil })
        }
        if model.helperReachable {
            if model.needsFullDiskAccess {
                items.append(Notice(kind: .warning,
                                    text: "采集器没有完全磁盘访问权限。在“隐私与安全性 > 完全磁盘访问”中添加 \(AgentGuardConfig.collectorPath)（按 ⌘⇧G 输入路径）。",
                                    actionTitle: "复制路径") { Pasteboard.copy(AgentGuardConfig.collectorPath) })
            }
            let others = model.helperProblems.filter { !$0.contains("未授权") }
            if !others.isEmpty {
                items.append(Notice(kind: .warning, text: "采集器：" + others.joined(separator: "；") + "。未观测到不代表没有发生。",
                                    actionTitle: "已知悉", action: model.acknowledgeCollectorProblems))
            }
        }
        return items
    }
}

private struct SidebarRow: View {
    let profile: ProfileStatusReport

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: profile.mode.symbol, tint: profile.mode.tint, size: 24)
            VStack(alignment: .leading, spacing: 1) {
                Text(profile.profileID)
                HStack(spacing: 4) {
                    Circle().fill(profile.revisionState.tint).frame(width: 6, height: 6)
                    Text(profile.revisionState.displayText).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct OnboardingView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: "lock.shield")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.tint)
            VStack(spacing: 6) {
                Text("安装 AgentGuard Helper").font(.title2.weight(.semibold))
                Text("Helper 负责保存权限、加载沙箱规则和记录受管程序的行为。").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 14) {
                Step(number: 1, title: "安装 Helper", detail: "点下面的按钮。第一次安装时系统会先拦下后台项目，这是正常的。")
                Step(number: 2, title: "允许在后台运行", detail: "在“系统设置 > 通用 > 登录项 > 允许在后台”中打开 AgentGuard。")
                Step(number: 3, title: "授予完全磁盘访问",
                     detail: "在“隐私与安全性 > 完全磁盘访问”中添加 \(AgentGuardConfig.collectorPath)。采集器装在 App 包外，重装 App 不需要重新授权。")
            }
            .frame(maxWidth: 440)
            if let notice = model.installNotice {
                Notice(kind: notice.hasPrefix("安装 Helper 失败") ? .error : .info, text: notice).frame(maxWidth: 440)
            }
            HStack {
                Button("安装 Helper", action: model.installHelper)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                Button("重新检测") { model.refresh() }
                    .controlSize(.large)
            }
        }
        .padding(40)
    }
}

private struct Step: View {
    let number: Int
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.callout.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(Circle().fill(Color.accentColor))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium))
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct NewProfileSheet: View {
    @EnvironmentObject var model: AppModel
    @Binding var isPresented: Bool
    @State private var name = ""
    @State private var selected: Set<String> = ["system-base"]
    @State private var program: String?
    @State private var runsInBackground = false
    @State private var arguments = ""
    @State private var originalLabel = ""

    private var nameIsValid: Bool { ProfileID.isValid(name) }
    private var nameTaken: Bool { model.report?.profiles.contains { $0.profileID == name } ?? false }

    private var launch: LaunchSettings? {
        guard runsInBackground, let program else { return nil }
        let label = originalLabel.trimmingCharacters(in: .whitespaces)
        return LaunchSettings(executable: program, arguments: arguments.split(separator: " ").map(String.init), workingDirectory: nil,
                              originalLabel: label.isEmpty ? nil : label, restartOnCleanExit: false)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("新建配置档").font(.title2.weight(.semibold))
                Text("新配置档以“受限学习”开始：未允许的访问会被拒绝并列为待定项，逐项批准后再切换到强制保护。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("名称").font(.headline)
                TextField("例如 claude-work", text: $name).textFieldStyle(.roundedBorder)
                Group {
                    if name.isEmpty {
                        Text("小写字母、数字和 -，用于 guard run <名称>")
                    } else if !nameIsValid {
                        Text("只能使用小写字母、数字和 -，且不能以 - 开头").foregroundStyle(.red)
                    } else if nameTaken {
                        Text("已有同名配置档").foregroundStyle(.red)
                    } else {
                        Text("命令行启动：guard run \(name) -- <命令>")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("要管控的程序").font(.headline)
                HStack(spacing: 8) {
                    if let program {
                        PathLabel(path: program).frame(maxWidth: .infinity, alignment: .leading)
                        Button("更换…") { self.program = model.chooseExecutable() ?? program }
                        Button { self.program = nil } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(.secondary).help("不指定程序")
                    } else {
                        Text("可选。指定后，没有经过 AgentGuard 直接运行它会被报告。").font(.callout).foregroundStyle(.secondary)
                        Spacer(minLength: 8)
                        Button("选择…") { program = model.chooseExecutable() }
                    }
                }
                if program != nil {
                    Picker("启动方式", selection: $runsInBackground) {
                        Text("命令行工具（guard run）").tag(false)
                        Text("后台程序（接管启动项）").tag(true)
                    }
                    .pickerStyle(.radioGroup)
                    if runsInBackground {
                        TextField("启动参数（可选，空格分隔）", text: $arguments).textFieldStyle(.roundedBorder)
                        TextField("要替换的原启动项 label（可选），例如 com.example.agent", text: $originalLabel).textFieldStyle(.roundedBorder)
                        Text("创建后在配置档的“启动项”里点“接管启动项”，以后由 AgentGuard 在沙箱内启动它。程序需要在前台运行，不要自己转到后台。")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("运行时模板").font(.headline)
                ForEach(model.templates, id: \.id) { template in
                    let info = TemplateInfo.of(template.id)
                    Toggle(isOn: Binding(
                        get: { selected.contains(template.id) },
                        set: { if $0 { selected.insert(template.id) } else { selected.remove(template.id) } })) {
                        HStack(spacing: 10) {
                            IconTile(systemImage: info.symbol, size: 24)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(info.title)
                                Text(info.detail).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .toggleStyle(.checkbox)
                }
            }

            HStack {
                Spacer()
                Button("取消") { isPresented = false }.keyboardShortcut(.cancelAction)
                Button("创建") {
                    model.createProfile(id: name, templateIDs: selected, program: program, launch: launch)
                    isPresented = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!nameIsValid || nameTaken)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
#endif
