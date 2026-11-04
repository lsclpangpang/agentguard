#if os(macOS)
import GuardCore
import SwiftUI

struct MainWindow: View {
    static let selectionKey = "selectedProfile"

    @EnvironmentObject var model: AppModel
    @AppStorage(MainWindow.selectionKey) private var storedSelection = ""
    @State private var selection: String?
    @State private var creating = false
    @State private var sidebarVisible = true
    @AppStorage(MainWindowBehavior.pinnedKey) private var pinned = false

    var body: some View {
        // NavigationSplitView's titlebar safe area shifts both columns when a notice is inserted
        // after an open panel closes. A native split view keeps the columns inside this viewport.
        GeometryReader { viewport in
            HSplitView {
                if sidebarVisible {
                    sidebar
                        .frame(width: 220)
                        .frame(maxHeight: .infinity)
                }
                detail
            }
            .frame(width: viewport.size.width, height: viewport.size.height)
        }
        .navigationTitle(selection ?? "AgentGuard")
        .sheet(isPresented: $creating) {
            NewProfileSheet(isPresented: $creating).environmentObject(model)
        }
        .sheet(item: $model.confirmation, onDismiss: { NSApp.keyWindow?.makeFirstResponder(nil) }) { pending in
            ConfirmationSheet(pending: pending) { model.answerConfirmation($0) }
        }
        .background(WindowAccessor { MainWindowBehavior.apply(pinned: pinned, to: $0) })
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button { sidebarVisible.toggle() } label: {
                    Label(sidebarVisible ? "隐藏侧栏" : "显示侧栏", systemImage: "sidebar.left")
                }
                .help(sidebarVisible ? "隐藏侧栏" : "显示侧栏")
            }
            ToolbarItem(placement: .navigation) {
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
            ToolbarItem(placement: .automatic) {
                CollectorTipsButton(
                    problems: model.helperProblems,
                    reachable: model.helperReachable,
                    acknowledge: model.acknowledgeCollectorProblems
                )
            }
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
    }

    @ViewBuilder private var detail: some View {
        VStack(spacing: 0) {
            notices
            Group {
                if !model.helperReachable && model.report == nil {
                    OnboardingView()
                } else if let selection, model.profile(selection) != nil {
                    ProfileDetailView(profileID: selection).id(selection)
                } else {
                    ContentUnavailableView("选择一个配置档", systemImage: "shield.lefthalf.filled",
                                           description: Text("或者点工具栏的 + 新建，开始为命令行工具或 Agent 设定权限。"))
                }
            }
            .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
        }
        .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .top)
        .clipped()
    }

    @ViewBuilder private var notices: some View {
        let items = noticeItems
        if !items.isEmpty {
            VStack(spacing: 8) {
                ForEach(items.indices, id: \.self) { items[$0] }
            }
            .padding(.horizontal, 20)
            .padding(.top, 14)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var noticeItems: [Notice] {
        var items: [Notice] = []
        if let error = model.lastError {
            items.append(Notice(kind: .error, text: error, actionTitle: "关闭") { model.lastError = nil })
        }
        if let warning = model.lastWarning {
            items.append(Notice(kind: .warning, text: "上次操作提示：" + warning, actionTitle: "关闭") { model.lastWarning = nil })
        }
        if !model.helperReachable && model.report != nil {
            items.append(Notice(kind: .warning, text: "暂时连不上 Helper，下面是上次的状态，修改不会生效。正在重试…"))
        }
        return items
    }
}

private struct CollectorTipsButton: View {
    let problems: [String]
    let reachable: Bool
    let acknowledge: () -> Void
    @State private var showingTips = false

    private var hasProblems: Bool { reachable && !problems.isEmpty }
    private var needsFullDiskAccess: Bool { problems.contains { $0.contains("未授权") } }

    var body: some View {
        Button { showingTips.toggle() } label: {
            Image(systemName: hasProblems ? "info.circle.fill" : "info.circle")
                .foregroundStyle(hasProblems ? Color.orange : Color.secondary)
        }
        .accessibilityLabel(hasProblems ? "活动记录提示，有采集异常" : "活动记录说明")
        .help(hasProblems ? "活动记录有提示，点此查看" : "活动记录说明")
        .popover(isPresented: $showingTips, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 12) {
                Text("活动记录说明").font(.headline)
                if !reachable {
                    Text("暂时无法获取采集状态，请稍后重试。")
                } else if hasProblems {
                    ForEach(problems, id: \.self) { problem in
                        Text(problem).foregroundStyle(.orange)
                    }
                    Text("活动记录和待定项可能不完整，已生效的权限限制继续执行。")
                } else {
                    Text("当前未报告采集异常。活动记录和待定项只包含已观测到的行为。")
                }
                Text("遗漏数量统计整台 Mac 的系统活动，在本次监测期间累计。清除历史提示后重新计数，新增问题会再次提示。")
                    .foregroundStyle(.secondary)
                if reachable && needsFullDiskAccess {
                    Text("请在“隐私与安全性 > 完全磁盘访问”中添加采集器，选择文件时按 ⌘⇧G 输入路径。")
                    Button("复制采集器路径") { Pasteboard.copy(AgentGuardConfig.collectorPath) }
                }
                if hasProblems {
                    Button("清除历史提示") {
                        acknowledge()
                        showingTips = false
                    }
                    .help("清除累计遗漏和已恢复的中断提示，当前故障仍保留")
                }
            }
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
            .padding(16)
            .frame(width: 320, alignment: .leading)
        }
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
    @State private var runAtLogin = false

    private var nameIsValid: Bool { ProfileID.isValid(name) }
    private var nameTaken: Bool { model.report?.profiles.contains { $0.profileID == name } ?? false }

    private var launch: LaunchSettings? {
        guard runsInBackground, let program, let parsed = try? LaunchArguments.parse(arguments) else { return nil }
        return LaunchSettings(executable: program, arguments: parsed, workingDirectory: nil,
                              originalLabel: nil, restartOnCleanExit: false, runAtLogin: runAtLogin)
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
                        Button("更换…") { Task { if let picked = await model.chooseExecutable() { self.program = picked } } }
                        Button { self.program = nil } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(.secondary).help("不指定程序")
                    } else {
                        Text("可选。指定后，没有经过 AgentGuard 直接运行它会被报告。").font(.callout).foregroundStyle(.secondary)
                        Spacer(minLength: 8)
                        Button("选择…") { Task { if let picked = await model.chooseExecutable() { program = picked } } }
                    }
                }
                if program != nil {
                    Picker("启动方式", selection: $runsInBackground) {
                        Text("命令行工具（guard run）").tag(false)
                        Text("后台程序（在界面启动）").tag(true)
                    }
                    .pickerStyle(.radioGroup)
                    if runsInBackground {
                        TextField("启动参数（可选，带空格的参数用引号包住）", text: $arguments).textFieldStyle(.roundedBorder)
                        Toggle("登录 Mac 时自动启动", isOn: $runAtLogin)
                        if (try? LaunchArguments.parse(arguments)) == nil { Text("启动参数的引号或反斜杠不完整").font(.caption).foregroundStyle(.red) }
                        Text("创建后在“启动方式”里点“启动程序”。如需替换已有自启任务，可在“编辑设置”中直接选择。需要终端输入的工具请选命令行方式。")
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
                .disabled(!nameIsValid || nameTaken || (runsInBackground && (try? LaunchArguments.parse(arguments)) == nil))
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
#endif
