#if os(macOS)
import GuardCore
import SwiftUI

struct MainWindow: View {
    static let selectionKey = "selectedProfile"

    @EnvironmentObject var model: AppModel
    @AppStorage(MainWindow.selectionKey) private var storedSelection = ""
    @State private var selection: String?
    @State private var creating = false
    @State private var tidying = false
    @Environment(\.openWindow) private var openWindow
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
            NewProgramWizard(isPresented: $creating) { selection = $0 }.environmentObject(model)
        }
        .sheet(isPresented: $tidying) {
            TidyUpSheet(isPresented: $tidying).environmentObject(model)
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
                    Button("添加程序…") { creating = true }
                    Button("整理现有安装…") { tidying = true }
                    Divider()
                    Button("迁移现有 Knodo 沙箱…") { model.importKnodo() }
                } label: {
                    Label("添加", systemImage: "plus")
                } primaryAction: {
                    creating = true
                }
                .disabled(!model.helperReachable)
                .help("添加要保护的程序")
            }
            ToolbarItem(placement: .automatic) {
                CollectorTipsButton(
                    problems: model.helperProblems,
                    reachable: model.helperReachable,
                    acknowledge: model.acknowledgeCollectorProblems
                )
            }
            ToolbarItem(placement: .automatic) {
                Button {
                    openWindow(id: "settings")
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label("设置", systemImage: "gearshape")
                }
                .help("AgentGuard 设置、故障处理与卸载")
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
        // The menu bar writes the program the user picked there; follow it while the window is open.
        .onChange(of: storedSelection) { _, value in
            if !value.isEmpty, value != selection { selection = value }
        }
        .onChange(of: model.report?.profiles.map(\.profileID) ?? []) { _, ids in
            // 列表暂时为空（查询失败/正在刷新）时保持当前选择，别把详情页拆掉重建。
            guard !ids.isEmpty else { return }
            if selection == nil || !(ids.contains(selection ?? "")) { selection = ids.first }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.refresh() }
    }

    private var sidebar: some View {
        List(selection: $selection) {
            Section("我的程序") {
                ForEach(model.report?.profiles ?? [], id: \.profileID) { profile in
                    SidebarRow(profile: profile)
                        .tag(profile.profileID)
                        .contextMenu {
                            if model.profile(profile.profileID)?.launch?.originalLabel != nil {
                                Button("移除保护并恢复原启动方式…", role: .destructive) { model.deleteProfile(profile.profileID, restoreOriginal: true) }
                            }
                            Button("移除保护…", role: .destructive) { model.deleteProfile(profile.profileID) }
                        }
                        .badge(profile.pendingCount)
                }
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if model.helperReachable && (model.report?.profiles.isEmpty ?? true) {
                VStack(spacing: 8) {
                    Text("还没有受保护的程序").foregroundStyle(.secondary)
                    Button("添加程序") { creating = true }
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
                    ContentUnavailableView("选择一个程序", systemImage: "shield.lefthalf.filled",
                                           description: Text("或者点工具栏的 +，选择要保护的程序和它可以访问的项目文件夹。"))
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
            items.append(Notice(kind: .warning, text: "上次操作中没有确认的部分：\n" + warning, actionTitle: "关闭") { model.lastWarning = nil })
        }
        if let notice = model.lastNotice {
            items.append(Notice(kind: .info, text: notice, actionTitle: "关闭") { model.lastNotice = nil })
        }
        if model.helperOutdated {
            items.append(Notice(kind: .warning, text: "后台服务还是旧版本，部分功能不可用。", actionTitle: "检查并修复") { model.installHelper() })
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
    @EnvironmentObject var model: AppModel
    let profile: ProfileStatusReport

    private var summary: ProgramStatusSummary {
        ProgramStatusSummary.evaluate(profile, freshness: model.freshness, programName: profile.profileID,
                                      hasLaunch: model.profile(profile.profileID)?.launch != nil)
    }

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: "app.badge.checkmark", tint: Theme.color(summary.headlineLevel), size: 24)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(profile.profileID)
                    if !profile.untrackedInstances.isEmpty { TrackingGapIndicator() }
                }
                HStack(spacing: 4) {
                    Circle().fill(Theme.color(summary.headlineLevel)).frame(width: 6, height: 6)
                    Text(summary.headline).font(.caption).foregroundStyle(.secondary).lineLimit(1)
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

#endif
