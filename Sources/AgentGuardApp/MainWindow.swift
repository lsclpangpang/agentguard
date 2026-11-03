#if os(macOS)
import GuardCore
import SwiftUI

struct MainWindow: View {
    static let selectionKey = "selectedProfile"

    @EnvironmentObject var model: AppModel
    @AppStorage(MainWindow.selectionKey) private var storedSelection = ""
    @State private var selection: String?
    @State private var creating = false

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
        .onAppear {
            model.refresh()
            selection = storedSelection.isEmpty ? nil : storedSelection
        }
        .onChange(of: selection) { _, value in storedSelection = value ?? "" }
        .onChange(of: model.report?.profiles.map(\.profileID) ?? []) { _, ids in
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

    private var nameIsValid: Bool { ProfileID.isValid(name) }
    private var nameTaken: Bool { model.report?.profiles.contains { $0.profileID == name } ?? false }

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
                    model.createProfile(id: name, templateIDs: selected)
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
