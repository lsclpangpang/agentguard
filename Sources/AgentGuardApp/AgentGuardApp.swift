#if os(macOS)
import GuardCore
import SwiftUI

@main
struct AgentGuardApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent().environmentObject(model)
        } label: {
            Image(systemName: icon)
        }
        .menuBarExtraStyle(.window)

        Window("AgentGuard", id: "main") {
            MainView().environmentObject(model).frame(minWidth: 820, minHeight: 560)
        }
    }

    private var icon: String {
        switch model.overall.level {
        case .allGood: return "lock.shield"
        case .attention: return "exclamationmark.shield"
        case .problem: return "xmark.shield"
        }
    }
}

struct MenuContent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            ForEach(model.overall.reasons, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
            Divider()
            ForEach(model.report?.profiles ?? [], id: \.profileID) { profile in
                HStack {
                    Text(profile.profileID)
                    Spacer()
                    Text("\(profile.mode.displayName) · \(profile.revisionState.displayText)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Divider()
            HStack {
                Button("打开 AgentGuard") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Button("刷新") { model.refresh() }
                Spacer()
                Button("退出") { NSApp.terminate(nil) }
            }
        }
        .padding(12)
        .frame(width: 340)
        .onAppear { model.refresh() }
    }

    private var title: String {
        switch model.overall.level {
        case .allGood: return "全部正常"
        case .attention: return "需要关注"
        case .problem: return "存在问题"
        }
    }
}

struct MainView: View {
    @EnvironmentObject var model: AppModel
    @State private var selection: String?
    @State private var newProfileID = ""
    @State private var newTemplates: Set<String> = ["system-base"]

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("配置档") {
                    ForEach(model.report?.profiles ?? [], id: \.profileID) { profile in
                        Text(profile.profileID).tag(profile.profileID)
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading) {
                    TextField("新配置档名称（小写字母、数字、-）", text: $newProfileID)
                    ForEach(model.templates, id: \.id) { template in
                        Toggle(template.id, isOn: Binding(
                            get: { newTemplates.contains(template.id) },
                            set: { if $0 { newTemplates.insert(template.id) } else { newTemplates.remove(template.id) } }))
                    }
                    Button("新建（受限学习）") { model.createProfile(id: newProfileID, templateIDs: newTemplates) }
                    Button("导入现有 Knodo 沙箱") { model.importKnodo() }
                }
                .padding(8)
            }
        } detail: {
            VStack(spacing: 0) {
                banners
                if let selection, model.profile(selection) != nil {
                    ProfileDetail(profileID: selection).id("\(selection)-\(model.revision)")
                } else {
                    Text(model.helperReachable ? "选择或新建一个配置档" : "尚未连接 Helper").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .onAppear { model.refresh() }
    }

    @ViewBuilder private var banners: some View {
        if !model.helperReachable {
            Banner(text: "Helper 未运行。安装后在“系统设置 > 通用 > 登录项”中允许，并给 /usr/bin/eslogger 授予“完全磁盘访问”。", action: ("安装 Helper", model.installHelper))
        }
        if let problems = model.report?.collectorProblems, !problems.isEmpty {
            Banner(text: "采集器：" + problems.joined(separator: "；") + "。未观测到不代表没有发生。", action: nil)
        }
        Banner(text: "系统能力检查（M0）尚未实现：规则在本机是否真正拦截，需要用测试文件手动验证。", action: nil)
        if let error = model.lastError {
            Banner(text: error, action: ("关闭", { model.lastError = nil }))
        }
    }
}

struct Banner: View {
    let text: String
    let action: (String, () -> Void)?

    var body: some View {
        HStack {
            Text(text).font(.callout)
            Spacer()
            if let action { Button(action.0, action: action.1) }
        }
        .padding(8)
        .background(Color.yellow.opacity(0.15))
    }
}

struct ProfileDetail: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    @State private var newPort = ""

    var body: some View {
        if let profile = model.profile(profileID) {
            Form {
                Section("状态") {
                    if let status = model.report?.profiles.first(where: { $0.profileID == profileID }) {
                        LabeledContent("已保存修订", value: "\(status.savedRevision)")
                        LabeledContent("运行状态", value: status.revisionState.displayText)
                        LabeledContent("运行实例", value: status.runningInstances.map(String.init).joined(separator: ", "))
                    }
                    Picker("模式", selection: Binding(get: { profile.mode }, set: { mode in model.edit(profileID) { $0.mode = mode } })) {
                        Text(Mode.enforce.displayName).tag(Mode.enforce)
                        Text(Mode.restrictedLearning.displayName).tag(Mode.restrictedLearning)
                    }
                    Text("命令行启动：guard run \(profileID) -- <命令>").font(.caption).textSelection(.enabled)
                }

                Section("目录与文件") {
                    ForEach(Array(profile.files.enumerated()), id: \.offset) { index, grant in
                        HStack {
                            Text(grant.path).textSelection(.enabled)
                            Spacer()
                            if grant.readsSecrets { Text("允许读取凭证").foregroundStyle(.red).font(.caption) }
                            Text(grant.access == .readWrite ? "读写" : "只读").foregroundStyle(.secondary)
                            Button("移除") { model.edit(profileID) { $0.files.remove(at: index) } }
                        }
                    }
                    HStack {
                        Button("添加只读…") { model.addFolder(to: profileID, access: .readOnly) }
                        Button("添加读写…") { model.addFolder(to: profileID, access: .readWrite) }
                    }
                }

                Section("运行时模板") {
                    ForEach(model.templates, id: \.id) { template in
                        Toggle(template.id, isOn: Binding(
                            get: { profile.templates.contains { $0.id == template.id } },
                            set: { enabled in
                                model.edit(profileID) { p in
                                    p.templates.removeAll { $0.id == template.id }
                                    if enabled { p.templates.append(TemplateRef(id: template.id, version: template.version)) }
                                }
                            }))
                    }
                }

                Section("程序与网络") {
                    if profile.unrestrictedExec { Text("允许执行任意程序（迁移保留）").foregroundStyle(.orange) }
                    ForEach(profile.exec, id: \.path) { Text("可执行：\($0.path)") }
                    ForEach(profile.network.loopbackTCPConnect, id: \.self) { port in
                        HStack {
                            Text("本机 TCP 端口 \(port)")
                            Spacer()
                            Button("移除") { model.edit(profileID) { $0.network.loopbackTCPConnect.removeAll { $0 == port } } }
                        }
                    }
                    HStack {
                        TextField("端口", text: $newPort).frame(width: 100)
                        Button("允许连接本机端口") {
                            if let port = Int(newPort) { model.edit(profileID) { $0.network.loopbackTCPConnect.append(port) } }
                        }
                    }
                    Toggle("允许对外 TCP 连接", isOn: Binding(
                        get: { profile.network.outboundTCP == .allowed },
                        set: { allowed in model.edit(profileID) { $0.network.outboundTCP = allowed ? .allowed : .denied } }))
                }

                Section("待定项（已观测行为，不代表全部）") {
                    let items = model.pending[profileID] ?? []
                    if items.isEmpty { Text("暂无").foregroundStyle(.secondary) }
                    ForEach(items, id: \.self) { item in
                        HStack {
                            Text(describe(item.suggestion)).foregroundStyle(item.sensitive ? .red : .primary)
                            Spacer()
                            Text("\(item.evidence) 次").foregroundStyle(.secondary)
                            Button("允许") { model.accept(item, for: profileID) }
                        }
                    }
                }

                if let launch = profile.launch {
                    Section("启动项") {
                        Text(([launch.executable] + launch.arguments).joined(separator: " ")).textSelection(.enabled)
                        if let original = launch.originalLabel { Text("原启动项：\(original)").foregroundStyle(.secondary) }
                        HStack {
                            Button("接管启动项") { model.installLaunchAgent(profileID) }
                            Button("停止并移除管控") { model.removeManagement(profileID, restoreOriginal: false) }
                            Button("恢复原启动项…") { model.removeManagement(profileID, restoreOriginal: true) }
                        }
                    }
                }
            }
            .formStyle(.grouped)
        }
    }

    private func describe(_ suggestion: Suggestion) -> String {
        switch suggestion {
        case let .template(id): return "启用模板 \(id)"
        case let .file(path, kind, access): return "\(access == .readWrite ? "读写" : "只读")\(kind == .directory ? "目录" : "文件") \(path)"
        case let .exec(path): return "执行 \(path)"
        case let .loopbackPort(port): return "连接本机 TCP 端口 \(port)"
        case .outboundTCP: return "对外 TCP 连接"
        case .listen: return "监听端口"
        }
    }
}
#else
@main
struct AgentGuardApp {
    static func main() {
        print("AgentGuard 只能在 macOS 上运行")
    }
}
#endif
