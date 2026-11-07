#if os(macOS)
import GuardCore
import SwiftUI

/// AgentGuard itself: one overall result first, components on request, then repair, export and removal.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var showComponents = false
    @State private var opensAtLogin = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                overall
                Card(title: "登录", systemImage: "person.crop.circle") {
                    SwiftUI.Toggle(isOn: Binding(get: { opensAtLogin }, set: { value in
                        model.setOpensAtLogin(value)
                        opensAtLogin = model.opensAtLogin
                    })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("登录 Mac 时打开 AgentGuard")
                            Text("只控制 AgentGuard 的窗口和菜单栏。各程序自己的登录自启在程序的“启动方式”中设置；后台保护不依赖这个开关。")
                                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .toggleStyle(.switch)
                }
                Card(title: "窗口与退出", systemImage: "macwindow") {
                    VStack(alignment: .leading, spacing: 6) {
                        behavior("关闭窗口", "隐藏窗口；菜单栏、受管程序和后台限制继续运行。")
                        behavior("退出 AgentGuard", "退出窗口和菜单栏；受管程序和后台限制继续运行，不改变任何登录启动设置。")
                        behavior("停止本次运行", "在程序的“启动方式”中操作：结束这次运行的程序，本次登录不再自动拉起，以后登录仍按原设置。")
                        behavior("关闭程序的登录自启", "只影响以后的登录，不停止现在的程序。")
                        behavior("移除某个程序的保护", "先停止它的受管副本，再删除权限和启动项；是否恢复原启动方式由你选择。")
                        behavior("卸载 AgentGuard", "停止全部受管程序，移除启动项和后台组件；保留权限设置、备份和程序的工作数据。")
                    }
                }
                Card(title: "故障处理", systemImage: "wrench.and.screwdriver") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("后台服务连不上、版本不一致或刚更新 App 后，先点“检查并修复”。修复会重新登记后台服务，可能需要在系统设置中允许。")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        if let notice = model.installNotice { Text(notice).font(.callout) }
                        HStack {
                            Button("检查并修复") { model.installHelper() }
                            Button("导出诊断…") { model.exportDiagnostics() }
                            Button("复制诊断") { Pasteboard.copy(model.diagnosticsText()) }
                        }
                    }
                }
                Card(title: "卸载 AgentGuard", systemImage: "trash") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("会先列出受影响的程序和启动项，确认后停止全部受管程序，再移除 AgentGuard 安装的启动项、活动记录采集器和后台服务。权限设置、备份和程序的工作数据会保留。没有完成的部分会单独报告。")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Button("卸载…", role: .destructive) { model.uninstall(restoreOriginals: false) }
                            Button("卸载并恢复原启动方式…", role: .destructive) { model.uninstall(restoreOriginals: true) }
                        }
                        .disabled(!model.helperReachable)
                        Text("恢复原启动方式后，相关程序将不受任何限制地运行。").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .padding(20)
        }
        .frame(width: 560, height: 640)
        .onAppear {
            opensAtLogin = model.opensAtLogin
            model.refresh()
        }
    }

    private var overall: some View {
        let (title, detail, level) = installationResult
        return Card(title: title, systemImage: Theme.symbol(level)) {
            VStack(alignment: .leading, spacing: 8) {
                Text(detail).font(.callout).fixedSize(horizontal: false, vertical: true)
                DisclosureGroup("组件详情", isExpanded: $showComponents) {
                    VStack(alignment: .leading, spacing: 4) {
                        component("AgentGuard App", AgentGuardVersion.current, ok: true)
                        component("后台服务（Helper）", model.helperReachable ? "已连接 · 协议 \(model.report?.helperProtocol ?? 0)" : "未连接",
                                  ok: model.helperReachable && !model.helperOutdated)
                        component("活动记录采集器", model.helperProblems.isEmpty ? "正常" : model.helperProblems.joined(separator: "；"),
                                  ok: model.helperProblems.isEmpty)
                        component("采集器位置", AgentGuardConfig.collectorPath, ok: true)
                    }
                    .padding(.top, 4)
                }
                .font(.callout)
            }
        }
    }

    private var installationResult: (String, String, StatusLevel) {
        if !model.helperReachable {
            return ("后台保护不可用", "连不上后台服务：权限无法保存，状态无法确认。已经运行的受管程序继续按原来的限制运行。点“检查并修复”。", .problem)
        }
        if model.helperOutdated {
            return ("需要更新后台服务", "App 已更新，但后台服务还是旧版本，部分功能不可用。点“检查并修复”完成更新。", .attention)
        }
        if !model.helperProblems.isEmpty {
            return ("安装完整，活动记录有缺口", "保护正常执行，但活动记录采集器报告了问题，被阻止的访问可能没有全部列出。", .attention)
        }
        return ("安装完整，后台保护可用", "App、后台服务和活动记录采集器都在正常工作，版本一致。", .allGood)
    }

    private func behavior(_ action: String, _ result: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(action).font(.callout.weight(.medium)).frame(width: 130, alignment: .leading)
            Text(result).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func component(_ name: String, _ value: String, ok: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill").foregroundStyle(ok ? Color.green : Color.orange)
            Text(name).frame(width: 130, alignment: .leading)
            Text(value).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }
}
#endif
