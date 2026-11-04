#if os(macOS)
import GuardCore
import SwiftUI

/// The panel under the menu bar icon: overall state first, then each profile, then the way into the app.
struct MenuBarView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var spin = 0.0

    var body: some View {
        let overall = model.overall
        VStack(spacing: 0) {
            header(overall)
            // Helper 断开时下面的占位已经说明了，别再重复一遍。
            if model.helperReachable, !overall.reasons.isEmpty {
                reasons(overall)
            }
            content
            footer
        }
        .frame(width: 340)
        .onAppear { model.refresh() }
    }

    // MARK: Header

    private func header(_ overall: OverallStatus) -> some View {
        let tint = Theme.color(overall.level)
        return HStack(spacing: 12) {
            Image(systemName: Theme.symbol(overall.level))
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 40, height: 40)
                .background(Circle().fill(tint.opacity(0.16)))
            VStack(alignment: .leading, spacing: 2) {
                Text(Theme.title(overall.level)).font(.system(size: 14, weight: .semibold))
                Text(headline(overall)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            Button {
                withAnimation(.easeInOut(duration: 0.6)) { spin += 360 }
                model.refresh()
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 12, weight: .semibold))
                    .rotationEffect(.degrees(spin))
                    .frame(width: 26, height: 26)
                    .contentShape(Circle())
            }
            .buttonStyle(MenuIconButtonStyle())
            .help("刷新")
        }
        .padding(.horizontal, 14)
        .padding(.top, 14)
        .padding(.bottom, 12)
        .background(
            LinearGradient(colors: [tint.opacity(0.10), .clear], startPoint: .top, endPoint: .bottom)
        )
    }

    private func headline(_ overall: OverallStatus) -> String {
        guard model.helperReachable else { return "Helper 未连接" }
        let count = model.report?.profiles.count ?? 0
        if count == 0 { return "还没有受管对象" }
        return overall.reasons.isEmpty ? "\(count) 个配置档均已生效" : "\(count) 个配置档，\(overall.reasons.count) 项需要处理"
    }

    /// Each reason on its own line; joined into one sentence they were cut off after two lines.
    private func reasons(_ overall: OverallStatus) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(overall.reasons, id: \.self) { reason in
                HStack(alignment: .top, spacing: 8) {
                    Circle().fill(Theme.color(overall.level)).frame(width: 5, height: 5).padding(.top, 5)
                    Text(reason).font(.caption).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.color(overall.level).opacity(0.08)))
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    // MARK: Profiles

    @ViewBuilder private var content: some View {
        if !model.helperReachable {
            placeholder(symbol: "bolt.horizontal.circle", title: "Helper 未运行", detail: "权限无法保存，沙箱也不会更新。") {
                Button("打开 AgentGuard 安装") { open(nil) }.controlSize(.small)
            }
        } else if let profiles = model.report?.profiles, !profiles.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("配置档")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(profiles, id: \.profileID) { profile in
                            Button { open(profile.profileID) } label: { MenuProfileRow(profile: profile) }
                                .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 6)
                }
                // 配置档多了也别把面板撑出屏幕。
                .frame(height: min(CGFloat(profiles.count) * 46 - 2, 46 * 6 - 2))
            }
            .padding(.top, 4)
            .padding(.bottom, 8)
        } else {
            placeholder(symbol: "shield.lefthalf.filled", title: "还没有配置档", detail: "为命令行工具或 Agent 设定它能访问的文件和网络。") {
                Button("新建配置档") { open(nil) }.controlSize(.small)
            }
        }
    }

    private func placeholder<Action: View>(symbol: String, title: String, detail: String, @ViewBuilder action: () -> Action) -> some View {
        VStack(spacing: 6) {
            Image(systemName: symbol).font(.system(size: 26, weight: .light)).foregroundStyle(.secondary)
            Text(title).font(.callout.weight(.medium))
            Text(detail).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            action().padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
    }

    // MARK: Footer

    private var footer: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                Button { open(nil) } label: {
                    Label("打开 AgentGuard", systemImage: "macwindow")
                }
                .buttonStyle(MenuFooterButtonStyle())
                .keyboardShortcut("o")
                Spacer()
                Button { NSApp.terminate(nil) } label: {
                    Label("退出", systemImage: "power")
                }
                .buttonStyle(MenuFooterButtonStyle(secondary: true))
                .keyboardShortcut("q")
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
    }

    private func open(_ profileID: String?) {
        if let profileID { UserDefaults.standard.set(profileID, forKey: MainWindow.selectionKey) }
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

private struct MenuProfileRow: View {
    let profile: ProfileStatusReport
    @State private var hovering = false

    private var problem: (text: String, tint: Color)? {
        if !profile.unmanagedProcesses.isEmpty { return ("\(profile.unmanagedProcesses.count) 未受管", .red) }
        if !profile.detachedInstances.isEmpty { return ("已脱离看护", .orange) }
        if profile.pendingCount > 0 { return ("\(profile.pendingCount) 待定", .orange) }
        return nil
    }

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: profile.mode.symbol, tint: profile.mode.tint, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(profile.profileID).font(.system(size: 13, weight: .medium)).lineLimit(1)
                HStack(spacing: 5) {
                    Circle().fill(profile.revisionState.tint).frame(width: 6, height: 6)
                    Text("\(profile.mode.displayName) · \(profile.revisionState.displayText)")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            if let problem {
                Chip(text: problem.text, tint: problem.tint)
            }
            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary)
                .opacity(hovering ? 1 : 0.5)
        }
        .padding(.horizontal, 8)
        .frame(height: 44)
        .contentShape(Rectangle())
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(hovering ? Color.primary.opacity(0.07) : .clear))
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

/// Round icon button that highlights on hover, like the system's own menu bar panels.
private struct MenuIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverBackground(shape: Circle(), pressed: configuration.isPressed) { configuration.label }
    }
}

/// Footer actions: plain until hovered, so the panel doesn't end in a row of bordered buttons.
private struct MenuFooterButtonStyle: ButtonStyle {
    var secondary = false

    func makeBody(configuration: Configuration) -> some View {
        HoverBackground(shape: RoundedRectangle(cornerRadius: 6, style: .continuous), pressed: configuration.isPressed) {
            configuration.label
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(secondary ? Color.secondary : Color.primary)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
        }
    }
}

private struct HoverBackground<S: Shape, Label: View>: View {
    let shape: S
    let pressed: Bool
    @ViewBuilder let label: () -> Label
    @State private var hovering = false

    var body: some View {
        label()
            .background(shape.fill(Color.primary.opacity(pressed ? 0.14 : hovering ? 0.08 : 0)))
            .contentShape(shape)
            .onHover { hovering = $0 }
    }
}
#endif
