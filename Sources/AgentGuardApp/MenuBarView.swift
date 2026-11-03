#if os(macOS)
import GuardCore
import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let overall = model.overall
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: Theme.symbol(overall.level))
                    .font(.system(size: 30))
                    .foregroundStyle(Theme.color(overall.level))
                    .symbolRenderingMode(.hierarchical)
                VStack(alignment: .leading, spacing: 2) {
                    Text(Theme.title(overall.level)).font(.headline)
                    Text(summary(overall)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless)
                    .help("刷新")
            }
            .padding(14)

            Divider()

            if model.helperReachable, let profiles = model.report?.profiles, !profiles.isEmpty {
                VStack(spacing: 2) {
                    ForEach(profiles, id: \.profileID) { profile in
                        Button { open(profile.profileID) } label: { MenuProfileRow(profile: profile) }
                            .buttonStyle(.plain)
                    }
                }
                .padding(6)
            } else {
                Text(model.helperReachable ? "还没有配置档" : "Helper 未运行")
                    .font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity).padding(.vertical, 18)
            }

            Divider()

            HStack {
                Button("打开 AgentGuard") { open(nil) }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                Spacer()
                Button("退出") { NSApp.terminate(nil) }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
            .padding(12)
        }
        .frame(width: 360)
        .onAppear { model.refresh() }
    }

    private func summary(_ overall: OverallStatus) -> String {
        guard !overall.reasons.isEmpty else {
            let count = model.report?.profiles.count ?? 0
            return count == 0 ? "没有受管对象" : "\(count) 个配置档均已生效"
        }
        return overall.reasons.joined(separator: "，")
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

    var body: some View {
        HStack(spacing: 10) {
            IconTile(systemImage: profile.mode.symbol, tint: profile.mode.tint, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                Text(profile.profileID).font(.body.weight(.medium))
                Text("\(profile.mode.displayName) · \(profile.revisionState.displayText)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if profile.pendingCount > 0 {
                Chip(text: "\(profile.pendingCount) 待定", tint: .orange)
            }
            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .background(RoundedRectangle(cornerRadius: 8).fill(hovering ? Color.primary.opacity(0.06) : .clear))
        .onHover { hovering = $0 }
    }
}
#endif
