#if os(macOS)
import AppKit
import GuardCore
import SwiftUI

/// What the program tried, what was blocked, and how each item was handled.
struct ActivityTab: View {
    @EnvironmentObject var model: AppModel
    let profileID: String
    @State private var selected: Set<Suggestion> = []
    @State private var showRecent = false
    @State private var expandedAccess: Observation?

    private var items: [PendingItem] { model.pending[profileID] ?? [] }
    private var log: ActivityLog? { model.activity[profileID] }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if log?.recordsIncomplete == true || !model.helperProblems.isEmpty {
                Notice(kind: .warning, text: "部分活动记录缺失：被阻止的访问可能没有全部列出。已经生效的限制不受影响。")
            }
            blocked
            suggestions
            if !selected.isEmpty {
                HStack {
                    Text("已选 \(selected.count) 项").foregroundStyle(.secondary)
                    Spacer()
                    Button("取消选择") { selected = [] }
                    Button("允许所选…") {
                        let chosen = items.filter { selected.contains($0.suggestion) }
                        selected = []
                        model.acceptAll(chosen, for: profileID)
                    }
                    .buttonStyle(.borderedProminent)
                    .help("确认前会逐项列出实际新增的权限")
                }
            }
            archived
            history
            recent
        }
        .onAppear { model.loadActivity(profileID) }
        .onChange(of: model.revision) { _, _ in model.loadActivity(profileID) }
    }

    // MARK: Pending

    @ViewBuilder private var blocked: some View {
        let list = items.filter(\.wasBlocked)
        Card(title: "被阻止的访问", systemImage: "hand.raised.fill",
             subtitle: "沙箱拒绝了这些访问。保持阻止是正常的选择：它会归档这条记录，以后相同的访问不再提醒。需要时再给最小的权限。") {
            if list.isEmpty {
                Text("最近没有被阻止的访问。").font(.callout).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 2) {
                    ForEach(list, id: \.self) { item in
                        PendingRow(item: item, selected: binding(item), templates: model.templates) {
                            Button("保持阻止") { model.decide(item, .keepBlocked, for: profileID) }
                            Button("允许…") { model.acceptAll([item], for: profileID) }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private var suggestions: some View {
        let unknown = items.filter { !$0.wasBlocked && !$0.refusalKnown }
        if !unknown.isEmpty {
            Card(title: "需要处理的访问", systemImage: "questionmark.circle",
                 subtitle: "后台服务是旧版本，无法区分这些访问是否被阻止。更新后台服务后会分开显示。") {
                VStack(spacing: 2) {
                    ForEach(unknown, id: \.self) { item in
                        PendingRow(item: item, selected: binding(item), templates: model.templates) {
                            Button("允许…") { model.acceptAll([item], for: profileID) }
                        }
                    }
                }
            }
        }
        let list = items.filter(\.isSuggestionOnly)
        if !list.isEmpty {
            Card(title: "权限建议", systemImage: "lightbulb",
                 subtitle: "这些访问没有被阻止（可能由系统基础规则或旧规则放行），只是当前权限没有明确包含它们。加入权限后会明确列出；不处理也不会改变现在的行为。") {
                VStack(spacing: 2) {
                    ForEach(list, id: \.self) { item in
                        PendingRow(item: item, selected: binding(item), templates: model.templates) {
                            Button("不再提示") { model.decide(item, .dismissed, for: profileID) }
                            Button("加入权限…") { model.acceptAll([item], for: profileID) }
                        }
                    }
                }
            }
        }
    }

    private func binding(_ item: PendingItem) -> Binding<Bool> {
        Binding(get: { selected.contains(item.suggestion) },
                set: { if $0 { selected.insert(item.suggestion) } else { selected.remove(item.suggestion) } })
    }

    // MARK: Handled

    @ViewBuilder private var archived: some View {
        if let archived = log?.archived, !archived.isEmpty {
            Card(title: "已处理", systemImage: "archivebox",
                 subtitle: "保持阻止和不再提示的记录。它们没有改变任何权限；已经允许的访问要收回，请在“权限”中撤回。") {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(archived.enumerated()), id: \.offset) { _, entry in
                        HStack(alignment: .firstTextBaseline) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.decision.suggestion.title).lineLimit(2).truncationMode(.middle)
                                Text(describe(entry)).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("重新提示") { model.decide(entry.decision.suggestion, .reopened, for: profileID) }.controlSize(.small)
                        }
                    }
                }
            }
        }
    }

    private func describe(_ entry: ArchivedItem) -> String {
        let action = entry.decision.decision == .keepBlocked ? "保持阻止" : "不再提示"
        var text = "\(action) · \(entry.decision.at.formatted(date: .abbreviated, time: .shortened))"
        if let current = entry.current, current.evidence > entry.decision.evidence {
            text += " · 之后又出现 \(current.evidence - entry.decision.evidence) 次"
        }
        return text
    }

    @ViewBuilder private var history: some View {
        if let history = log?.history, !history.isEmpty {
            Card(title: "处理记录", systemImage: "clock.arrow.circlepath",
                 subtitle: "权限变更、启动和停止、保护确认，以及你对每项活动的处理。") {
                VStack(alignment: .leading, spacing: 8) {
                    if !(model.status(for: profileID)?.untrackedInstances.isEmpty ?? true) {
                        Text("跟踪记录有缺口时，历史中的“已退出”只确认当时已跟踪的进程，不能证明遗漏的子进程也已退出。")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ForEach(Array(history.prefix(50).enumerated()), id: \.offset) { _, entry in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: entry.kind.symbol).foregroundStyle(entry.kind.tint).frame(width: 16)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(entry.title)
                                ForEach(entry.details, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                            }
                            Spacer()
                            Text(entry.at.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private var recent: some View {
        if let recent = log?.recent, !recent.isEmpty {
            let canAllowSystemDNS = model.profile(profileID)?.network.systemDNS != .allowed
            Card(title: "最近的访问记录", systemImage: "list.bullet.rectangle") {
                DisclosureGroup(isExpanded: $showRecent) {
                    VStack(alignment: .leading, spacing: 4) {
                        if recent.contains(where: \.isNetwork) {
                            Text("网络记录显示系统提供的目标和端口。系统未提供的域名、完整 URL 或协议会明确标注；端口号不能单独证明访问了哪个网站。")
                                .font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true).padding(.bottom, 6)
                        }
                        ForEach(Array(recent.prefix(200).enumerated()), id: \.offset) { _, observation in
                            RecentAccessRow(observation: observation, expanded: Binding(
                                get: { expandedAccess == observation },
                                set: { expandedAccess = $0 ? observation : nil }
                            ), allowSystemDNS: observation.denied && observation.isSystemDNS
                                && canAllowSystemDNS ? {
                                    model.acceptAll([PendingItem(suggestion: .systemDNS, sensitive: false,
                                                                 evidence: observation.count, samples: [SystemDNS.socketPath],
                                                                 denied: observation.count, firstSeen: observation.at, lastSeen: observation.at)],
                                                    for: profileID)
                                } : nil)
                        }
                    }
                    .padding(.top, 6)
                } label: {
                    Text("本次 Helper 运行期间记录的 \(recent.count) 条访问。日常正常活动只在这里列出。").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct RecentAccessRow: View {
    let observation: Observation
    @Binding var expanded: Bool
    var allowSystemDNS: (() -> Void)?

    private var endpoint: NetworkEndpoint? { observation.networkEndpoint }
    private var isSocket: Bool {
        if case .unixSocket = observation.access { return true }
        return false
    }
    private var isSignal: Bool {
        if case .signal = observation.access { return true }
        return false
    }
    private var port: String { observation.networkPort.map(String.init) ?? (isSocket ? "不适用（本机套接字）" : "系统未提供") }
    private var process: String {
        let name = observation.processName ?? "名称未记录"
        return observation.pid.map { "\(name)（PID \($0)）" } ?? name
    }
    private var eventTime: String { observation.at?.formatted(date: .omitted, time: .standard) ?? "时间未记录" }
    private var eventIdentifier: String {
        "\(observation.at?.timeIntervalSince1970 ?? 0)-\(observation.pid ?? 0)-\(observation.hashValue)"
    }
    private var fields: [(String, String)] {
        [
            ("目标", endpoint?.host ?? endpoint?.socketPath ?? "系统未提供"),
            ("端口", port),
            ("传输协议", endpoint?.transport ?? "系统未提供，不能仅凭端口判断"),
            ("域名", isSocket ? "不适用（本机套接字）" : endpoint?.hostname ?? "系统未提供"),
            ("完整 URL", isSocket ? "不适用（本机套接字）" : endpoint?.url ?? "系统未提供；IP 和端口无法还原完整 URL"),
            ("发起程序", process),
            ("原始目标", observation.networkTarget ?? "旧记录未保存目标，无法补回"),
        ]
    }
    private var copyText: String {
        ([observation.denied ? "阻止" : "允许", observation.summary]
         + fields.map { "\($0.0)：\($0.1)" }
         + (observation.at.map { ["时间：\($0.formatted(date: .numeric, time: .standard))"] } ?? [])).joined(separator: "\n")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(observation.denied ? "阻止" : "允许").font(.caption.weight(.medium))
                    .foregroundStyle(observation.denied ? Color.red : Color.secondary).frame(width: 32, alignment: .leading)
                VStack(alignment: .leading, spacing: 3) {
                    Text(observation.summary).font(.system(.caption, design: .monospaced))
                        .lineLimit(observation.isNetwork || isSignal ? nil : 1).truncationMode(.middle)
                        .fixedSize(horizontal: false, vertical: observation.isNetwork || isSignal)
                        .textSelection(.enabled)
                    if isSignal {
                        Text("任务结束或取消时的进程控制；拒绝可能使任务停在等待退出状态。")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        Text(process).font(.caption).foregroundStyle(.secondary)
                    }
                    if observation.isNetwork {
                        Text(observation.isSystemDNS ? "\(SystemDNS.title) · 本机服务"
                             : isSocket ? "本机进程间通信 · 不使用网络端口"
                             : "端口：\(port) · 传输协议：\(endpoint?.transport ?? "未记录") · URL：\(endpoint?.url == nil ? "系统未提供" : "见详情")")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if observation.processName != nil || observation.pid != nil {
                            Text(process).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Spacer(minLength: 4)
                if observation.isNetwork {
                    if let allowSystemDNS {
                        Button("允许系统 DNS…", action: allowSystemDNS).controlSize(.small)
                            .accessibilityLabel("允许系统域名解析与服务发现，仅连接 \(SystemDNS.socketPath)")
                            .accessibilityIdentifier("system-dns-allow-\(eventIdentifier)")
                    }
                    Button(expanded ? "收起" : "详情") { expanded.toggle() }.buttonStyle(.borderless).controlSize(.small)
                        .accessibilityLabel("\(expanded ? "收起" : "查看")连接详情：\(eventTime)，\(observation.summary)，\(process)，端口 \(port)")
                        .accessibilityIdentifier("network-details-\(eventIdentifier)")
                }
                if let at = observation.at {
                    Text(at.formatted(date: .omitted, time: .standard)).font(.caption).foregroundStyle(.secondary)
                }
            }
            if observation.isNetwork && expanded {
                VStack(alignment: .leading, spacing: 5) {
                    if observation.isSystemDNS {
                        Text(SystemDNS.detail).font(.caption)
                        Text("这条记录只显示连接了系统服务，未记录具体查询的域名。").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(fields.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 10) {
                            Text(fields[index].0).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
                            Text(fields[index].1).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }.font(.caption)
                    }
                    Button("复制连接详情") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(copyText, forType: .string)
                    }.controlSize(.small).padding(.top, 3)
                        .accessibilityLabel("复制连接详情：\(eventTime)，\(observation.summary)，\(process)，端口 \(port)")
                        .accessibilityIdentifier("network-copy-\(eventIdentifier)")
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
                .padding(.leading, 40)
            }
        }
        .padding(.vertical, observation.isNetwork ? 5 : 0)
    }
}

private struct PendingRow<Actions: View>: View {
    let item: PendingItem
    @Binding var selected: Bool
    let templates: [Template]
    @ViewBuilder let actions: () -> Actions
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                SwiftUI.Toggle("", isOn: $selected).toggleStyle(.checkbox).labelsHidden()
                IconTile(systemImage: item.suggestion.symbol, tint: item.sensitive ? .red : .accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.suggestion.title).lineLimit(2).truncationMode(.middle)
                    HStack(spacing: 6) {
                        Text(evidence).font(.caption).foregroundStyle(.secondary)
                        if item.sensitive { Chip(text: "包含敏感位置", systemImage: "exclamationmark.triangle.fill", tint: .red) }
                    }
                }
                Spacer(minLength: 8)
                Button(expanded ? "收起" : "详情") { expanded.toggle() }.buttonStyle(.borderless).controlSize(.small)
                actions().controlSize(.small)
            }
            if expanded {
                VStack(alignment: .leading, spacing: 3) {
                    Text("允许后实际新增：").font(.caption.weight(.medium))
                    ForEach(scope, id: \.self) { Text("  " + $0).font(.system(.caption, design: .monospaced)) }
                    if !item.samples.isEmpty {
                        Text(sampleHeading).font(.caption.weight(.medium)).padding(.top, 2)
                        ForEach(item.samples, id: \.self) { Text("  " + $0).font(.system(.caption, design: .monospaced)) }
                    }
                    Text("允许不会补做已经失败的操作；保存并重启程序后，请重新尝试原来的操作。").font(.caption).foregroundStyle(.secondary).padding(.top, 2)
                }
                .padding(.leading, 64)
                .textSelection(.enabled)
            }
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
    }

    private var evidence: String {
        var text = item.wasBlocked ? "被阻止 \(item.denied) 次" : item.refusalKnown ? "成功 \(item.evidence) 次" : "出现 \(item.evidence) 次"
        if item.wasBlocked && item.evidence > item.denied { text += "，成功 \(item.evidence - item.denied) 次" }
        if let last = item.lastSeen { text += " · 最近 \(last.formatted(date: .omitted, time: .shortened))" }
        return text
    }

    private var sampleHeading: String {
        switch item.suggestion {
        case .outboundTCP, .loopbackPort, .listen: return "观测到的连接目标（不代表授权仅限这些目标）："
        case .processControl: return "被拒绝的进程控制目标（系统原文）："
        default: return "涉及的位置："
        }
    }

    /// Everything accepting the item would grant, so a harmless-looking trigger cannot hide a broad group.
    private var scope: [String] {
        switch item.suggestion {
        case let .template(id):
            guard let template = templates.first(where: { $0.id == id }) else { return [item.suggestion.title] }
            return template.files.map { "\($0.access == .readWrite ? "读写" : "只读")\($0.kind == .directory ? "目录" : "文件") \($0.path)\($0.readsSecrets ? "（含凭证）" : "")" }
                + template.exec.map { "运行 \($0.path)" } + template.loopbackPorts.map { "连接本机端口 \($0)" }
        case .systemDNS:
            return ["仅连接本机服务 \(SystemDNS.socketPath)", SystemDNS.detail]
        case .processControl:
            return [ProcessControl.detail]
        default:
            return [item.suggestion.title]
        }
    }
}

extension HistoryKind {
    var symbol: String {
        switch self {
        case .permissionChange: return "slider.horizontal.3"
        case .decision: return "checkmark.bubble"
        case .started: return "play.circle"
        case .stopped: return "stop.circle"
        case .verified: return "checkmark.shield"
        case .verificationFailed: return "xmark.shield"
        }
    }

    var tint: Color {
        switch self {
        case .verificationFailed: return .red
        case .verified: return .green
        default: return .secondary
        }
    }
}
#endif
