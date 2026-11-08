#if os(macOS)
import AppKit
import GuardCore
import SwiftUI

struct AccessLogHistoryView: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var history: AccessLogHistoryModel
    @State private var expanded = true
    @State private var expandedID: String?
    let profileID: String

    init(profileID: String) {
        self.profileID = profileID
        _history = StateObject(wrappedValue: AccessLogHistoryModel(profileID: profileID))
    }

    private var supported: Bool { app.helperReachable && (app.report?.helperProtocol ?? 0) >= 9 }
    private var recent: [Observation] { history.afterClear(app.activity[profileID]?.recent ?? []) }
    private var entries: [AccessLogListItem] {
        AccessLogPresentation.merge(records: history.paging.page?.records ?? [],
            recent: history.paging.isFirstPage ? recent : [], status: history.status, query: history.paging.query)
    }

    var body: some View {
        Card(title: "访问记录", systemImage: "list.bullet.rectangle",
             subtitle: "逐条保存已采集的允许和阻止访问。默认保留 7 天，每个程序最多 256 MiB，所有程序合计最多 512 MiB；容量不足时会提前清理旧记录。") {
            if !supported {
                Notice(kind: .warning, text: app.helperReachable
                    ? "后台服务需要更新才能保存和查询历史访问。请在设置中点“检查并修复”。下方仅显示本次运行的临时记录。"
                    : "暂时无法连接后台服务。下方仅显示已经读取的临时记录。")
                legacyRows
            } else {
                controls
                if let status = history.status { storageStatus(status) }
                if let error = history.error {
                    Notice(kind: .error, text: error, actionTitle: "刷新") { Task { await history.refresh() } }
                }
                if let notice = history.notice { Notice(kind: .info, text: notice) }
                if history.newRecordsAvailable {
                    Notice(kind: .info, text: "有新的访问或历史保留范围已变化。当前页保持原查询位置。", actionTitle: "重新查询") {
                        Task { await history.refresh() }
                    }
                }
                DisclosureGroup(isExpanded: $expanded) {
                    records
                } label: {
                    Text("本页 \(entries.count) 条 · 按接收时间倒序")
                        .font(.callout).foregroundStyle(.secondary)
                }
                pagination
            }
        }
        .task(id: supported) {
            if supported { await history.watch() }
        }
        .onDisappear { history.suspend() }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SwiftUI.Toggle("保存访问日志", isOn: Binding(
                    get: { history.status?.loggingEnabled ?? false },
                    set: { enabled in Task { await history.setEnabled(enabled) } }
                ))
                .toggleStyle(.switch)
                .disabled(history.status == nil || history.working)
                .help("独立控制访问日志，不改变这个程序的权限或保护方式")
                Spacer()
                if history.exporting {
                    ProgressView().controlSize(.small)
                    Text("已导出 \(history.exportedCount) 条").font(.caption).foregroundStyle(.secondary)
                    Button("取消导出") { history.cancelExport() }.controlSize(.small)
                }
            }
            HStack(spacing: 10) {
                Picker("时间", selection: $history.timeRange) {
                    ForEach(AccessLogTimeRange.allCases) { Text($0.rawValue).tag($0) }
                }.frame(maxWidth: 220)
                Picker("结果", selection: $history.outcome) {
                    ForEach(AccessLogOutcomeFilter.allCases) { Text($0.rawValue).tag($0) }
                }.frame(maxWidth: 160)
                Spacer(minLength: 0)
                Button("刷新") { Task { await history.refresh() } }.disabled(history.working)
            }
            .disabled(history.clearing)
            .onChange(of: history.timeRange) { _, _ in Task { await history.refresh() } }
            .onChange(of: history.outcome) { _, _ in Task { await history.refresh() } }
            if history.timeRange == .custom {
                HStack {
                    DatePicker("从", selection: $history.from).datePickerStyle(.field)
                    DatePicker("到", selection: $history.through).datePickerStyle(.field)
                    Button("查询") { Task { await history.refresh() } }.disabled(history.working)
                }.disabled(history.clearing)
                if history.hasUnappliedRange {
                    Text("时间范围已调整，请点“查询”后查看或导出。").font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                Button("导出所选范围…") { history.export() }
                    .disabled(!history.canRead || history.working || history.exporting || history.requiresRefresh || history.hasUnappliedRange)
                Button("清空这个程序的日志…", role: .destructive) { Task { await history.clear(using: app) } }
                    .disabled(history.status?.isReady != true || history.working || history.exporting)
                Spacer()
                if history.loading || history.clearing || history.changingSetting {
                    ProgressView().controlSize(.small)
                    Text(history.clearing ? "正在清空…" : history.changingSetting ? "正在保存设置…" : "正在读取…")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func storageStatus(_ status: AccessLogStatus) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(storageTitle(status)) · 已占 \(AccessLogHistoryModel.bytes(status.bytes)) · 待写 \(status.queuedCount) 条（\(AccessLogHistoryModel.bytes(status.queuedBytes))）")
                .font(.callout)
            Text("最早保留：\(date(status.earliestRetainedAt)) · 最近写入：\(date(status.lastWrittenAt)) · 最近同步：\(date(status.lastSyncedAt))")
                .font(.caption).foregroundStyle(.secondary)
            Text(AccessLogPresentation.coverageText(status.coverage))
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let cleanup = status.lastCleanupSummary {
                Text("本次后台运行最近清理：\(date(cleanup.occurredAt)) · \(cleanupReason(cleanup.reason)) · 移除 \(cleanup.deletedSegments) 段，释放 \(AccessLogHistoryModel.bytes(cleanup.releasedBytes))")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if status.droppedCount > 0 || status.knownGapCount > 0 {
                Text("记录有缺口：本次后台运行保存时丢失 \(status.droppedCount) 条；保留日志含采集缺口 \(status.sourceGapCount) 份、保存缺口 \(status.storageGapCount) 份。无法确定的遗漏数量会单独标注。")
                    .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            if status.unsupportedSegments > 0 || status.quarantinedSegments > 0 {
                Text("有 \(status.unsupportedSegments) 段格式暂不支持、\(status.quarantinedSegments) 段损坏记录已隔离；它们仍计入占用，当前列表可能不完整。")
                    .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            ForEach(Array(status.errors.prefix(6).enumerated()), id: \.offset) { _, error in
                Text("保存状态：\(error)").font(.caption).foregroundStyle(.red)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            Text("“允许”表示系统事件观察到访问成功。系统未提供的域名、URL、端口或进程身份不能从现有记录补造。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var records: some View {
        LazyVStack(alignment: .leading, spacing: 7) {
            if entries.isEmpty && !history.loading {
                Text(history.paging.page?.incomplete == true
                    ? "本批扫描暂未找到符合条件的记录，点“继续查找”查看后续历史。"
                    : "当前范围没有已读取的访问记录。")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(entries) { item in
                if let record = item.record {
                    SavedAccessLogRow(record: record, persistence: item.persistence, expanded: expansion(item.id))
                } else if let observation = item.observation {
                    VStack(alignment: .leading, spacing: 2) {
                        RecentAccessRow(observation: observation, expanded: expansion(item.id),
                                        allowSystemDNS: dnsAction(observation))
                        Text(item.persistence).font(.caption2).foregroundStyle(.secondary).padding(.leading, 40)
                    }
                }
            }
        }.padding(.top, 8)
    }

    private var pagination: some View {
        HStack {
            Button("上一页") { Task { await history.previousPage() } }
                .disabled(!history.paging.canGoBack || history.working || history.requiresRefresh)
            Text("第 \(history.paging.pageNumber) 页").font(.caption).foregroundStyle(.secondary)
            Button(history.paging.page?.incomplete == true ? "继续查找" : "下一页") { Task { await history.nextPage() } }
                .disabled(!history.paging.canAdvance || history.working || history.requiresRefresh)
            Spacer()
            if let through = history.paging.query.through {
                Text("查询截至 \(date(through))").font(.caption).foregroundStyle(.secondary)
            }
        }.controlSize(.small)
    }

    private var legacyRows: some View {
        LazyVStack(alignment: .leading, spacing: 5) {
            ForEach(Array(recent.prefix(200).enumerated()), id: \.offset) { index, observation in
                RecentAccessRow(observation: observation, expanded: expansion("legacy-\(index)"),
                                allowSystemDNS: dnsAction(observation))
            }
        }
    }

    private func expansion(_ id: String) -> Binding<Bool> {
        Binding(get: { expandedID == id }, set: { expandedID = $0 ? id : nil })
    }

    private func dnsAction(_ observation: Observation) -> (() -> Void)? {
        guard observation.denied, observation.isSystemDNS,
              app.profile(profileID)?.network.systemDNS != .allowed else { return nil }
        return {
            app.acceptAll([PendingItem(suggestion: .systemDNS, sensitive: false, evidence: observation.count,
                samples: [SystemDNS.socketPath], denied: observation.count,
                firstSeen: observation.at, lastSeen: observation.at)], for: profileID)
        }
    }

    private func date(_ value: Date?) -> String {
        value?.formatted(date: .abbreviated, time: .standard) ?? "暂无"
    }

    private func storageTitle(_ status: AccessLogStatus) -> String {
        if !status.isReady { return "保存服务未就绪" }
        if !status.errors.isEmpty { return "保存存在异常" }
        return status.loggingEnabled == true ? "已开启保存" : "已暂停保存新访问"
    }

    private func cleanupReason(_ reason: String) -> String {
        switch reason {
        case "retention": return "按保留期限检查"
        case "capacity": return "达到日志容量上限"
        case "low_disk": return "磁盘剩余空间不足"
        default: return reason
        }
    }
}

private struct SavedAccessLogRow: View {
    let record: AccessLogRecord
    let persistence: String
    @Binding var expanded: Bool

    private var title: String {
        switch record.kind {
        case .access:
            let operation = record.operation == "rename"
                ? (record.sourceSubsequence == 0 ? "重命名来源" : record.sourceSubsequence == 1 ? "重命名目标" : "重命名")
                : AccessLogPresentation.operationTitle(record.operation)
            return "\(operation)  \(record.target ?? "系统未提供目标")"
        case .gap: return gapTitle
        case .storageStatus: return "保存状态：\(record.evidence ?? record.operation)"
        }
    }

    private var gapTitle: String {
        switch record.gap?.reason {
        case "invalidWire": return "采集消息格式无法识别，部分活动可能未记录"
        case "unparseableEvent": return "系统活动格式无法识别，部分活动可能未记录"
        case "queueOverflow", "transportOverflow": return "采集消息积压，部分活动可能未记录"
        case "oversizedLine": return "采集消息过长，部分活动可能未记录"
        case "disconnected": return "采集连接中断，期间活动可能未记录"
        case "sourceRestarted": return "采集来源已重启，切换期间可能漏记"
        case "sourceSequenceGap": return "采集消息不连续，部分活动可能未记录"
        case "collector_health_changed": return "采集状态异常，部分活动可能未记录"
        default: return "访问记录存在缺口，部分活动可能未记录"
        }
    }

    private var subtitle: String {
        let truncation = record.truncatedFields.isEmpty ? "" : " · 含截断字段"
        if record.kind == .access {
            return "\(record.processName ?? "程序未记录")\(record.pid.map { "（PID \($0)）" } ?? "") · \(persistence)\(truncation)"
        }
        let category = record.kind == .gap ? "采集状态提示" : "保存状态提示"
        return "\(category) · 此提示\(persistence)\(truncation)"
    }

    private var fields: [(String, String)] {
        var fields: [(String, String)] = []
        func add(_ title: String, _ value: String) { fields.append((title, value)) }
        add("接收时间", record.receivedAt.formatted(date: .numeric, time: .standard))
        add("来源时间", record.sourceAt?.formatted(date: .numeric, time: .standard) ?? "未记录")
        if record.kind == .access {
            add("程序", record.processName ?? "系统未提供")
            add("进程", record.pid.map { "PID \($0)" } ?? "系统未提供")
            add("创建身份", record.pidversion.map { "pidversion \($0)" } ?? "系统未提供")
            add("可执行文件", record.executablePath ?? "系统未提供")
        }
        add("原始动作", record.operation)
        if record.operation == "open" {
            add("打开方式", record.openFlags.map { String(format: "fflag 0x%08x", $0) } ?? "来源未提供有效标志，未推断正文读取")
            add("读取证据", "这里只观察到文件打开；不能证明已读取正文。")
        }
        add("目标", record.target ?? "系统未提供")
        add("原始目标", record.rawTarget ?? "系统未提供")
        add("判定依据", record.evidence ?? "来源未提供")
        add("权限版本", record.profileRevision.map { "修订 \($0)" } ?? "未记录")
        add("运行身份", record.runUUID ?? "未记录")
        add("实例来源", record.instanceOrigin ?? "未记录")
        add("系统启动", record.bootID ?? "未记录")
        add("采集来源", record.source.rawValue)
        add("来源序号", record.sourceSequence.map { String($0) } ?? "系统未提供")
        add("来源事件", record.sourceEventID ?? "系统未提供")
        add("来源子序号", record.sourceSubsequence.map { String($0) } ?? "不适用")
        add("事件身份", record.eventID)
        add("写入身份", "\(record.writerID) / \(record.sequence)")
        add("采集覆盖", AccessLogPresentation.coverageText(record.coverage))
        add("进程归属", attribution)
        if let endpoint = record.endpointFields {
            let parsed = NetworkEndpoint(record.rawTarget ?? record.target ?? "")
            let port = endpoint.port.map { String($0) } ?? "系统未提供"
            add("连接目标", endpoint.socketPath ?? endpoint.host ?? "系统未提供")
            add("端口", endpoint.socketPath != nil ? "不适用（本机套接字）" : port)
            add("协议", endpoint.transport ?? parsed.transport ?? "系统未提供")
            add("域名", endpoint.socketPath != nil ? "不适用（本机套接字）" : parsed.hostname ?? "系统未提供")
            add("完整 URL", endpoint.socketPath != nil ? "不适用（本机套接字）" : parsed.url ?? "系统未提供；IP 和端口无法还原完整 URL")
        }
        if let gap = record.gap {
            fields.append(("原始缺口原因", gap.reason))
            fields.append(("缺失数量", gap.droppedCount.map { String($0) } ?? "无法确定"))
        }
        if !record.truncatedFields.isEmpty {
            fields.append(("截断说明", record.truncatedFields.sorted { $0.key < $1.key }
                .map { "\($0.key)：原始 \($0.value) 字节" }.joined(separator: "；")))
        }
        return fields
    }

    private var attribution: String {
        switch record.attributionStatus {
        case .confirmed: return "已确认"
        case .pidOnly: return "来源仅提供 PID，未提供完整创建身份"
        case .incomplete: return "进程归属存在缺口"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(record.kind == .access ? AccessLogPresentation.outcomeTitle(record.outcome) : record.kind == .gap ? "缺口" : "状态")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(record.outcome == .denied ? Color.red : record.kind == .access ? Color.secondary : Color.orange)
                    .frame(width: 40, alignment: .leading)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.system(.caption, design: .monospaced))
                        .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                    Text(subtitle)
                        .font(.caption2).foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Button(expanded ? "收起" : "详情") { expanded.toggle() }.buttonStyle(.borderless).controlSize(.small)
                    .accessibilityLabel("\(expanded ? "收起" : "查看")访问详情：\(title)")
                Text(record.receivedAt.formatted(date: .omitted, time: .standard))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if expanded {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(fields.indices, id: \.self) { index in
                        HStack(alignment: .top, spacing: 10) {
                            Text(fields[index].0).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
                            Text(fields[index].1).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }.font(.caption)
                    }
                    Button("复制访问详情") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(([title] + fields.map { "\($0.0)：\($0.1)" }).joined(separator: "\n"), forType: .string)
                    }.controlSize(.small)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
                .padding(.leading, 48)
            }
        }.padding(.vertical, 3)
    }
}
#endif
