#if os(macOS)
import AppKit
import Foundation
import GuardCore
import GuardPlatform

enum AccessLogTimeRange: String, CaseIterable, Identifiable {
    case day = "最近 24 小时", week = "最近 7 天", all = "全部保留记录", custom = "自选时间"
    var id: String { rawValue }
}

enum AccessLogOutcomeFilter: String, CaseIterable, Identifiable {
    case all = "全部结果", allowed = "允许", denied = "阻止", unknown = "未确认"
    var id: String { rawValue }
    var outcome: AccessLogOutcome? {
        switch self {
        case .all: return nil
        case .allowed: return .allowedObserved
        case .denied: return .denied
        case .unknown: return .unknown
        }
    }
}

/// Only one disk page is retained. Blocking XPC and export I/O stay off the UI thread.
@MainActor
final class AccessLogHistoryModel: ObservableObject {
    let profileID: String
    @Published private(set) var status: AccessLogStatus?
    @Published private(set) var paging: AccessLogPagingState
    @Published private(set) var loading = false
    @Published private(set) var changingSetting = false
    @Published private(set) var clearing = false
    @Published private(set) var exporting = false
    @Published private(set) var exportedCount = 0
    @Published private(set) var error: String?
    @Published private(set) var requiresRefresh = false
    @Published private(set) var notice: String?
    @Published private(set) var newRecordsAvailable = false
    @Published var timeRange: AccessLogTimeRange = .day
    @Published var outcome: AccessLogOutcomeFilter = .all
    @Published var from = Date().addingTimeInterval(-24 * 60 * 60)
    @Published var through = Date()

    private var queryTicket = UUID()
    private var exportTask: Task<Void, Never>?
    private var clearCutoff: AccessLogClearResult?

    init(profileID: String) {
        self.profileID = profileID
        paging = AccessLogPagingState(query: .init(profileID: profileID,
                                                   from: Date().addingTimeInterval(-24 * 60 * 60),
                                                   through: Date()))
    }

    var working: Bool { loading || changingSetting || clearing }
    var canRead: Bool { status.map { !$0.writerID.isEmpty } ?? false }
    var hasUnappliedRange: Bool {
        timeRange == .custom && (paging.query.from != from || paging.query.through != through)
    }

    func watch() async {
        await refresh()
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard !Task.isCancelled else { return }
            await poll()
        }
    }

    func suspend() {
        queryTicket = UUID()
        loading = false
        cancelExport()
    }

    func refresh() async {
        guard !clearing, !changingSetting else { return }
        if timeRange == .custom && from > through {
            error = "开始时间要早于结束时间。"
            return
        }
        let ticket = UUID()
        queryTicket = ticket
        loading = true
        requiresRefresh = false
        error = nil
        newRecordsAvailable = false
        paging.reset(query: makeQuery(now: Date()))
        do {
            let result = try await request(.accessLogStatus(profileID: profileID))
            guard valid(ticket) else { return }
            guard case let .accessLogStatus(snapshot) = result else { throw responseError(result) }
            status = snapshot
            guard !snapshot.writerID.isEmpty else {
                loading = false
                error = "访问日志保存服务尚未就绪，请查看下方保存状态。"
                return
            }
            await loadPage(ticket: ticket)
        } catch {
            guard valid(ticket) else { return }
            loading = false
            self.error = describe(error)
        }
    }

    func nextPage() async {
        guard !working, !requiresRefresh, paging.advance() else { return }
        await loadPage()
    }

    func previousPage() async {
        guard !working, !requiresRefresh, paging.goBack() else { return }
        await loadPage()
    }

    func setEnabled(_ enabled: Bool) async {
        guard !working, status?.loggingEnabled != enabled else { return }
        changingSetting = true
        queryTicket = UUID()
        error = nil
        var failure: String?
        do {
            let response = try await request(.setAccessLogEnabled(profileID: profileID, enabled: enabled))
            guard !Task.isCancelled else { changingSetting = false; return }
            guard case .ok = response else { throw responseError(response) }
            notice = enabled ? "已开启访问日志，从现在收到的事件开始保存。" : "已暂停保存新访问；已有日志仍按保留期限和容量清理。"
        } catch { failure = describe(error) }
        changingSetting = false
        await refresh()
        if let failure { error = failure }
    }

    func clear(using app: AppModel) async {
        guard !working, !exporting, let snapshot = status, snapshot.isReady else { return }
        let generation = snapshot.generation
        guard await app.askConfirmation("清空 \(profileID) 的访问日志", [
            "删除这个程序已保存的访问明细及清空前仍在排队的记录",
            "清空后发生的新访问会按当前日志开关继续保存",
            "已导出的文件由你自行管理"
        ]) else { return }
        guard !working else { return }
        clearing = true
        error = nil
        queryTicket = UUID()
        do {
            let response = try await request(.clearAccessLog(profileID: profileID, expectedGeneration: generation))
            guard case let .accessLogCleared(id, result) = response, id == profileID else {
                throw responseError(response)
            }
            clearCutoff = result
            requiresRefresh = false
            if var activity = app.activity[profileID] {
                activity.recent = afterClear(activity.recent)
                app.activity[profileID] = activity
            }
            paging.reset(query: makeQuery(now: Date()))
            notice = "已清空访问日志，释放 \(Self.bytes(result.removedBytes))。"
            app.loadActivity(profileID)
        } catch {
            self.error = describe(error)
            requiresRefresh = true
        }
        clearing = false
        if !requiresRefresh { await refresh() }
    }

    func afterClear(_ recent: [Observation]) -> [Observation] {
        guard let cutoff = clearCutoff else { return recent }
        return recent.filter {
            guard let writer = $0.accessLogWriterID, let sequence = $0.accessLogSequence else { return false }
            if writer == cutoff.writerID { return sequence > cutoff.cutoffSequence }
            return writer == status?.writerID && status?.writerID != cutoff.writerID
        }
    }

    func export() {
        guard !exporting, !working, !requiresRefresh, !hasUnappliedRange, canRead,
              let snapshot = status else { return }
        let query = paging.query
        let panel = NSSavePanel()
        panel.title = "导出所选范围的访问日志"
        panel.nameFieldStringValue = "AgentGuard-\(profileID)-访问日志.jsonl"
        panel.canCreateDirectories = true
        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in self?.beginExport(query: query, status: snapshot, to: url) }
        }
    }

    func cancelExport() { exportTask?.cancel() }

    private func beginExport(query: AccessLogQuery, status: AccessLogStatus, to url: URL) {
        guard !exporting else { return }
        exporting = true
        exportedCount = 0
        error = nil
        notice = nil
        exportTask = Task {
            let worker = Task.detached {
                try AccessLogExporter.export(query: query, status: status, to: url,
                    send: { try HelperClient().send($0, timeout: 20) },
                    cancelled: { Task<Never, Never>.isCancelled },
                    progress: { [weak self] count in Task { @MainActor in self?.exportedCount = count } })
            }
            do {
                let count = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
                notice = "已导出 \(count) 条记录：\(url.lastPathComponent)。导出文件由你自行保留和清理。"
            } catch is CancellationError {
                notice = "已取消导出。"
            } catch AccessLogExportError.cancelled {
                notice = "已取消导出。"
            } catch {
                self.error = "导出未完成：" + describe(error)
            }
            exporting = false
            exportTask = nil
        }
    }

    private func poll() async {
        guard !working else { return }
        let ticket = queryTicket
        do {
            let response = try await request(.accessLogStatus(profileID: profileID))
            guard valid(ticket) else { return }
            guard case let .accessLogStatus(snapshot) = response else { throw responseError(response) }
            let changed = snapshot.writerID != status?.writerID
                || snapshot.writtenThroughSequence != status?.writtenThroughSequence
                || snapshot.generation != status?.generation
            status = snapshot
            if changed && !requiresRefresh {
                if paging.isFirstPage && !hasUnappliedRange { await refresh() }
                else { newRecordsAvailable = true }
            }
        } catch {
            guard valid(ticket) else { return }
            self.error = describe(error)
        }
    }

    private func loadPage(ticket suppliedTicket: UUID? = nil) async {
        let ticket = suppliedTicket ?? UUID()
        queryTicket = ticket
        loading = true
        error = nil
        let query = paging.query
        do {
            let response = try await request(.queryAccessLog(query))
            guard valid(ticket) else { return }
            guard case let .accessLogPage(page) = response else { throw responseError(response) }
            try paging.accept(page)
        } catch {
            guard valid(ticket) else { return }
            self.error = describe(error)
            requiresRefresh = true
        }
        if valid(ticket) { loading = false }
    }

    private func makeQuery(now: Date) -> AccessLogQuery {
        let start: Date?
        let end: Date
        switch timeRange {
        case .day: start = now.addingTimeInterval(-24 * 60 * 60); end = now
        case .week: start = now.addingTimeInterval(-7 * 24 * 60 * 60); end = now
        case .all: start = nil; end = now
        case .custom: start = from; end = through
        }
        return .init(profileID: profileID, from: start, through: end, outcome: outcome.outcome, limit: 200)
    }

    private func valid(_ ticket: UUID) -> Bool { !Task.isCancelled && queryTicket == ticket }

    private func request(_ request: HelperRequest) async throws -> HelperResponse {
        try await Task.detached { try HelperClient().send(request, timeout: 20) }.value
    }

    private func responseError(_ response: HelperResponse) -> Error {
        if case let .failure(code) = response {
            return NSError(domain: "AgentGuard.AccessLog", code: 1,
                           userInfo: [NSLocalizedDescriptionKey: AccessLogPresentation.errorMessage(code)])
        }
        return NSError(domain: "AgentGuard.AccessLog", code: 2,
                       userInfo: [NSLocalizedDescriptionKey: "后台服务返回了无法识别的日志响应，请检查版本。"])
    }

    private func describe(_ error: Error) -> String {
        if let error = error as? AccessLogError {
            switch error {
            case .historyExpired: return AccessLogPresentation.errorMessage("history_expired")
            case .invalidCursor: return AccessLogPresentation.errorMessage("cursor_invalid")
            default: break
            }
        }
        return error.localizedDescription
    }

    static func bytes(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }
}
#endif
