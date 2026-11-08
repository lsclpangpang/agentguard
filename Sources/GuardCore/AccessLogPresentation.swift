import Foundation

/// A saved record or an as-yet unwritten event from the current Helper's fast cache.
public struct AccessLogListItem: Identifiable, Equatable, Sendable {
    public var id: String
    public var record: AccessLogRecord?
    public var observation: Observation?
    public var persistence: String
    public var at: Date? { record?.receivedAt ?? observation?.at }
}

/// Presentation rules preserve event identity and the distinction between observed and inferred facts.
public enum AccessLogPresentation {
    /// Combines a bounded disk page with unwritten cache entries without collapsing repeated accesses.
    public static func merge(records: [AccessLogRecord], recent: [Observation], status: AccessLogStatus?,
                             query: AccessLogQuery) -> [AccessLogListItem] {
        var seen = Set<String>()
        var items: [AccessLogListItem] = []
        for record in records where seen.insert(record.eventID).inserted {
            let pendingSync = record.writerID == status?.writerID
                && record.sequence > (status?.syncedThroughSequence ?? 0)
            items.append(.init(id: record.eventID, record: record, observation: nil,
                               persistence: pendingSync ? "已写入，待同步" : "已保存"))
        }
        for (index, observation) in recent.enumerated() {
            guard matches(observation, query: query) else { continue }
            let id = observation.eventID ?? "memory-\(observation.hashValue)-\(index)"
            guard !seen.contains(id) else { continue }
            let confirmedProgress = observation.accessLogDisposition == .queued
                && status?.errors.isEmpty == true && status?.droppedCount == 0
            if confirmedProgress, let sequence = observation.accessLogSequence, let writer = observation.accessLogWriterID,
               writer == status?.writerID, sequence <= (status?.writtenThroughSequence ?? 0) {
                continue
            }
            seen.insert(id)
            let persistence: String
            if observation.accessLogDisposition == .memoryOnly || observation.eventID == nil {
                persistence = "仅本次运行"
            } else if observation.accessLogDisposition == .rejected {
                persistence = "未保存"
            } else if observation.accessLogDisposition != .queued || !confirmedProgress
                        || observation.accessLogWriterID != status?.writerID {
                persistence = "保存结果待确认"
            } else {
                persistence = "保存中"
            }
            items.append(.init(id: id, record: nil, observation: observation, persistence: persistence))
        }
        return items.sorted {
            let lhs = $0.at ?? .distantPast, rhs = $1.at ?? .distantPast
            if lhs != rhs { return lhs > rhs }
            let leftSequence = $0.record?.sequence ?? $0.observation?.accessLogSequence ?? 0
            let rightSequence = $1.record?.sequence ?? $1.observation?.accessLogSequence ?? 0
            if leftSequence != rightSequence { return leftSequence > rightSequence }
            return $0.id < $1.id
        }
    }

    /// Unknown timestamps cannot be assumed to fall within a selected time range.
    private static func matches(_ observation: Observation, query: AccessLogQuery) -> Bool {
        if let from = query.from {
            guard let at = observation.at, at >= from else { return false }
        }
        if let through = query.through {
            guard let at = observation.at, at <= through else { return false }
        }
        if let outcome = query.outcome {
            guard outcome != .unknown, observation.denied == (outcome == .denied) else { return false }
        }
        return true
    }

    /// Describes actual source capability; missing information remains explicitly unconfirmed.
    public static func coverageText(_ coverage: AccessLogCoverage) -> String {
        let files = coverage.fileEventsSubscribed.map { $0 ? "文件访问：已订阅" : "文件访问：未订阅" } ?? "文件访问：待确认"
        let collector = coverage.collectorHealthy.map { $0 ? "采集器：正常" : "采集器：存在缺口" } ?? "采集器：待确认"
        let attribution = coverage.attributionComplete.map { $0 ? "进程归属：已确认" : "进程归属存在缺口" } ?? "进程归属：待确认"
        let network = coverage.successfulNetworkCovered ? "成功的网络连接：有采集来源" : "成功的网络连接暂未采集"
        return [files, collector, attribution, network].joined(separator: "；")
    }

    /// Human-readable results do not promote unknown outcomes into successful accesses.
    public static func outcomeTitle(_ outcome: AccessLogOutcome) -> String {
        switch outcome {
        case .allowedObserved: return "允许"
        case .denied: return "阻止"
        case .unknown: return "未确认"
        }
    }

    /// Keeps raw operation names available when no reliable friendly category exists.
    public static func operationTitle(_ operation: String) -> String {
        switch operation {
        case "read", "open_read", "file-read-data": return "读取"
        case "write", "open_write", "file-write-data": return "写入"
        case "exec", "process-exec": return "运行"
        case "open": return "打开"
        case "close": return "关闭"
        case "create": return "创建"
        case "unlink": return "删除"
        case "rename_source": return "重命名来源"
        case "rename_destination": return "重命名目标"
        case "rename": return "重命名"
        case "fork": return "创建子进程"
        case "exit": return "进程退出"
        case "signal": return "进程信号"
        case "network-outbound": return "向外连接"
        case "network-inbound": return "接收连接"
        case "network-bind": return "监听"
        default: return operation
        }
    }

    /// Cursor expiry asks for an explicit refresh rather than silently restarting a historical query.
    public static func errorMessage(_ code: String) -> String {
        switch code {
        case "history_expired", "access_log_history_expired":
            return "部分历史已被清理，请点“刷新”重新查询。"
        case "cursor_invalid", "invalid_cursor", "access_log_cursor_invalid":
            return "查询位置已失效，请点“刷新”重新查询。"
        case "generation_conflict", "access_log_generation_conflict":
            return "日志已经变化，请刷新后再执行此操作。"
        case "access_log_busy", "query_busy", "access_log_query_busy":
            return "日志正在处理其他请求，请稍后重试。"
        case "access_log_unavailable", "access_log_storage_unavailable":
            return "访问日志暂时无法保存或读取，请查看保存状态。"
        case "unsupported_version", "access_log_unsupported_version":
            return "历史包含暂不支持的日志格式，文件已保留，请更新 App 和后台服务后再读取。"
        case "not_trusted", "managed_caller":
            return "当前 App 无法读取访问日志，请检查后台服务版本。"
        case "unknown_profile", "invalid_profile", "invalid_profile_id":
            return "没有找到这个程序的访问日志。"
        default:
            return "访问日志操作未完成（\(code)）。"
        }
    }
}
