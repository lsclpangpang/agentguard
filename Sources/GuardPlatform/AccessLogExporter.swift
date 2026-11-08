import Foundation
import GuardCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public enum AccessLogExportError: Error, Equatable, LocalizedError {
    case cancelled
    case invalidDestination
    case destinationChanged
    case invalidStatus
    case helperFailure(String)
    case invalidPage
    case generationChanged
    case cursorDidNotAdvance
    case cursorBudgetExceeded
    case countOverflow
    case fileOperation(String, Int32)

    public var errorDescription: String? {
        switch self {
        case .cancelled: return "已取消导出，原文件已保留。"
        case .invalidDestination: return "无法使用这个保存位置。请选择普通文件，不能选择链接或文件夹。"
        case .destinationChanged: return "导出期间，目标文件发生了变化。请重新选择保存位置。"
        case .invalidStatus: return "日志状态已变化，请刷新后重新导出。"
        case let .helperFailure(code): return AccessLogPresentation.errorMessage(code)
        case .invalidPage: return "收到的日志数据不完整，导出未保存。请刷新后重试。"
        case .generationChanged: return "导出期间日志已被清理，请刷新后重新导出。"
        case .cursorDidNotAdvance: return "日志分页没有继续前进，导出已停止，原文件已保留。"
        case .cursorBudgetExceeded: return "导出的分页过多，请缩小时间范围后重试。"
        case .countOverflow: return "导出记录数超出支持范围，原文件已保留。"
        case let .fileOperation(operation, code): return "\(operation)失败：\(String(cString: strerror(code)))。原文件已保留。"
        }
    }
}

/// A synchronous, bounded writer for use from the App's detached export task. Only committed pages
/// cross the Helper boundary. No destination is modified until all pages and the file sync succeed.
public enum AccessLogExporter {
    public static let pageByteLimit = 256 * 1024
    private static let maximumCursors = 16_384
    private static let maximumCursorBytes = 4 * 1024 * 1024

    public static func export(query: AccessLogQuery, status: AccessLogStatus, to destination: URL,
                              send: (HelperRequest) throws -> HelperResponse,
                              cancelled: () -> Bool = { false }, progress: (Int) -> Void = { _ in }) throws -> Int {
        try checkCancellation(cancelled)
        guard ProfileID.isValid(query.profileID), status.profileID == query.profileID else { throw AccessLogExportError.invalidStatus }
        guard destination.isFileURL, destination.host == nil || destination.host == "" || destination.host == "localhost",
              !destination.hasDirectoryPath, !destination.path.contains("\0") else { throw AccessLogExportError.invalidDestination }
        let name = destination.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..", name != "/" else { throw AccessLogExportError.invalidDestination }
        let parent = destination.deletingLastPathComponent()
        let directory = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else { throw fileFailure("打开保存位置") }
        defer { _ = closeFD(directory) }
        let original = try destinationIdentity(directory: directory, name: name)
        let temporary = ".agentguard-export-" + UUID().uuidString + ".tmp"
        var file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw fileFailure("创建导出文件") }
        var temporaryExists = true
        defer {
            if file >= 0 { _ = closeFD(file) }
            if temporaryExists { _ = unlinkat(directory, temporary, 0) }
        }
        guard fchmod(file, 0o600) == 0 else { throw fileFailure("设置导出文件权限") }
        var temporaryInfo = stat()
        guard fstat(file, &temporaryInfo) == 0 else { throw fileFailure("检查导出文件") }
        guard temporaryInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), temporaryInfo.st_nlink == 1 else {
            throw AccessLogExportError.invalidDestination
        }

        var fixedQuery = query
        fixedQuery.cursor = nil
        let header = try manifest(query: fixedQuery, status: status)
        try writeAll(file, data: header)
        progress(0)
        var cursor: String?
        var seenCursors: Set<String> = []
        var cursorBytes = 0
        var count = 0
        while true {
            try checkCancellation(cancelled)
            var pageQuery = fixedQuery
            pageQuery.cursor = cursor
            let response = try send(.exportAccessLogPage(query: pageQuery, byteLimit: pageByteLimit))
            try checkCancellation(cancelled)
            let page: AccessLogExportPage
            switch response {
            case let .accessLogExportPage(value): page = value
            case let .failure(code): throw AccessLogExportError.helperFailure(code)
            default: throw AccessLogExportError.invalidPage
            }
            guard page.generation == status.generation else { throw AccessLogExportError.generationChanged }
            guard page.data.count <= pageByteLimit, page.recordCount >= 0, page.recordCount <= 500,
                  page.recordCount <= page.data.count, !page.incomplete || page.nextCursor != nil else {
                throw AccessLogExportError.invalidPage
            }
            if let next = page.nextCursor {
                guard !next.isEmpty, next != cursor, !seenCursors.contains(next) else { throw AccessLogExportError.cursorDidNotAdvance }
                let bytes = next.utf8.count
                guard bytes <= 16 * 1024, seenCursors.count < maximumCursors,
                      cursorBytes <= maximumCursorBytes - min(maximumCursorBytes, bytes) else {
                    throw AccessLogExportError.cursorBudgetExceeded
                }
                cursorBytes += bytes
                seenCursors.insert(next)
            }
            let (nextCount, overflow) = count.addingReportingOverflow(page.recordCount)
            guard !overflow else { throw AccessLogExportError.countOverflow }
            try writeAll(file, data: page.data)
            count = nextCount
            progress(count)
            guard let next = page.nextCursor else { break }
            cursor = next
        }
        try checkCancellation(cancelled)
        guard fsync(file) == 0 else { throw fileFailure("保存导出文件") }
        let result = closeFD(file)
        file = -1
        guard result == 0 else { throw fileFailure("关闭导出文件") }
        try checkCancellation(cancelled)
        guard try destinationIdentity(directory: directory, name: name) == original else { throw AccessLogExportError.destinationChanged }
        guard let temporaryIdentity = try destinationIdentity(directory: directory, name: temporary),
              temporaryIdentity == Identity(temporaryInfo) else { throw AccessLogExportError.destinationChanged }
        // rename replaces a directory entry; it never follows the destination as a link.
        guard renameat(directory, temporary, directory, name) == 0 else { throw fileFailure("保存导出文件") }
        temporaryExists = false
        return count
    }

    private struct Identity: Equatable {
        let device: UInt64
        let inode: UInt64
        init(_ info: stat) {
            device = UInt64(truncatingIfNeeded: info.st_dev)
            inode = UInt64(truncatingIfNeeded: info.st_ino)
        }
    }

    private static func destinationIdentity(directory: Int32, name: String) throws -> Identity? {
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
            guard info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else { throw AccessLogExportError.invalidDestination }
            return Identity(info)
        }
        guard errno == ENOENT else { throw fileFailure("检查保存位置") }
        return nil
    }

    private static func checkCancellation(_ cancelled: () -> Bool) throws {
        if cancelled() { throw AccessLogExportError.cancelled }
    }

    private static func writeAll(_ file: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let count = write(file, base.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw fileFailure("写入导出文件") }
                offset += count
            }
        }
    }

    private static func closeFD(_ file: Int32) -> Int32 {
        #if canImport(Darwin)
        Darwin.close(file)
        #else
        Glibc.close(file)
        #endif
    }

    private static func fileFailure(_ operation: String) -> AccessLogExportError { .fileOperation(operation, errno) }

    private struct Manifest: Encodable {
        let schemaVersion = 1
        let recordKind = "export_manifest"
        let exportedAt: Date
        let profileID: String
        let from: Date?
        let through: Date?
        let outcome: AccessLogOutcome?
        let generation: UInt64
        let committedOnly = true
        let coverage: AccessLogCoverage
        let sourceGapCount: UInt64
        let storageGapCount: UInt64
        let storageDroppedCount: UInt64
        let statusErrors: [String]
        let notices = [
            "仅包含已保存的记录；采集器尚未保存的访问不包含在导出中。",
            "采集覆盖以记录中的 coverage 为准，不能据此证明所有访问都已记录；成功的网络连接目前未覆盖。",
            "采集和保存缺口分别保留；重复拒绝报告数不等同于真实调用次数。",
            "字段截断时，truncated_fields 保留原始 UTF-8 字节数；缺失字段不补造。"
        ]
        enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version", recordKind = "record_kind", exportedAt = "exported_at"
            case profileID = "profile_id", from, through, outcome, generation, committedOnly = "committed_only", coverage
            case sourceGapCount = "source_gap_count", storageGapCount = "storage_gap_count", storageDroppedCount = "storage_dropped_count"
            case statusErrors = "status_errors", notices
        }

        func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(schemaVersion, forKey: .schemaVersion)
            try container.encode(recordKind, forKey: .recordKind)
            try container.encode(exportedAt, forKey: .exportedAt)
            try container.encode(profileID, forKey: .profileID)
            // Explicit nulls distinguish an unrestricted range/filter from missing metadata.
            try container.encode(from, forKey: .from)
            try container.encode(through, forKey: .through)
            try container.encode(outcome, forKey: .outcome)
            try container.encode(generation, forKey: .generation)
            try container.encode(committedOnly, forKey: .committedOnly)
            try container.encode(coverage, forKey: .coverage)
            try container.encode(sourceGapCount, forKey: .sourceGapCount)
            try container.encode(storageGapCount, forKey: .storageGapCount)
            try container.encode(storageDroppedCount, forKey: .storageDroppedCount)
            try container.encode(statusErrors, forKey: .statusErrors)
            try container.encode(notices, forKey: .notices)
        }
    }

    private static func manifest(query: AccessLogQuery, status: AccessLogStatus) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = AccessLogTimestamp.encodingStrategy
        encoder.outputFormatting = [.sortedKeys]
        let value = Manifest(exportedAt: Date(), profileID: query.profileID, from: query.from, through: query.through,
                             outcome: query.outcome, generation: status.generation, coverage: status.coverage,
                             sourceGapCount: status.sourceGapCount, storageGapCount: status.storageGapCount,
                             storageDroppedCount: status.droppedCount, statusErrors: status.errors)
        var data = try encoder.encode(value)
        guard data.count < pageByteLimit else { throw AccessLogExportError.invalidStatus }
        data.append(0x0a)
        return data
    }
}
