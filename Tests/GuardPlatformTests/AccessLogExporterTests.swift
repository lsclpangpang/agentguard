import Foundation
import Testing
import GuardCore
@testable import GuardPlatform
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@Suite struct AccessLogExporterTests {
    @Test func streamsFixedQueryAcrossEmptyScanPagesAndWritesPrivateMetadataExport() throws {
        let f = try ExportFixture()
        defer { f.cleanup() }
        try Data("original".utf8).write(to: f.destination)
        var requests: [AccessLogQuery] = []
        var counts: [Int] = []
        var query = AccessLogQuery(profileID: "knodo", from: Date(timeIntervalSince1970: 1_800_000_000),
                                   through: Date(timeIntervalSince1970: 1_800_000_100), outcome: .denied, limit: 200)
        query.cursor = "discard-initial-cursor"
        let count = try AccessLogExporter.export(query: query, status: f.status, to: f.destination, send: { request in
            guard case let .exportAccessLogPage(current, byteLimit) = request else { Issue.record("wrong request"); return .failure(code: "wrong_request") }
            requests.append(current)
            #expect(byteLimit == 256 * 1024)
            #expect(try Data(contentsOf: f.destination) == Data("original".utf8))
            let temporary = try #require(f.temporaryFiles().first)
            #expect(try f.mode(temporary) == 0o600)
            switch requests.count {
            case 1: return .accessLogExportPage(.init(data: f.header, nextCursor: "scan-1", generation: 7, incomplete: true, recordCount: 0))
            case 2: return .accessLogExportPage(.init(data: f.chunk("one"), nextCursor: "scan-2", generation: 7, incomplete: false, recordCount: 1))
            default: return .accessLogExportPage(.init(data: f.chunk("two"), nextCursor: nil, generation: 7, incomplete: false, recordCount: 1))
            }
        }, progress: { counts.append($0) })
        #expect(count == 2 && counts.last == 2)
        #expect(requests.map(\.cursor) == [nil, "scan-1", "scan-2"])
        #expect(requests.allSatisfy { $0.profileID == query.profileID && $0.from == query.from && $0.through == query.through && $0.outcome == query.outcome && $0.limit == query.limit })
        let output = try Data(contentsOf: f.destination)
        let lines = String(decoding: output, as: UTF8.self).split(separator: "\n")
        let first = try #require(lines.first)
        let manifest = try #require(JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any])
        #expect(manifest["record_kind"] as? String == "export_manifest")
        #expect(manifest["profile_id"] as? String == "knodo")
        #expect(manifest["committed_only"] as? Bool == true)
        #expect((manifest["exported_at"] as? String)?.hasSuffix("Z") == true)
        #expect(manifest["outcome"] as? String == "denied")
        #expect(manifest["status_errors"] as? [String] == ["previous_source_gap"])
        #expect(manifest["source_gap_count"] as? Int == 2 && manifest["storage_dropped_count"] as? Int == 3)
        #expect(manifest["storage_gap_count"] as? Int == 0)
        let coverage = try #require(manifest["coverage"] as? [String: Any])
        #expect(coverage["successful_network_covered"] as? Bool == false)
        #expect(String(decoding: output, as: UTF8.self).contains("truncated_fields"))
        #expect(String(decoding: output, as: UTF8.self).contains("\"event_id\":\"one\""))
        #expect(String(decoding: output, as: UTF8.self).contains("\"event_id\":\"two\""))
        #expect(try f.mode(f.destination) == 0o600)
        #expect(try f.temporaryFiles().isEmpty)
    }

    @Test func generationChangeAndInvalidPageLeaveTheExistingFileIntact() throws {
        for page in [
            AccessLogExportPage(data: Data(), nextCursor: nil, generation: 8, incomplete: false, recordCount: 0),
            .init(data: Data(repeating: 65, count: 256 * 1024 + 1), nextCursor: nil, generation: 7, incomplete: false, recordCount: 0),
            .init(data: Data(), nextCursor: nil, generation: 7, incomplete: true, recordCount: 0),
            .init(data: Data(), nextCursor: nil, generation: 7, incomplete: false, recordCount: -1),
            .init(data: Data(), nextCursor: nil, generation: 7, incomplete: false, recordCount: Int.max),
        ] {
            let f = try ExportFixture()
            defer { f.cleanup() }
            try Data("keep".utf8).write(to: f.destination)
            #expect(throws: (any Error).self) {
                try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination,
                                             send: { _ in .accessLogExportPage(page) })
            }
            #expect(try Data(contentsOf: f.destination) == Data("keep".utf8))
            #expect(try f.temporaryFiles().isEmpty)
        }
    }

    @Test func repeatedAndCyclicCursorsFailWithoutReplacingTheDestination() throws {
        let sequences: [[String?]] = [["same", "same"], ["a", "b", "a"]]
        for cursors in sequences {
            let f = try ExportFixture()
            defer { f.cleanup() }
            try Data("keep".utf8).write(to: f.destination)
            var step = 0
            #expect(throws: (any Error).self) {
                try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination, send: { _ in
                    let next = cursors[min(step, cursors.count - 1)]
                    step += 1
                    return .accessLogExportPage(.init(data: f.header, nextCursor: next, generation: 7, incomplete: true, recordCount: 0))
                })
            }
            #expect(step <= cursors.count)
            #expect(try Data(contentsOf: f.destination) == Data("keep".utf8))
            #expect(try f.temporaryFiles().isEmpty)
        }
    }

    @Test func cancellationAfterAChunkPreservesOriginalAndCleansTemporaryFile() throws {
        let f = try ExportFixture()
        defer { f.cleanup() }
        try Data("keep".utf8).write(to: f.destination)
        var shouldCancel = false
        #expect(throws: (any Error).self) {
            try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination, send: { _ in
                .accessLogExportPage(.init(data: f.chunk("one"), nextCursor: nil, generation: 7, incomplete: false, recordCount: 1))
            }, cancelled: { shouldCancel }, progress: { count in if count == 1 { shouldCancel = true } })
        }
        #expect(try Data(contentsOf: f.destination) == Data("keep".utf8))
        #expect(try f.temporaryFiles().isEmpty)
    }

    @Test func helperFailureAndPreexistingCancellationDoNotLeavePartialExports() throws {
        let f = try ExportFixture()
        defer { f.cleanup() }
        #expect(throws: (any Error).self) {
            try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination,
                                         send: { _ in .failure(code: "access_log_history_expired") })
        }
        var calls = 0
        #expect(throws: (any Error).self) {
            try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination,
                                         send: { _ in calls += 1; return .ok }, cancelled: { true })
        }
        #expect(calls == 0 && !FileManager.default.fileExists(atPath: f.destination.path))
        #expect(try f.temporaryFiles().isEmpty)
    }

    @Test func unrestrictedExportExplicitlyDescribesItsEmptyFilters() throws {
        let f = try ExportFixture()
        defer { f.cleanup() }
        let count = try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination,
                                                 send: { _ in .accessLogExportPage(.init(data: f.header, nextCursor: nil, generation: 7, incomplete: false, recordCount: 0)) })
        #expect(count == 0)
        let lines = String(decoding: try Data(contentsOf: f.destination), as: UTF8.self).split(separator: "\n")
        let first = try #require(lines.first)
        let header = try #require(JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any])
        #expect(header["from"] is NSNull && header["through"] is NSNull && header["outcome"] is NSNull)
        #expect(AccessLogExportError.helperFailure("access_log_history_expired").localizedDescription == AccessLogPresentation.errorMessage("access_log_history_expired"))
    }

    @Test func refusesSymbolicLinksAndRechecksTheTargetBeforeAtomicReplacement() throws {
        let f = try ExportFixture()
        defer { f.cleanup() }
        let outside = f.parent.appendingPathComponent("outside")
        try Data("outside-keep".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(at: f.destination, withDestinationURL: outside)
        var calls = 0
        #expect(throws: (any Error).self) {
            try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination,
                                         send: { _ in calls += 1; return .ok })
        }
        #expect(calls == 0)
        #expect(try Data(contentsOf: outside) == Data("outside-keep".utf8))
        try FileManager.default.removeItem(at: f.destination)
        try Data("original".utf8).write(to: f.destination)
        #expect(throws: (any Error).self) {
            try AccessLogExporter.export(query: .init(profileID: "knodo"), status: f.status, to: f.destination, send: { _ in
                try FileManager.default.removeItem(at: f.destination)
                try FileManager.default.createSymbolicLink(at: f.destination, withDestinationURL: outside)
                return .accessLogExportPage(.init(data: f.header, nextCursor: nil, generation: 7, incomplete: false, recordCount: 0))
            })
        }
        #expect(try Data(contentsOf: outside) == Data("outside-keep".utf8))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: f.destination.path) == outside.path)
        #expect(try f.temporaryFiles().isEmpty)
    }
}

private struct ExportFixture {
    let parent: URL
    var destination: URL { parent.appendingPathComponent("export.jsonl") }
    var header: Data { Data("{\"schema_version\":1,\"record_kind\":\"export_header\"}\n".utf8) }
    var status: AccessLogStatus {
        var result = AccessLogStatus(profileID: "knodo", writerID: "writer")
        result.generation = 7
        result.isReady = true
        result.sourceGapCount = 2
        result.droppedCount = 3
        result.errors = ["previous_source_gap"]
        result.coverage = .init(fileEventsSubscribed: true, collectorHealthy: true, attributionComplete: false)
        return result
    }
    init() throws {
        guard let temporary = realpath(FileManager.default.temporaryDirectory.path, nil) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { free(temporary) }
        parent = URL(fileURLWithPath: String(cString: temporary), isDirectory: true)
            .appendingPathComponent("agentguard-access-export-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    func chunk(_ eventID: String) -> Data {
        var result = header
        result.append(Data("{\"record_kind\":\"access\",\"event_id\":\"\(eventID)\"}\n".utf8))
        return result
    }
    func mode(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try #require(attributes[.posixPermissions] as? NSNumber).intValue
    }
    func temporaryFiles() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: parent, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix(".agentguard-export-") }
    }
    func cleanup() { try? FileManager.default.removeItem(at: parent) }
}
