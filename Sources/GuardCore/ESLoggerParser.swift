import Foundation
import CoreFoundation

public enum ESEventKind: Equatable, Sendable {
    case fork(child: ProcessKey)
    case exec(target: ProcessKey, path: String?)
    case exit
    case open(path: String, write: Bool)
    /// An open notification without a trustworthy FREAD/FWRITE mode. Keep the event and target,
    /// but never infer a content-read permission suggestion from the absence of a write bit.
    case openUnclassified(path: String)
    case create(path: String)
    case rename(from: String, to: String)
    case unlink(path: String)
    case close(path: String, modified: Bool)
    case unsupported(String)
}

public struct ESLine: Equatable, Sendable {
    public var globalSequence: UInt64
    public var process: ProcessKey
    public var executablePath: String?
    public var kind: ESEventKind
    /// Identity baselines from the event itself, never sampled later by a potentially reused PID.
    public var processStartTime: UInt64? = nil
    public var relatedProcessStartTime: UInt64? = nil
    /// Frozen at ingress by the collector adapter. A process start time is never a source event time.
    public var receivedAt: Date? = nil
    public var sourceAt: Date? = nil
    public var sourceEventID: String? = nil
    /// Kernel FREAD/FWRITE flags, not userspace O_RDONLY/O_WRONLY flags. Nil means not supplied
    /// or not an integral UInt32. An open notification does not prove content was consumed.
    public var openFlags: UInt32? = nil

    public init(globalSequence: UInt64, process: ProcessKey, executablePath: String?, kind: ESEventKind,
                processStartTime: UInt64? = nil, relatedProcessStartTime: UInt64? = nil,
                receivedAt: Date? = nil, sourceAt: Date? = nil, sourceEventID: String? = nil,
                openFlags: UInt32? = nil) {
        self.globalSequence = globalSequence; self.process = process; self.executablePath = executablePath
        self.kind = kind; self.processStartTime = processStartTime; self.relatedProcessStartTime = relatedProcessStartTime
        self.receivedAt = receivedAt; self.sourceAt = sourceAt; self.sourceEventID = sourceEventID
        self.openFlags = openFlags
    }

    /// Preserved before `observedAccesses` groups create/unlink/rename into writes.
    public var rawOperation: String {
        switch kind {
        case .fork: return "fork"
        case .exec: return "exec"
        case .exit: return "exit"
        case .open, .openUnclassified: return "open"
        case .create: return "create"
        case .rename: return "rename"
        case .unlink: return "unlink"
        case .close: return "close"
        case let .unsupported(name): return name
        }
    }

    /// Each rename target keeps the same source event identity and its own stable subsequence.
    public var rawTargets: [String?] {
        switch kind {
        case let .exec(_, path): return [path]
        case let .open(path, _), let .openUnclassified(path), let .create(path), let .unlink(path), let .close(path, _): return [path]
        case let .rename(from, to): return [from, to]
        case .fork, .exit, .unsupported: return [nil]
        }
    }

    public var processEvent: ProcessEvent? {
        switch kind {
        case let .fork(child): return .fork(parent: process, child: child)
        case let .exec(target, _): return .exec(from: process, to: target)
        case .exit: return .exit(process)
        default: return nil
        }
    }

    public var observedAccesses: [ObservedAccess] {
        switch kind {
        case let .exec(_, path): return path.map { [.exec($0)] } ?? []
        case let .open(path, write): return [write ? .write(path) : .read(path)]
        case let .create(path), let .unlink(path): return [.write(path)]
        case let .rename(from, to): return [.write(from), .write(to)]
        case let .close(path, modified): return modified ? [.write(path)] : []
        case .fork, .exit, .openUnclassified, .unsupported: return []
        }
    }

    public var observedAccess: ObservedAccess? { observedAccesses.first }
}

public enum ESParseError: Error, Equatable, Sendable {
    case malformed
    case missingField(String)
}

/// Parses one line of `eslogger --format json`. eslogger is not a stable API; this adapter is
/// replaceable and its failures must surface as collector problems, never as silence.
public enum ESLoggerParser {
    /// Kernel open flags (FREAD/FWRITE), distinct from the userspace O_* constants.
    static let readFlag: UInt32 = 0x1
    static let writeFlag: UInt32 = 0x2

    public static func parse(_ line: String) throws -> ESLine {
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)), let root = object as? [String: Any] else {
            throw ESParseError.malformed
        }
        guard let sequence = integer(root["global_seq_num"]) else { throw ESParseError.missingField("global_seq_num") }
        guard let process = root["process"] as? [String: Any] else { throw ESParseError.missingField("process") }
        let key = try processKey(process)
        guard let event = root["event"] as? [String: Any], let name = event.keys.first, event.count == 1 else {
            throw ESParseError.missingField("event")
        }
        let body = event[name] as? [String: Any] ?? [:]
        let related = body[name == "fork" ? "child" : "target"] as? [String: Any]
        return ESLine(globalSequence: UInt64(sequence), process: key, executablePath: executablePath(process), kind: try kind(name, body),
                      processStartTime: startTime(process), relatedProcessStartTime: related.flatMap(startTime),
                      sourceAt: SourceEventTimestamp.parse(root["time"]),
                      openFlags: name == "open" ? openFlags(body["fflag"]) : nil)
    }

    private static func startTime(_ process: [String: Any]) -> UInt64? {
        if let time = process["start_time"] as? [String: Any], let seconds = integer(time["tv_sec"]), let micros = integer(time["tv_usec"]),
           seconds > 0, micros >= 0, micros < 1_000_000 {
            return UInt64(seconds) * 1_000_000 + UInt64(micros)
        }
        // Some eslogger versions render timeval as RFC3339. Only a complete microsecond value is
        // usable for signaling; a rounded timestamp must not establish process identity.
        guard let text = process["start_time"] as? String,
              let range = text.range(of: #"\.\d{6}(?=Z|[+-]\d{2}:\d{2}$)"#, options: .regularExpression),
              let micros = UInt64(text[range].dropFirst()) else { return nil }
        let secondsText = String(text[..<range.lowerBound]) + String(text[range.upperBound...])
        // Removing the six microsecond digits must leave whole seconds, never another fraction.
        // Keep the uppercase separator and avoid a per-event formatter; microseconds stay integers.
        guard secondsText.utf8.dropFirst(10).first == UInt8(ascii: "T"),
              !secondsText.utf8.contains(UInt8(ascii: ".")),
              let date = SourceEventTimestamp.parse(secondsText), date.timeIntervalSince1970 > 0 else { return nil }
        return UInt64(date.timeIntervalSince1970.rounded()) * 1_000_000 + micros
    }

    private static func kind(_ name: String, _ body: [String: Any]) throws -> ESEventKind {
        switch name {
        case "fork":
            guard let child = body["child"] as? [String: Any] else { throw ESParseError.missingField("fork.child") }
            return .fork(child: try processKey(child))
        case "exec":
            guard let target = body["target"] as? [String: Any] else { throw ESParseError.missingField("exec.target") }
            return .exec(target: try processKey(target), path: executablePath(target))
        case "exit":
            return .exit
        case "open":
            let path = try filePath(body["file"], "open.file")
            guard let flags = openFlags(body["fflag"]), flags & (readFlag | writeFlag) != 0 else {
                return .openUnclassified(path: path)
            }
            return .open(path: path, write: flags & writeFlag != 0)
        case "create":
            return .create(path: try destination(body["destination"], "create.destination"))
        case "rename":
            return .rename(from: try filePath(body["source"], "rename.source"), to: try destination(body["destination"], "rename.destination"))
        case "unlink":
            return .unlink(path: try filePath(body["target"], "unlink.target"))
        case "close":
            return .close(path: try filePath(body["target"], "close.target"), modified: body["modified"] as? Bool ?? false)
        default:
            return .unsupported(name)
        }
    }

    private static func processKey(_ process: [String: Any]) throws -> ProcessKey {
        guard let token = process["audit_token"] as? [String: Any],
              let pid = integer(token["pid"]), let version = integer(token["pidversion"])
        else { throw ESParseError.missingField("audit_token") }
        return ProcessKey(pid: Int32(truncatingIfNeeded: pid), version: UInt32(truncatingIfNeeded: version))
    }

    private static func executablePath(_ process: [String: Any]) -> String? {
        (process["executable"] as? [String: Any])?["path"] as? String
    }

    private static func filePath(_ value: Any?, _ field: String) throws -> String {
        guard let file = value as? [String: Any], let path = file["path"] as? String else { throw ESParseError.missingField(field) }
        return path
    }

    private static func destination(_ value: Any?, _ field: String) throws -> String {
        guard let destination = value as? [String: Any] else { throw ESParseError.missingField(field) }
        if let existing = destination["existing_file"] { return try filePath(existing, field) }
        guard let newPath = destination["new_path"] as? [String: Any], let filename = newPath["filename"] as? String else {
            throw ESParseError.missingField(field)
        }
        let dir = try filePath(newPath["dir"], field)
        return dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
    }

    private static func integer(_ value: Any?) -> Int? {
        switch value {
        case let v as Int: return v
        case let v as NSNumber: return v.intValue
        default: return nil
        }
    }

    private static func openFlags(_ value: Any?) -> UInt32? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value.isFinite, value >= 0, value <= Double(UInt32.max), value.rounded(.towardZero) == value else { return nil }
        return UInt32(value)
    }
}
