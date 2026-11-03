import Foundation

public enum ESEventKind: Equatable, Sendable {
    case fork(child: ProcessKey)
    case exec(target: ProcessKey, path: String?)
    case exit
    case open(path: String, write: Bool)
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
        case .fork, .exit, .unsupported: return []
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
    /// Kernel open flag for write access (FWRITE).
    static let writeFlag = 0x2

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
        return ESLine(globalSequence: UInt64(sequence), process: key, executablePath: executablePath(process), kind: try kind(name, body))
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
            let flags = integer(body["fflag"]) ?? 0
            return .open(path: try filePath(body["file"], "open.file"), write: flags & writeFlag != 0)
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
}
