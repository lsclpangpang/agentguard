import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// What a managed program path turned out to be, checked before it goes into a profile.
public enum ProgramPathError: Error, Equatable, Sendable {
    case empty
    case notAbsolute
    case missing
    case appBundle
    case directory
    case notExecutable
    /// `interpreter` is the `#!` line's program, when it could be read.
    case script(interpreter: String?)
    case notMachO
}

public enum ProgramFileKind: Equatable, Sendable {
    case missing, directory, file
}

/// The filesystem facts the check needs, so it can be tested without real files.
public protocol ProgramFileProbe {
    func kind(_ path: String) -> ProgramFileKind
    func isExecutable(_ path: String) -> Bool
    /// The path with every symlink resolved, or nil when it can't be resolved.
    func realPath(_ path: String) -> String?
    func header(_ path: String, count: Int) -> Data?
}

public enum ProgramPath {
    static let machOMagics: Set<[UInt8]> = [
        [0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe], // 32-bit
        [0xfe, 0xed, 0xfa, 0xcf], [0xcf, 0xfa, 0xed, 0xfe], // 64-bit
        [0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca], // universal
    ]

    /// Returns the real path to store, with symlinks resolved.
    ///
    /// 受管程序要和进程列表里的 `proc_pidpath` 对上，所以必须是解析过软链接的真实路径，
    /// 也必须是 Mach-O：脚本跑起来进程名是 bash/node，永远匹配不到。
    public static func validate(_ input: String, home: String, probe: some ProgramFileProbe) -> Result<String, ProgramPathError> {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .failure(.empty) }
        var path = trimmed
        if path == "~" { path = home } else if path.hasPrefix("~/") { path = home + path.dropFirst() }
        guard path.hasPrefix("/") else { return .failure(.notAbsolute) }
        switch probe.kind(path) {
        case .missing: return .failure(.missing)
        case .directory:
            let bare = path.hasSuffix("/") ? String(path.dropLast()) : path
            return .failure(bare.lowercased().hasSuffix(".app") ? .appBundle : .directory)
        case .file: break
        }
        guard let real = probe.realPath(path) else { return .failure(.missing) }
        guard probe.isExecutable(real) else { return .failure(.notExecutable) }
        let header = probe.header(real, count: 128) ?? Data()
        if header.starts(with: Array("#!".utf8)) { return .failure(.script(interpreter: interpreter(in: header))) }
        guard header.count >= 4, machOMagics.contains(Array(header.prefix(4))) else { return .failure(.notMachO) }
        return .success(real)
    }

    static func interpreter(in header: Data) -> String? {
        let line = String(decoding: header.dropFirst(2).prefix { $0 != 0x0a }, as: UTF8.self)
        let words = line.split(separator: " ").map(String.init)
        guard let first = words.first, !first.isEmpty else { return nil }
        // `#!/usr/bin/env node` 真正跑起来的是 node。
        if first.hasSuffix("/env") { return words.dropFirst().first { !$0.hasPrefix("-") } }
        return first
    }

    public static func message(for error: ProgramPathError) -> String {
        switch error {
        case .empty: return "请填写可执行文件的路径"
        case .notAbsolute: return "请填写以 / 开头的完整路径（也可以用 ~ 表示主目录）"
        case .missing: return "找不到这个文件"
        case .appBundle: return "这是一个 App 包。请填它包里 Contents/MacOS 下的程序，例如 /Applications/Foo.app/Contents/MacOS/Foo"
        case .directory: return "这是一个文件夹，请填其中的可执行文件"
        case .notExecutable: return "这个文件没有执行权限，不是可执行程序"
        case let .script(interpreter):
            let runner = interpreter.map { "（这里是 \($0)）" } ?? ""
            return "这是一个脚本。进程列表里看到的是解释器\(runner)，请填它最终启动的那个程序"
        case .notMachO: return "这不是 macOS 可执行程序"
        }
    }
}

/// Probes the local filesystem.
public struct LocalProgramFileProbe: ProgramFileProbe {
    public init() {}

    public func kind(_ path: String) -> ProgramFileKind {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else { return .missing }
        return isDirectory.boolValue ? .directory : .file
    }

    public func isExecutable(_ path: String) -> Bool {
        FileManager.default.isExecutableFile(atPath: path)
    }

    public func realPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    public func header(_ path: String, count: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: count)
    }
}
