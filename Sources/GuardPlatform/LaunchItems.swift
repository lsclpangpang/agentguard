import Foundation
import GuardCore
#if canImport(Darwin)
import Darwin
#endif

public struct LaunchItem: Identifiable, Equatable, Sendable {
    public var id: String { path }
    public let path: String
    public let label: String
    public let executable: String
    public let arguments: [String]
    public let workingDirectory: String?
    public let unsupportedKeys: [String]

    public init?(path: String, data: Data) {
        guard let p = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let label = p["Label"] as? String, !label.isEmpty else { return nil }
        let args = p["ProgramArguments"] as? [String] ?? []
        guard let executable = p["Program"] as? String ?? args.first, executable.hasPrefix("/") else { return nil }
        self.path = path
        self.label = label
        self.executable = executable
        self.arguments = Array(args.dropFirst())
        self.workingDirectory = p["WorkingDirectory"] as? String
        let supported: Set<String> = ["Label", "Program", "ProgramArguments", "WorkingDirectory", "RunAtLoad", "KeepAlive",
                                      "ThrottleInterval", "StandardOutPath", "StandardErrorPath", "ProcessType",
                                      "LimitLoadToSessionType", "Disabled", "AssociatedBundleIdentifiers"]
        var unsupported = p.keys.filter { !supported.contains($0) }
        if p["Program"] != nil, let first = args.first, first != executable { unsupported.append("自定义 argv[0]") }
        self.unsupportedKeys = unsupported.sorted()
    }
}

public enum LaunchItemError: Error, Equatable, CustomStringConvertible {
    case missingOriginal, ambiguousOriginal, invalidBackup, destinationExists, operationFailed, invalidManagedItem, rollbackFailed, rollbackLeftStopped
    public var description: String {
        switch self {
        case .missingOriginal: return "找不到选定的原启动项，请重新选择"
        case .ambiguousOriginal: return "存在多个同名原启动项，请先解决重复项"
        case .invalidBackup: return "原启动项备份不存在或不完整，当前受控启动保持不变"
        case .destinationExists: return "原启动项的位置已有文件，请先检查，当前受控启动保持不变"
        case .operationFailed: return "系统未能完成启动项变更，请检查启动状态后重试"
        case .invalidManagedItem: return "受控启动项的文件与系统注册不一致，请检查启动项后重试"
        case .rollbackFailed: return "启动项变更失败，未能完整恢复原启动方式，请检查系统启动状态"
        case .rollbackLeftStopped: return "启动项变更失败，文件已还原；部分任务未重新加载，请检查系统启动状态"
        }
    }
}

/// Shared read-only inspection; mutations are only invoked by the privileged Helper.
public struct LaunchItemFiles: Sendable {
    public let originalDirectories: [String]
    public let automaticDirectory: String
    public let manualDirectory: String
    public let backupDirectory: String
    public let launcherPath: String
    public let labelPrefix: String

    public init(home: String, configRoot: String, launcherPath: String, labelPrefix: String,
                automaticDirectory: String = "/Library/LaunchAgents") {
        self.originalDirectories = [home + "/Library/LaunchAgents", automaticDirectory]
        self.automaticDirectory = automaticDirectory
        self.manualDirectory = configRoot + "/launch-jobs"
        self.backupDirectory = configRoot + "/backups"
        self.launcherPath = launcherPath
        self.labelPrefix = labelPrefix
    }

    public func items(in directory: String) throws -> [LaunchItem] {
        guard FileManager.default.fileExists(atPath: directory) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: directory).sorted().filter { $0.hasSuffix(".plist") }.compactMap {
            let path = directory + "/" + $0
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
            return LaunchItem(path: path, data: data)
        }
    }

    public func originals() throws -> [LaunchItem] {
        try originalDirectories.flatMap { try items(in: $0) }.filter { !$0.label.hasPrefix("com.lsclpangpang.agentguard.") }
    }

    public func managed(profileID: String) throws -> [LaunchItem] {
        let scan = try managedScan(profileID: profileID)
        guard scan.problems.isEmpty else { throw LaunchItemError.invalidManagedItem }
        return scan.items
    }

    public func managedScan(profileID: String) throws -> (items: [LaunchItem], problems: [String]) {
        var result: [LaunchItem] = [], problems: [String] = []
        for directory in [automaticDirectory, manualDirectory] where FileManager.default.fileExists(atPath: directory) {
            for filename in try FileManager.default.contentsOfDirectory(atPath: directory).sorted() where filename.hasSuffix(".plist") {
                let path = directory + "/" + filename
                let nameMatches = LaunchAgentDefinition.isManagedLabel(String(filename.dropLast(6)), profileID: profileID, labelPrefix: labelPrefix)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), let item = LaunchItem(path: path, data: data) else {
                    if nameMatches { problems.append("启动文件无法读取，已保留：" + path) }
                    continue
                }
                guard LaunchAgentDefinition.isManagedLabel(item.label, profileID: profileID, labelPrefix: labelPrefix) else { continue }
                guard item.executable == launcherPath, item.arguments == ["launch", profileID] else {
                    problems.append("启动文件的程序与配置不一致，已保留：" + path); continue
                }
                result.append(item)
            }
        }
        return (result, problems)
    }

    public func original(label: String, selectedPath: String?) throws -> LaunchItem {
        let matches = try originals().filter { $0.label == label }
        guard matches.count < 2 else { throw LaunchItemError.ambiguousOriginal }
        guard let item = matches.first, selectedPath == nil || selectedPath == item.path,
              isOriginalLocation(item.path) else { throw LaunchItemError.missingOriginal }
        return item
    }

    public func isOriginalLocation(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        return path.hasSuffix(".plist") && originalDirectories.contains {
            url.deletingLastPathComponent().path == $0
                && url.resolvingSymlinksInPath().deletingLastPathComponent().path == URL(fileURLWithPath: $0).resolvingSymlinksInPath().path
        }
    }

    public func backup(label: String, requireEmptyDestination: Bool = false) throws -> (path: String, destination: String) {
        guard !label.isEmpty, label.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0) }),
              !label.hasPrefix(".") else { throw LaunchItemError.invalidBackup }
        let path = backupDirectory + "/" + label + ".plist"
        guard let data = FileManager.default.contents(atPath: path), let item = LaunchItem(path: path, data: data), item.label == label,
              let destination = try? String(contentsOfFile: path + ".location", encoding: .utf8), isOriginalLocation(destination)
        else { throw LaunchItemError.invalidBackup }
        if requireEmptyDestination && FileManager.default.fileExists(atPath: destination) { throw LaunchItemError.destinationExists }
        return (path, destination)
    }
}

public enum LaunchctlClient {
    public struct Result {
        public let status: Int32
        public let output: String
        public init(status: Int32, output: String = "") { self.status = status; self.output = output }
    }

    public static func run(_ arguments: [String]) -> Result {
        #if os(macOS)
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return Result(status: -1, output: "") }
        let deadline = DispatchWorkItem { if process.isRunning { kill(process.processIdentifier, SIGKILL) } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 3, execute: deadline)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        deadline.cancel()
        return Result(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
        #else
        return Result(status: -1, output: "")
        #endif
    }

    /// A missing job is a normal state. Other failures must not masquerade as "not enabled".
    public static func registration(_ result: Result) -> (loaded: Bool, running: Bool)? {
        if result.status == 0 {
            let running = result.output.split(separator: "\n").contains {
                let line = $0.trimmingCharacters(in: .whitespaces)
                return line.hasPrefix("pid = ") && (Int32(line.dropFirst(6)) ?? 0) > 0
            }
            return (true, running)
        }
        if result.output.contains("Could not find service") { return (false, false) }
        return nil
    }

    /// Read the services section only; other sections may also contain label-like strings.
    public static func labels(inDomain result: Result) -> Set<String>? {
        guard result.status == 0 else { return nil }
        var inServices = false, labels = Set<String>()
        for line in result.output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "services = {" { inServices = true; continue }
            if inServices && trimmed == "}" { return labels }
            if inServices {
                let parts = trimmed.split(whereSeparator: \.isWhitespace)
                // Ignore headers/unknown rows rather than making unrelated jobs block all work.
                if parts.count >= 3, Int32(parts[0]) != nil, let label = parts.last { labels.insert(String(label)) }
            }
        }
        return nil
    }

    /// Used only to clean up a registered job whose source file vanished. A matching label alone
    /// is insufficient permission to unload it: confirm the launcher and exact argument array.
    public static func isManagedJob(_ result: Result, launcherPath: String, profileID: String) -> Bool {
        guard result.status == 0 else { return false }
        var program: String?, arguments: [String] = [], inArguments = false
        for line in result.output.split(separator: "\n") {
            let value = line.trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("program = ") { program = String(value.dropFirst(10)) }
            if value == "arguments = {" { inArguments = true; continue }
            if inArguments {
                if value == "}" { inArguments = false } else { arguments.append(value) }
            }
        }
        return program == launcherPath && arguments == [launcherPath, "launch", profileID]
    }
}
