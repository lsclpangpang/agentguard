import Foundation
import GuardCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum PlatformError: Error, CustomStringConvertible {
    case unsupported
    case sandbox(String)
    case helper(String)
    case exec(String, Int32)
    case signing(String)
    case authorization(Int32)
    case notFound(String)
    case notExecutable(String)

    public var description: String {
        switch self {
        case .unsupported: return "只能在 macOS 上运行"
        case let .sandbox(message): return "加载沙箱规则失败：\(message)"
        case let .helper(message): return "Helper：\(message)"
        case let .exec(path, code): return "无法启动 \(path)：\(String(cString: strerror(code)))"
        case let .signing(message): return "签名校验失败：\(message)"
        case let .authorization(status): return "系统认证未完成（\(status)）"
        case let .notFound(what): return "找不到 \(what)"
        case let .notExecutable(path): return "\(path) 不是可执行文件（缺少执行权限）"
        }
    }
}

public enum Exec {
    /// PATH lookup as execvp does it, but against the plan's environment rather than ours.
    public static func resolve(_ executable: String, searchPath: String,
                               isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }) -> String? {
        if executable.contains("/") { return isExecutable(executable) ? executable : nil }
        for directory in searchPath.split(separator: ":") where !directory.isEmpty {
            let candidate = directory + "/" + executable
            if isExecutable(candidate) { return candidate }
        }
        return nil
    }

    /// Closes every descriptor the target should not inherit.
    public static func closeInheritedDescriptors(keeping keep: Set<Int32> = [0, 1, 2]) {
        let limit = min(Int32(getdtablesize()), 65_536)
        var fd: Int32 = 0
        while fd < limit {
            if !keep.contains(fd) { close(fd) }
            fd += 1
        }
    }

    /// Replaces the current process with the plan's target. Only returns by throwing.
    public static func replaceProcess(with plan: LaunchPlan) throws -> Never {
        let searchPath = plan.environment["PATH"] ?? LaunchPlan.defaultPath
        guard let path = resolve(plan.executable, searchPath: searchPath) else {
            // 文件在、但没有执行位时，说“找不到”会把人带偏；这条错误此前就误导过一次排查。
            if FileManager.default.fileExists(atPath: plan.executable) {
                throw PlatformError.notExecutable(plan.executable)
            }
            throw PlatformError.notFound(plan.executable)
        }
        guard chdir(plan.workingDirectory) == 0 else { throw PlatformError.exec(plan.workingDirectory, errno) }
        if plan.stdinFromNull {
            let fd = open("/dev/null", O_RDONLY)
            if fd >= 0 {
                dup2(fd, 0)
                if fd != 0 { close(fd) }
            }
        }
        let arguments = [plan.executable] + plan.arguments
        let environment = plan.environment.map { "\($0.key)=\($0.value)" }.sorted()
        var cArguments: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
        var cEnvironment: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) } + [nil]
        execve(path, &cArguments, &cEnvironment)
        throw PlatformError.exec(path, errno)
    }
}

public enum UserAccount {
    public static func home(uid: uid_t) -> String? {
        guard let entry = getpwuid(uid), let dir = entry.pointee.pw_dir else { return nil }
        return String(cString: dir)
    }
}

/// Process facts the Helper needs to recognise an already-running instance after a restart.
public enum ProcessFacts {
    /// Start time in microseconds since the epoch; stable across exec, so it distinguishes a live
    /// instance from a reused PID.
    public static func startTime(pid: Int32) -> UInt64? {
        #if canImport(Darwin)
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
        #else
        return nil
        #endif
    }
}
