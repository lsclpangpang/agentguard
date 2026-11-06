import CSandboxCheck
import Foundation
import GuardCore

#if os(macOS)
import Darwin

@_silgen_name("sandbox_init")
private func c_sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64, _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32

@_silgen_name("sandbox_free_error")
private func c_sandbox_free_error(_ errorbuf: UnsafeMutablePointer<CChar>?)
#endif

/// Wraps the (deprecated but still shipped) sandbox_init SPI. Child processes inherit the profile.
public enum Sandbox {
    public static func apply(_ profile: String) throws {
        #if os(macOS)
        var error: UnsafeMutablePointer<CChar>?
        let result = profile.withCString { c_sandbox_init($0, 0, &error) }
        if result != 0 {
            let message = error.map { String(cString: $0) } ?? "未知错误"
            c_sandbox_free_error(error)
            throw PlatformError.sandbox(message)
        }
        #else
        throw PlatformError.unsupported
        #endif
    }

    /// Whether the process runs under any sandbox profile. Says nothing about which profile.
    public static func isSandboxed(pid: Int32) -> Bool {
        SystemSandboxProbe().isSandboxed(pid: pid) == true
    }
}

/// Queries the kernel about another process's sandbox. Needs no cooperation from that process,
/// and the Helper runs as root, so it can probe every managed process.
public struct SystemSandboxProbe: SandboxProbe {
    public init() {}

    public func isSandboxed(pid: Int32) -> Bool? {
        switch agentguard_sandbox_is_sandboxed(pid) {
        case 0: return false
        case 1: return true
        default: return nil
        }
    }

    public func check(pid: Int32, operation: SandboxOperation, target: String) -> SandboxCheckResult {
        let result: Int32 = operation.rawValue.withCString { op in
            target.withCString { value in
                switch operation {
                case .machLookup: return agentguard_sandbox_check_global_name(pid, op, value)
                case .fileRead, .fileWrite: return agentguard_sandbox_check_path(pid, op, value)
                }
            }
        }
        switch result {
        case 0: return .allowed
        case 1: return .denied
        default: return .unavailable
        }
    }
}
