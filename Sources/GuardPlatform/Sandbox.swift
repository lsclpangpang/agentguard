import Foundation

#if os(macOS)
import Darwin

@_silgen_name("sandbox_init")
private func c_sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64, _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32

@_silgen_name("sandbox_free_error")
private func c_sandbox_free_error(_ errorbuf: UnsafeMutablePointer<CChar>?)

@_silgen_name("sandbox_check")
private func c_sandbox_check(_ pid: pid_t, _ operation: UnsafePointer<CChar>?, _ type: Int32) -> Int32
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
        #if os(macOS)
        return c_sandbox_check(pid, nil, 0) != 0
        #else
        return false
        #endif
    }
}
