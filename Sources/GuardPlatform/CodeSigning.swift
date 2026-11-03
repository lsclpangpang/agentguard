#if os(macOS)
import Foundation
import GuardCore
import Security

public enum CodeSigning {
    /// Reads the caller's audit token from an XPC connection (private but long-standing KVC key).
    public static func auditToken(of connection: NSXPCConnection) -> audit_token_t? {
        guard let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var token = audit_token_t()
        value.getValue(&token, size: MemoryLayout<audit_token_t>.size)
        return token
    }

    public static func processKey(_ token: audit_token_t) -> ProcessKey {
        ProcessKey(pid: Int32(bitPattern: token.val.5), version: token.val.7)
    }

    /// Code identity of a running process, validated against its on-disk signature.
    public static func identity(of token: audit_token_t, uid: Int) throws -> CallerIdentity {
        var token = token
        let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            throw PlatformError.signing("无法获取调用方代码")
        }
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { throw PlatformError.signing("调用方签名无效") }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw PlatformError.signing("无法读取调用方签名")
        }
        let info = try signingInformation(staticCode)
        return CallerIdentity(uid: uid, signingIdentifier: info.identifier, teamIdentifier: info.team, cdhash: info.cdhash, managedInstance: nil)
    }

    /// cdhash of a signed binary or bundle on disk.
    public static func cdhash(atPath path: String) throws -> String {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess, let staticCode else {
            throw PlatformError.signing("无法读取 \(path)")
        }
        guard let hash = try signingInformation(staticCode).cdhash else { throw PlatformError.signing("\(path) 没有签名") }
        return hash
    }

    private static func signingInformation(_ code: SecStaticCode) throws -> (identifier: String?, team: String?, cdhash: String?) {
        var dictionary: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &dictionary) == errSecSuccess,
              let info = dictionary as? [String: Any]
        else { throw PlatformError.signing("无法读取签名信息") }
        let unique = info[kSecCodeInfoUnique as String] as? Data
        return (info[kSecCodeInfoIdentifier as String] as? String,
                info[kSecCodeInfoTeamIdentifier as String] as? String,
                unique.map { $0.map { String(format: "%02x", $0) }.joined() })
    }
}
#endif
