#if os(macOS)
import Foundation
import GuardCore
import Security

/// System authorization for one change: the app asks with a fresh AuthorizationRef for the right
/// `<prefix><scope>`, the Helper re-checks that exact right from the external form and destroys it.
public enum UserAuthorization {
    public static func rightName(_ scope: String) -> String { AgentGuardConfig.authorizationRightPrefix + scope }

    /// Prompts the user and returns the external form to send to the Helper.
    public static func obtain(scope: String, prompt: String) throws -> Data {
        var reference: AuthorizationRef?
        var status = AuthorizationCreate(nil, nil, [], &reference)
        guard status == errAuthorizationSuccess, let reference else { throw PlatformError.authorization(status) }
        status = copyRights(reference, right: rightName(scope), prompt: prompt, flags: [.interactionAllowed, .extendRights, .preAuthorize])
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(reference, [])
            throw PlatformError.authorization(status)
        }
        var external = AuthorizationExternalForm()
        status = AuthorizationMakeExternalForm(reference, &external)
        guard status == errAuthorizationSuccess else { throw PlatformError.authorization(status) }
        return withUnsafeBytes(of: &external) { Data($0) }
    }

    static func copyRights(_ reference: AuthorizationRef, right: String, prompt: String?, flags: AuthorizationFlags) -> OSStatus {
        right.withCString { rightPointer in
            var item = AuthorizationItem(name: rightPointer, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                guard let prompt else {
                    return AuthorizationCopyRights(reference, &rights, nil, flags, nil)
                }
                return "prompt".withCString { keyPointer in
                    prompt.withCString { promptPointer in
                        var environmentItem = AuthorizationItem(name: keyPointer, valueLength: strlen(promptPointer),
                                                                value: UnsafeMutableRawPointer(mutating: promptPointer), flags: 0)
                        return withUnsafeMutablePointer(to: &environmentItem) { environmentPointer in
                            var environment = AuthorizationEnvironment(count: 1, items: environmentPointer)
                            return AuthorizationCopyRights(reference, &rights, &environment, flags, nil)
                        }
                    }
                }
            }
        }
    }

    /// Installs the wildcard rule for our right prefix: admin authentication, not shared, short-lived.
    public static func ensureRightDefinition() {
        let name = AgentGuardConfig.authorizationRightPrefix
        if AuthorizationRightGet(name, nil) == errAuthorizationSuccess { return }
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else { return }
        defer { AuthorizationFree(reference, []) }
        let rule: [String: Any] = [
            "class": "user",
            "group": "admin",
            "shared": false,
            "timeout": 30,
            "version": 1,
            "comment": "AgentGuard: confirm one permission change",
        ]
        _ = AuthorizationRightSet(reference, name, rule as CFDictionary, "AgentGuard 需要确认这次权限变更" as CFString, nil, nil)
    }
}

/// Helper-side verification used by HelperService.
public struct SystemAuthorizationVerifier: AuthorizationVerifier {
    public init() {}

    public func verify(token: Data?, scope: String, summary: [String]) -> Bool {
        guard let token, token.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { token.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &reference) == errAuthorizationSuccess, let reference else { return false }
        defer { AuthorizationFree(reference, [.destroyRights]) }
        return UserAuthorization.copyRights(reference, right: UserAuthorization.rightName(scope), prompt: nil, flags: [.extendRights]) == errAuthorizationSuccess
    }
}
#endif
