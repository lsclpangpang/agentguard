import Foundation
import GuardCore

/// Shared start sequence for `guard run` and the LaunchAgent launcher:
/// register with the Helper, close inherited descriptors, enter the sandbox, exec.
public enum ManagedStart {
    public enum Kind {
        case interactive(command: [String], workingDirectory: String)
        case agent
    }

    public static func config(uid: uid_t) throws -> AgentGuardConfig {
        guard let home = UserAccount.home(uid: uid) else { throw PlatformError.notFound("用户 \(uid) 的主目录") }
        return AgentGuardConfig(home: home, uid: Int(uid), homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix())
    }

    public static func run(profileID: String, kind: Kind) throws -> Never {
        #if os(macOS)
        let config = try config(uid: getuid())
        guard let profile = try config.store.latest(profileID) else { throw PlatformError.helper(HelperFailure.message(for: "unknown_profile")) }
        let response = try HelperClient().send(.registerInstance(profileID: profileID, revision: profile.revision))
        guard case let .registered(_, sbpl) = response else {
            if case let .failure(code) = response { throw PlatformError.helper(HelperFailure.message(for: code)) }
            throw PlatformError.helper("意外的响应")
        }
        let policy = try PolicyCompiler(environment: config.environment).compile(profile, catalog: TemplateCatalog(config.templates))
        let environment = ProcessInfo.processInfo.environment
        let plan: LaunchPlan
        switch kind {
        case let .interactive(command, workingDirectory):
            plan = try LaunchPlan.interactive(policy: policy, command: command, workingDirectory: workingDirectory, inheritedEnvironment: environment)
        case .agent:
            plan = try LaunchPlan.agent(policy: policy, inheritedEnvironment: environment)
        }
        // 是否生效由 Helper 从外部用 sandbox_check 核对这个进程，进程自己不上报：
        // 规则编译通过不代表内核真的按它拦截，受管进程的自述也不能当证据。
        Exec.closeInheritedDescriptors()
        try Sandbox.apply(sbpl)
        try Exec.replaceProcess(with: plan)
        #else
        throw PlatformError.unsupported
        #endif
    }
}
