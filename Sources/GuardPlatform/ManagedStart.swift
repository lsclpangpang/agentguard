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
        guard case let .registered(instance, sbpl) = response else {
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
        // 规则编译通过 = 这条修订确实能落到这个进程上，才算“验收通过”。
        // 必须在进沙箱之前上报：沙箱一旦生效，连 Helper 的 XPC 可能就被自己的规则拦掉了。
        // 装载失败会直接抛出、进程消失，状态随之回到“已停止”，不会留下错误的“已生效”。
        _ = try? HelperClient().send(.reportVerification(instance: instance, passed: true))
        Exec.closeInheritedDescriptors()
        try Sandbox.apply(sbpl)
        try Exec.replaceProcess(with: plan)
        #else
        throw PlatformError.unsupported
        #endif
    }
}
