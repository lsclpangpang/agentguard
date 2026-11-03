import Foundation

public enum LaunchError: Error, Equatable, Sendable {
    case noLaunchSettings
    case emptyCommand
}

/// Everything the launcher or `guard run` needs to exec the target after entering the sandbox.
public struct LaunchPlan: Equatable, Sendable {
    public var executable: String
    public var arguments: [String]
    public var environment: [String: String]
    public var workingDirectory: String
    public var stdinFromNull: Bool

    public static let defaultPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    public static func agent(policy: EffectivePolicy, inheritedEnvironment: [String: String]) throws -> LaunchPlan {
        guard let launch = policy.launch else { throw LaunchError.noLaunchSettings }
        return LaunchPlan(
            executable: launch.executable,
            arguments: launch.arguments,
            environment: environment(for: policy, inherited: inheritedEnvironment),
            workingDirectory: launch.workingDirectory ?? policy.stateDirectory ?? "/",
            stdinFromNull: true
        )
    }

    public static func interactive(policy: EffectivePolicy, command: [String], workingDirectory: String, inheritedEnvironment: [String: String]) throws -> LaunchPlan {
        guard let executable = command.first else { throw LaunchError.emptyCommand }
        return LaunchPlan(
            executable: executable,
            arguments: Array(command.dropFirst()),
            environment: environment(for: policy, inherited: inheritedEnvironment),
            workingDirectory: workingDirectory,
            stdinFromNull: false
        )
    }

    /// Passes the user environment through, minus dynamic-loader injection variables.
    static func environment(for policy: EffectivePolicy, inherited: [String: String]) -> [String: String] {
        var env = inherited.filter { key, _ in !key.hasPrefix("DYLD_") && !key.hasPrefix("LD_") }
        if env["PATH"]?.isEmpty ?? true { env["PATH"] = defaultPath }
        if let state = policy.stateDirectory { env["TMPDIR"] = state + "/tmp" }
        env["AGENTGUARD_PROFILE"] = policy.profileID
        env["AGENTGUARD_REVISION"] = String(policy.revision)
        return env
    }
}

/// The root-owned LaunchAgent that replaces an object's original startup item.
public struct LaunchAgentDefinition: Equatable, Sendable {
    public var labelPrefix: String
    public var launcherPath: String
    public var profileID: String
    public var runAtLoad: Bool
    public var restartOnCleanExit: Bool
    public var throttleInterval: Int
    public var logDirectory: String
    /// 启动器二进制的短指纹。launchd 会把首次注册时的代码约束（LWCR）记进 BTM，而 BTM 不会
    /// 因为重写 plist 而刷新它；ad-hoc 重签后约束失配，任务以 EX_CONFIG(78) 起不来。
    /// 把指纹写进 label 就能保证每次重编都拿到一条全新的记录，旧记录随旧 label 一起清掉。
    public var generation: String

    public init(labelPrefix: String, launcherPath: String, profileID: String, runAtLoad: Bool, restartOnCleanExit: Bool, throttleInterval: Int, logDirectory: String, generation: String = "") {
        self.labelPrefix = labelPrefix
        self.launcherPath = launcherPath
        self.profileID = profileID
        self.runAtLoad = runAtLoad
        self.restartOnCleanExit = restartOnCleanExit
        self.throttleInterval = throttleInterval
        self.logDirectory = logDirectory
        self.generation = generation
    }

    public var label: String {
        generation.isEmpty ? labelPrefix + "." + profileID : labelPrefix + "." + profileID + "." + generation
    }

    public func xmlData() throws -> Data {
        let log = logDirectory + "/" + profileID + ".log"
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [launcherPath, "launch", profileID],
            "RunAtLoad": runAtLoad,
            // 不要用 KeepAlive=true：对指向 App 包内二进制的 legacy agent，launchd 会要求一条
            // 可校验的 LWCR，而 ad-hoc 签名满足不了，结果就是 posix_spawn 直接 0xd/EX_CONFIG
            // 起不来。{SuccessfulExit: false} 一样能在异常退出后拉起，静态约束却宽松得多。
            "KeepAlive": ["SuccessfulExit": false] as Any,
            "LimitLoadToSessionType": "Aqua",
            "ThrottleInterval": throttleInterval,
            "StandardOutPath": log,
            "StandardErrorPath": log,
            "ProcessType": "Background",
        ]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }
}
