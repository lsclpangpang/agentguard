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

    public init(labelPrefix: String, launcherPath: String, profileID: String, runAtLoad: Bool, restartOnCleanExit: Bool, throttleInterval: Int, logDirectory: String) {
        self.labelPrefix = labelPrefix
        self.launcherPath = launcherPath
        self.profileID = profileID
        self.runAtLoad = runAtLoad
        self.restartOnCleanExit = restartOnCleanExit
        self.throttleInterval = throttleInterval
        self.logDirectory = logDirectory
    }

    public var label: String { labelPrefix + "." + profileID }

    public func xmlData() throws -> Data {
        let log = logDirectory + "/" + profileID + ".log"
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [launcherPath, "launch", profileID],
            "RunAtLoad": runAtLoad,
            "KeepAlive": restartOnCleanExit ? true as Any : ["SuccessfulExit": false] as Any,
            "LimitLoadToSessionType": "Aqua",
            "ThrottleInterval": throttleInterval,
            "StandardOutPath": log,
            "StandardErrorPath": log,
            "ProcessType": "Background",
        ]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }
}
