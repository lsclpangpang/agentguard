import Foundation
import Testing
@testable import GuardCore

@Suite struct LaunchTests {
    typealias F = Fixtures

    func agentProfile() -> Profile {
        var p = F.profile(files: [F.rw("/Users/me/easyops")])
        p.launch = LaunchSettings(executable: "/Library/Application Support/AgentGuard Releases/knodo/knodo-agentd", arguments: ["run"], workingDirectory: nil,
                                  originalLabel: "com.knodo.local-agent", restartOnCleanExit: true)
        return p
    }

    @Test func launchSettingsAreCompiledAndChangesExpand() throws {
        let policy = try F.compile(agentProfile())
        #expect(policy.launch?.executable == "/Library/Application Support/AgentGuard Releases/knodo/knodo-agentd")
        var changed = agentProfile()
        changed.launch?.executable = "/Users/me/evil"
        let diff = PolicyDiff(from: policy, to: try F.compile(changed))
        #expect(diff.requiresAuthorization)
        // The launch target is also a read grant and an exec grant, so the swap shows up there too.
        #expect(diff.summaryLines == [
            "- 只读文件 /Library/Application Support/AgentGuard Releases/knodo/knodo-agentd",
            "+ 只读文件 /Users/me/evil",
            "~ 启动程序：/Users/me/evil run（替换原启动项 com.knodo.local-agent）",
            "- 可执行 /Library/Application Support/AgentGuard Releases/knodo/knodo-agentd",
            "+ 可执行 /Users/me/evil",
        ])
    }

    @Test func launchExecutableMustNotBeWritable() {
        var p = agentProfile()
        p.launch?.executable = "/Users/me/easyops/agent"
        #expect(throws: CompileError.mutableExecutableWithoutHash("/Users/me/easyops/agent")) { try F.compile(p) }
    }

    @Test func agentPlanUsesStateDirectoryAndNullStdin() throws {
        var env = F.environment
        env.stateRoot = "/Library/Application Support/AgentGuard State"
        let policy = try F.compile(agentProfile(), environment: env)
        let plan = try LaunchPlan.agent(policy: policy, inheritedEnvironment: ["PATH": "/usr/bin:/bin", "HOME": "/Users/me"])
        #expect(plan.executable == "/Library/Application Support/AgentGuard Releases/knodo/knodo-agentd")
        #expect(plan.arguments == ["run"])
        #expect(plan.workingDirectory == "/Library/Application Support/AgentGuard State/knodo")
        #expect(plan.stdinFromNull)
        #expect(plan.environment["TMPDIR"] == "/Library/Application Support/AgentGuard State/knodo/tmp")
        #expect(plan.environment["AGENTGUARD_PROFILE"] == "knodo")
        #expect(plan.environment["AGENTGUARD_REVISION"] == "1")
    }

    @Test func agentPlanRequiresLaunchSettings() throws {
        #expect(throws: LaunchError.noLaunchSettings) { try LaunchPlan.agent(policy: try F.compile(F.profile()), inheritedEnvironment: [:]) }
    }

    @Test func interactivePlanKeepsTerminalAndUserEnvironmentButDropsLoaderVariables() throws {
        let policy = try F.compile(F.profile())
        let inherited = ["TERM": "xterm-256color", "ANTHROPIC_API_KEY": "k", "DYLD_INSERT_LIBRARIES": "/x.dylib", "DYLD_LIBRARY_PATH": "/y", "LD_PRELOAD": "/z"]
        let plan = try LaunchPlan.interactive(policy: policy, command: ["claude", "--resume"], workingDirectory: "/Users/me/easyops", inheritedEnvironment: inherited)
        #expect(plan.executable == "claude")
        #expect(plan.arguments == ["--resume"])
        #expect(plan.workingDirectory == "/Users/me/easyops")
        #expect(!plan.stdinFromNull)
        #expect(plan.environment["TERM"] == "xterm-256color")
        #expect(plan.environment["ANTHROPIC_API_KEY"] == "k")
        #expect(plan.environment.keys.allSatisfy { !$0.hasPrefix("DYLD_") && $0 != "LD_PRELOAD" })
        #expect(plan.environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
    }

    @Test func interactivePlanRejectsEmptyCommand() throws {
        #expect(throws: LaunchError.emptyCommand) {
            try LaunchPlan.interactive(policy: try F.compile(F.profile()), command: [], workingDirectory: "/", inheritedEnvironment: [:])
        }
    }

    @Test func launchAgentPropertyList() throws {
        let definition = LaunchAgentDefinition(labelPrefix: "com.example.agentguard.managed", launcherPath: "/Applications/AgentGuard.app/Contents/MacOS/agentguard-launcher",
                                               profileID: "knodo", runAtLoad: true, restartOnCleanExit: false, throttleInterval: 10,
                                               logDirectory: "/Library/Logs/AgentGuard")
        let plist = try #require(try PropertyListSerialization.propertyList(from: definition.xmlData(), format: nil) as? [String: Any])
        #expect(plist["Label"] as? String == "com.example.agentguard.managed.knodo")
        #expect(plist["ProgramArguments"] as? [String] == ["/Applications/AgentGuard.app/Contents/MacOS/agentguard-launcher", "launch", "knodo"])
        #expect(plist["RunAtLoad"] as? Bool == true)
        #expect((plist["KeepAlive"] as? [String: Any])?["SuccessfulExit"] as? Bool == false)
        #expect(plist["LimitLoadToSessionType"] as? String == "Aqua")
        #expect(plist["ThrottleInterval"] as? Int == 10)
        #expect(plist["StandardErrorPath"] as? String == "/Library/Logs/AgentGuard/knodo.log")
        #expect(definition.label == "com.example.agentguard.managed.knodo")
    }

    /// `KeepAlive = true` 会让 launchd 要求一条可校验的 LWCR；指向 App 包内 ad-hoc 签名的启动器时
    /// 这条要求满足不了，posix_spawn 直接 0xd/EX_CONFIG，任务永远起不来。所以两种情况都只声明
    /// “异常退出后重来”。
    @Test func keepAliveNeverAsksForAnUnconditionalConstraint() throws {
        for restartOnCleanExit in [true, false] {
            let definition = LaunchAgentDefinition(labelPrefix: "p", launcherPath: "/l", profileID: "knodo", runAtLoad: true,
                                                   restartOnCleanExit: restartOnCleanExit, throttleInterval: 10, logDirectory: "/tmp")
            let plist = try #require(try PropertyListSerialization.propertyList(from: definition.xmlData(), format: nil) as? [String: Any])
            #expect(plist["KeepAlive"] as? Bool == nil)
            #expect((plist["KeepAlive"] as? [String: Bool])?["SuccessfulExit"] == false)
        }
    }
}
