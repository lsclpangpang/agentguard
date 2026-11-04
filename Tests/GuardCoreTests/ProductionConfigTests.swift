import Testing
@testable import GuardCore

@Suite struct ProductionConfigTests {
    typealias F = Fixtures

    @Test func writeProtectedPathsAllowReadingButNotWriting() throws {
        _ = try F.compile(F.profile(files: [F.ro("/Applications/AgentGuard.app")]))
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Applications/AgentGuard.app/Contents", protected: "/Applications/AgentGuard.app")) {
            try F.compile(F.profile(files: [F.rw("/Applications/AgentGuard.app/Contents")]))
        }
        #expect(throws: CompileError.overlapsProtectedPath(grant: "/Applications", protected: "/Applications/AgentGuard.app")) {
            try F.compile(F.profile(files: [F.rw("/Applications")]))
        }
    }

    @Test func writeProtectedPathsAreDeniedInRenderedRules() throws {
        let sbpl = SBPLRenderer(environment: F.environment).render(try F.compile(F.profile()))
        #expect(sbpl.contains("(deny file-write* (subpath \"/Applications/AgentGuard.app\"))"))
    }

    @Test func launchExecutableIsReadable() throws {
        var p = F.profile()
        p.launch = LaunchSettings(executable: "/opt/knodo/knodo-agentd", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: true)
        let policy = try F.compile(p)
        #expect(policy.files.contains(EffectiveFileGrant(path: "/opt/knodo/knodo-agentd", kind: .file, access: .readOnly, readsSecrets: false)))
    }

    @Test func productionEnvironmentCompilesAllBuiltinTemplates() throws {
        let config = AgentGuardConfig(home: "/Users/me", uid: 501, homebrewPrefix: "/opt/homebrew")
        let templates = config.templates
        var p = F.profile(templates: templates.map { TemplateRef(id: $0.id, version: $0.version) })
        p.launch = LaunchSettings(executable: config.releasesRoot + "/knodo/knodo-agentd", arguments: [], workingDirectory: nil, originalLabel: nil, restartOnCleanExit: true)
        let policy = try PolicyCompiler(environment: config.environment).compile(p, catalog: TemplateCatalog(templates))
        #expect(policy.stateDirectory == "/Library/Application Support/AgentGuard State/knodo")
        let sbpl = SBPLRenderer(environment: config.environment).render(policy)
        #expect(sbpl.contains("(deny mach-lookup (global-name \"\(AgentGuardConfig.helperServiceName)\"))"))
        #expect(sbpl.contains("(deny file-write* (subpath \"/Users/me/Library/LaunchAgents\"))"))
    }

    /// 用户点「文件访问 > 添加 > 只读…」选到受保护目录时，Helper 只回一个 `compile_error`。
    /// 这段话就是 App 用同一份生产 environment 本地重编译换回来的解释 —— 它必须指名两条路径，
    /// 否则界面又只剩一句“配置档无效”。
    @Test func productionConfigExplainsAGrantOnAProtectedPath() throws {
        let config = AgentGuardConfig(home: "/Users/me", uid: 501, homebrewPrefix: "/opt/homebrew")
        let profile = F.profile(files: [FileGrant(path: config.configRoot + "/profiles", kind: .directory, access: .readOnly)])
        do {
            _ = try PolicyCompiler(environment: config.environment)
                .compile(profile, catalog: TemplateCatalog(config.templates))
            Issue.record("落在 protectedPaths 里的授权必须被拒绝")
        } catch let error as CompileError {
            #expect(error.message.contains(config.configRoot + "/profiles"))
            #expect(error.message.contains("与受保护目录 \(config.configRoot) 重叠"))
        }
    }

    @Test func identifiersAreConsistent() {        #expect(AgentGuardConfig.helperServiceName == "com.lsclpangpang.agentguard.helper")
        #expect(AgentGuardConfig.signingIdentifier(.app) == "com.lsclpangpang.agentguard")
        #expect(AgentGuardConfig.signingIdentifier(.cli) == "com.lsclpangpang.agentguard.cli")
        #expect(AgentGuardConfig.signingIdentifier(.launcher) == "com.lsclpangpang.agentguard.launcher")
    }
}
