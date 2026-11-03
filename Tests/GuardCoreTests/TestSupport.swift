import Foundation
@testable import GuardCore

enum Fixtures {
    static let appHash = String(repeating: "1", count: 40)
    static let cliHash = String(repeating: "2", count: 40)
    static let launcherHash = String(repeating: "3", count: 40)

    static let trust = CallerTrustPolicy(allowedUID: 501, identities: [
        .app: CodeIdentity(signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhashes: [appHash]),
        .cli: CodeIdentity(signingIdentifier: "com.example.agentguard.cli", teamIdentifier: nil, cdhashes: [cliHash]),
        .launcher: CodeIdentity(signingIdentifier: "com.example.agentguard.launcher", teamIdentifier: nil, cdhashes: [launcherHash]),
    ])

    static let appCaller = CallerIdentity(uid: 501, signingIdentifier: "com.example.agentguard.app", teamIdentifier: nil, cdhash: appHash, managedInstance: nil)
    static let cliCaller = CallerIdentity(uid: 501, signingIdentifier: "com.example.agentguard.cli", teamIdentifier: nil, cdhash: cliHash, managedInstance: nil)
    static let launcherCaller = CallerIdentity(uid: 501, signingIdentifier: "com.example.agentguard.launcher", teamIdentifier: nil, cdhash: launcherHash, managedInstance: nil)

    static let environment = CompileEnvironment(
        homeDirectory: "/Users/me",
        protectedPaths: ["/Library/Application Support/AgentGuard"],
        helperServiceName: "com.example.agentguard.helper",
        resolver: AliasResolver.macOSDefault,
        caseInsensitive: true,
        allowsNestedReadOnly: false,
        writeProtectedPaths: ["/Applications/AgentGuard.app"],
        stateRoot: nil,
        baseRules: []
    )

    static let helperSettings = HelperSettings(
        labelPrefix: "com.example.agentguard.managed",
        launcherPath: "/Applications/AgentGuard.app/Contents/MacOS/agentguard-launcher",
        logDirectory: "/Library/Logs/AgentGuard",
        throttleInterval: 10
    )

    static func profile(
        files: [FileGrant] = [],
        exec: [ExecGrant] = [],
        network: NetworkPolicy = NetworkPolicy(),
        mode: Mode = .enforce,
        templates: [TemplateRef] = [],
        revision: Int = 1,
        unrestrictedExec: Bool = false,
        extraRules: [String] = []
    ) -> Profile {
        Profile(id: "knodo", revision: revision, mode: mode, templates: templates, files: files, exec: exec, network: network,
                unrestrictedExec: unrestrictedExec, extraRules: extraRules)
    }

    static func compile(_ profile: Profile, templates: [Template] = [], environment: CompileEnvironment = environment) throws -> EffectivePolicy {
        try PolicyCompiler(environment: environment).compile(profile, catalog: TemplateCatalog(templates))
    }

    static func rw(_ path: String) -> FileGrant { FileGrant(path: path, kind: .directory, access: .readWrite) }
    static func ro(_ path: String) -> FileGrant { FileGrant(path: path, kind: .directory, access: .readOnly) }
    static func roFile(_ path: String) -> FileGrant { FileGrant(path: path, kind: .file, access: .readOnly) }
    static func rwFile(_ path: String) -> FileGrant { FileGrant(path: path, kind: .file, access: .readWrite) }
}

extension CallerIdentity {
    func managed(by instance: Int) -> CallerIdentity {
        var copy = self
        copy.managedInstance = instance
        return copy
    }
}
