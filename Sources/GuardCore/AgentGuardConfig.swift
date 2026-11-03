/// Production identifiers and locations shared by the app, CLI, launcher and Helper.
public struct AgentGuardConfig: Sendable {
    public static let bundleIdentifier = "com.lsclpangpang.agentguard"
    public static let helperServiceName = "com.lsclpangpang.agentguard.helper"
    public static let helperPlistName = "com.lsclpangpang.agentguard.helper.plist"
    public static let labelPrefix = "com.lsclpangpang.agentguard.managed"

    /// The privileged collector is the process that holds Full Disk Access. It is installed outside
    /// the app bundle and never replaced by an app rebuild, so its TCC identity stays valid; the
    /// bundled copy is only source material for the first install.
    public static let collectorLabel = "com.lsclpangpang.agentguard.collector"
    public static let collectorPlistName = "com.lsclpangpang.agentguard.collector.plist"
    public static let collectorSocketPath = "/var/run/com.lsclpangpang.agentguard.collector.sock"
    /// 文件事件（open/close/…）要占采集流量的九成以上，只有受限学习需要。Helper 在有学习模式
    /// 配置档时写下这个标记，采集器据此决定要不要订阅，切换后几秒内生效。
    public static let collectorFileEventsFlagPath = "/var/run/com.lsclpangpang.agentguard.collector.file-events"
    public static let privilegedHelperToolsDirectory = "/Library/PrivilegedHelperTools"
    public static let systemLaunchDaemonsDirectory = "/Library/LaunchDaemons"
    public static var collectorPath: String { privilegedHelperToolsDirectory + "/" + collectorLabel }
    public static var collectorPlistPath: String { systemLaunchDaemonsDirectory + "/" + collectorPlistName }
    /// Authorization rights are `<prefix><scope>`; the Helper installs a wildcard rule for the prefix.
    public static let authorizationRightPrefix = "com.lsclpangpang.agentguard."

    public static func signingIdentifier(_ role: CallerRole) -> String {
        switch role {
        case .app: return bundleIdentifier
        case .cli: return bundleIdentifier + ".cli"
        case .launcher: return bundleIdentifier + ".launcher"
        }
    }

    public var home: String
    public var uid: Int
    public var homebrewPrefix: String
    public var configRoot = "/Library/Application Support/AgentGuard"
    public var stateRoot = "/Library/Application Support/AgentGuard State"
    public var releasesRoot = "/Library/Application Support/AgentGuard Releases"
    public var appBundle = "/Applications/AgentGuard.app"
    public var logDirectory = "/Library/Logs/AgentGuard"

    public init(home: String, uid: Int, homebrewPrefix: String) {
        self.home = home
        self.uid = uid
        self.homebrewPrefix = homebrewPrefix
    }

    public var launcherPath: String { appBundle + "/Contents/MacOS/agentguard-launcher" }

    public var environment: CompileEnvironment {
        CompileEnvironment(
            homeDirectory: home,
            protectedPaths: [configRoot],
            helperServiceName: Self.helperServiceName,
            resolver: AliasResolver.macOSDefault,
            caseInsensitive: true,
            allowsNestedReadOnly: false,
            writeProtectedPaths: [releasesRoot, appBundle, home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"],
            stateRoot: stateRoot,
            // To be confirmed by the M0 capability check on each supported macOS version.
            baseRules: ["(import \"bsd.sb\")"]
        )
    }

    public var templates: [Template] {
        BuiltinTemplates.all(TemplateContext(home: home, uid: uid, homebrewPrefix: homebrewPrefix))
    }

    public var helperSettings: HelperSettings {
        HelperSettings(labelPrefix: Self.labelPrefix, launcherPath: launcherPath, logDirectory: logDirectory, throttleInterval: 10)
    }

    public var store: ProfileStore {
        ProfileStore(root: configRoot, files: LocalFileStore())
    }
}
