/// A launch item found in a LaunchAgents directory, reduced to what the survey compares.
public struct LaunchEntry: Equatable, Sendable {
    public var label: String
    public var path: String
    public var executable: String
    public var arguments: [String]

    public init(label: String, path: String, executable: String, arguments: [String]) {
        self.label = label
        self.path = path
        self.executable = executable
        self.arguments = arguments
    }
}

/// A launch item AgentGuard set aside because it started a managed program outside AgentGuard.
public struct DisabledLaunchEntry: Equatable, Sendable {
    public var label: String
    public var location: String
    /// The profile it was disabled for.
    public var profileID: String?

    public init(label: String, location: String, profileID: String? = nil) {
        self.label = label
        self.location = location
        self.profileID = profileID
    }
}

/// One program's startup routes and running copies, sorted into managed, not managed and unknown.
public struct ProgramSurvey: Equatable, Sendable {
    public enum Finding: Equatable, Sendable {
        /// Another launch item starts the program without AgentGuard.
        case otherLaunchEntry(LaunchEntry)
        /// The item that the takeover is set to replace is still in place.
        case originalNotReplaced(LaunchEntry)
        case unmanagedCopies([Int32])
        /// Running copies whose process tree is not fully known.
        case untrackedCopies([Int])
        case unverifiedLegacyRules([String])
        case runAtLoginNotApplied
    }

    public var profileID: String
    /// Executables recognised as this program: the managed programs and the launch executable.
    public var targets: [String]
    public var managedLaunch: Bool
    public var runningInstances: [Int]
    public var findings: [Finding]
    public var disabled: [DisabledLaunchEntry]

    public var isOrganized: Bool { findings.isEmpty }
}

/// Sorts what is installed and running into per-program summaries for the tidy-up flow.
///
/// A launch item belongs to a program only when it starts one of the program's executables, either
/// directly or as an argument (a shell running a script). Names are never compared: a similar name
/// is no reason to touch someone's launch item.
public enum InstallationSurvey {
    public static func survey(profiles: [Profile], entries: [LaunchEntry], disabled: [DisabledLaunchEntry], status: [ProfileStatusReport],
                              resolver: any PathResolver, caseInsensitive: Bool) -> [ProgramSurvey] {
        profiles.sorted { $0.id < $1.id }.map { profile in
            let targets = Array(Set(profile.programs + (profile.launch.map { [$0.detectionTarget] } ?? []))).sorted()
            let canonicalTargets = targets.compactMap { try? CanonicalPath($0, resolver: resolver) }
            func startsTarget(_ entry: LaunchEntry) -> Bool {
                ([entry.executable] + entry.arguments).contains { word in
                    guard word.hasPrefix("/"), let path = try? CanonicalPath(word, resolver: resolver) else { return false }
                    return canonicalTargets.contains { $0.isSame(as: path, caseInsensitive: caseInsensitive) }
                }
            }
            let report = status.first { $0.profileID == profile.id }
            let original = profile.launch?.originalLabel
            var findings: [ProgramSurvey.Finding] = []
            for entry in entries {
                if entry.label == original {
                    // Still in place: the takeover has not happened yet (or was undone).
                    if report?.launchAgent?.registered == true || report?.launchAgent?.canRestoreOriginal == true {
                        findings.append(.otherLaunchEntry(entry))
                    } else {
                        findings.append(.originalNotReplaced(entry))
                    }
                } else if startsTarget(entry) {
                    findings.append(.otherLaunchEntry(entry))
                }
            }
            if let unmanaged = report?.unmanagedProcesses, !unmanaged.isEmpty { findings.append(.unmanagedCopies(unmanaged)) }
            if let untracked = report?.untrackedInstances, !untracked.isEmpty { findings.append(.untrackedCopies(untracked)) }
            let legacy = LegacyRuleAnalysis(rules: profile.extraRules, resolver: resolver, caseInsensitive: caseInsensitive)
            if legacy.hasUnverifiedFileRules { findings.append(.unverifiedLegacyRules(legacy.unverified)) }
            if let launch = profile.launch, let agent = report?.launchAgent, agent.problem == nil,
               agent.registered || agent.runAtLogin, agent.runAtLogin != launch.runAtLogin {
                findings.append(.runAtLoginNotApplied)
            }
            let ownDisabled = disabled.filter { $0.profileID == profile.id }
            return ProgramSurvey(profileID: profile.id, targets: targets, managedLaunch: profile.launch != nil,
                                 runningInstances: report?.runningInstances ?? [], findings: findings, disabled: ownDisabled)
        }
    }
}

extension ProgramSurvey.Finding {
    public var title: String {
        switch self {
        case let .otherLaunchEntry(entry): return "另一个启动项 \(entry.label) 会在 AgentGuard 之外启动它"
        case let .originalNotReplaced(entry): return "原启动项 \(entry.label) 仍在使用，启动程序时会由 AgentGuard 替换"
        case let .unmanagedCopies(pids): return "\(pids.count) 个副本没有经过 AgentGuard 运行（PID \(pids.map(String.init).joined(separator: "、"))）"
        case let .untrackedCopies(ids): return "运行副本 #\(ids.map(String.init).joined(separator: "、#")) 的子进程没有被完整跟踪"
        case let .unverifiedLegacyRules(rules): return "\(rules.count) 条旧规则无法核对，可能放开没有列出的访问"
        case .runAtLoginNotApplied: return "登录自启设置还没有应用"
        }
    }

    public var advice: String {
        switch self {
        case .otherLaunchEntry: return "停用它，只保留 AgentGuard 的启动入口；停用前会备份，可以随时恢复。"
        case .originalNotReplaced: return "在“启动方式”中点“启动程序”完成替换。"
        case .unmanagedCopies: return "结束这些副本，改从 AgentGuard 启动。"
        case .untrackedCopies: return "重启程序即可恢复完整跟踪。"
        case .unverifiedLegacyRules: return "逐条核对后移除，或改为文件访问中的具体授权。"
        case .runAtLoginNotApplied: return "在“启动方式”中应用登录设置。"
        }
    }
}
