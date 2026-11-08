#if os(macOS)
import Foundation
import GuardCore
import GuardPlatform
import ServiceManagement

/// A deliberately narrow maintenance action. There is no arbitrary request/profile input and no
/// direct write to protected configuration. The installed App still has to authenticate an exact
/// Helper proposal; an intervening profile edit invalidates that proposal.
enum ProcessControlRepairCommand {
    enum RepairKind: Sendable {
        case processControl
        case goBuild

        var flag: String {
            switch self {
            case .processControl: return "--repair-process-control"
            case .goBuild: return "--repair-go-build"
            }
        }

        var title: String {
            switch self {
            case .processControl: return "任务取消与进程清理"
            case .goBuild: return "Go 构建"
            }
        }

        var detail: String {
            switch self {
            case .processControl: return ProcessControl.detail
            case .goBuild:
                return "只读 Go 工具链、用户 Go 配置和已有依赖缓存；读写 Go 编译缓存。"
            }
        }

        func isEnabled(in profile: Profile, home: String) -> Bool {
            switch self {
            case .processControl: return ProcessControl.isEnabled(in: profile)
            case .goBuild: return GoBuildPermissions.isEnabled(in: profile, home: home)
            }
        }

        func enable(in profile: inout Profile, config: AgentGuardConfig) throws {
            switch self {
            case .processControl: ProcessControl.enable(in: &profile)
            case .goBuild:
                profile = try GoBuildPermissions.validatedProfile(
                    from: profile, home: config.home, environment: config.environment,
                    catalog: TemplateCatalog(config.templates))
            }
        }
    }

    @MainActor
    static func run(arguments: [String], kind: RepairKind = .processControl) async -> Int32 {
        guard let profileID = arguments.first, ProfileID.isValid(profileID),
              arguments.count == 1 || (arguments.count == 2 && arguments[1] == "--restart") else {
            message("用法：AgentGuard \(kind.flag) <配置档> [--restart]")
            return 64
        }
        let restart = arguments.count == 2
        let uid = getuid()
        let config = AgentGuardConfig(home: UserAccount.home(uid: uid) ?? NSHomeDirectory(), uid: Int(uid),
                                      homebrewPrefix: AgentGuardConfig.detectHomebrewPrefix())
        do {
            guard try config.store.latest(profileID) != nil else {
                throw RepairError.message("配置档不存在：\(profileID)")
            }
            try await ensureCurrentHelper(for: kind)
            // Always read after the Helper update, and immediately before proposing. Never reuse a
            // diagnosis-time revision: the user may have saved other permissions in the meantime.
            guard var profile = try config.store.latest(profileID) else {
                throw RepairError.message("配置档不存在：\(profileID)")
            }
            let baseRevision = profile.revision
            if !kind.isEnabled(in: profile, home: config.home) {
                let original = profile
                try kind.enable(in: &profile, config: config)
                profile.revision += 1
                let response = try await send(.proposeChange(profile: profile))
                guard case let .pending(change) = response else { throw failure(response) }
                guard change.baseRevision == baseRevision, !change.summary.isEmpty, change.requiresAuthorization else {
                    throw RepairError.message("修复提案未能确认需要新增的权限；没有应用变更")
                }
                if case .goBuild = kind {
                    let compiler = PolicyCompiler(environment: config.environment)
                    let catalog = TemplateCatalog(config.templates)
                    let expected = PolicyDiff(from: try compiler.compile(original, catalog: catalog),
                                              to: try compiler.compile(profile, catalog: catalog))
                    guard change.digest == expected.digest else {
                        throw RepairError.message("后台服务的权限差异与已核对的 Go 范围不一致；没有应用变更")
                    }
                }
                message("将为 \(profileID) 保存以下变更：")
                change.summary.forEach(message)
                let restartNotice = restart ? "\n保存后将重启 \(profileID)，结束该程序当前运行的会话。" : ""
                let token = try await Task.detached {
                    try UserAuthorization.obtain(
                        scope: HelperService.authorizationScope(forChange: change.id),
                        prompt: "AgentGuard 将修复 \(profileID) 的\(kind.title)权限：\n"
                            + kind.detail + "\n" + change.summary.joined(separator: "\n") + restartNotice)
                }.value
                let approval = try await send(.approveChange(changeID: change.id, digest: change.digest, authorization: token))
                guard case let .applied(revision) = approval else { throw failure(approval) }
                message("权限已保存为修订 \(revision)。")
            } else {
                message("当前修订已包含\(kind.title)权限。")
            }
            if restart {
                let status = try await send(.status, timeout: 10)
                guard case let .status(beforeRestart) = status,
                      let before = beforeRestart.profiles.first(where: { $0.profileID == profileID }) else {
                    throw failure(status)
                }
                let previousInstances = Set(before.runningInstances)
                message("正在重启 \(profileID)，应用已保存的权限…")
                let response = try await send(.restartManagedInstance(profileID: profileID))
                switch response {
                case .failure:
                    throw failure(response)
                case let .completed(warnings):
                    warnings.forEach { message("提示：\($0)") }
                case let .report(report):
                    report.notes.forEach(message)
                    report.problems.forEach { message("提示：\($0)") }
                case .restartManaged, .ok:
                    break
                default:
                    throw RepairError.message("重启返回了未识别的响应；请检查当前运行状态")
                }
                try await confirmRestart(profileID: profileID, previousInstances: previousInstances, config: config, kind: kind)
            } else {
                message("重新启动 \(profileID) 后，新权限才会生效。")
            }
            return 0
        } catch {
            message("修复未完成：\(error)")
            return 1
        }
    }

    private static func send(_ request: HelperRequest, timeout: TimeInterval = 30) async throws -> HelperResponse {
        try await Task.detached { try HelperClient().send(request, timeout: timeout) }.value
    }

    @MainActor
    private static func ensureCurrentHelper(for kind: RepairKind) async throws {
        let directory = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).deletingLastPathComponent().path
        guard let expectedCodeHash = try? CodeSigning.validatedCDHash(
            atPath: directory + "/agentguard-helper", expectedIdentifier: AgentGuardConfig.helperServiceName) else {
            throw RepairError.message("无法核对 App 内后台组件的签名；没有修改权限或重启任何服务")
        }
        func isCurrent(_ report: StatusReport) -> Bool {
            ComponentVersionStatus.helper(protocolVersion: report.helperProtocol, requiredProtocol: HelperProtocol.version,
                                          runtimeCodeHash: report.helperRuntimeCodeHash, bundledCodeHash: expectedCodeHash) == .current
        }
        if case let .status(report)? = try? await send(.status, timeout: 5),
           isCurrent(report) { return }
        guard case .processControl = kind else {
            throw RepairError.message("后台服务暂未就绪；没有修改权限或重启任何服务，请稍后重试")
        }
        let service = SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName)
        guard service.status != .requiresApproval else {
            throw RepairError.message("需要在“系统设置 > 通用 > 登录项 > 允许在后台”中允许 AgentGuard")
        }
        message("正在更新后台服务，以处理权限变更…")
        if service.status == .enabled { try await service.unregister() }
        try service.register()
        for _ in 0..<30 {
            if case let .status(report)? = try? await send(.status, timeout: 2),
               isCurrent(report) { return }
            if service.status == .requiresApproval {
                throw RepairError.message("后台服务已登记，需要在系统设置中允许 AgentGuard")
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw RepairError.message("尚未收到新版后台服务的确认；没有修改权限")
    }

    private static func confirmRestart(profileID: String, previousInstances: Set<Int>, config: AgentGuardConfig, kind: RepairKind) async throws {
        for _ in 0..<20 {
            if case let .status(report)? = try? await send(.status, timeout: 5),
               let profile = report.profiles.first(where: { $0.profileID == profileID }),
               let saved = try config.store.latest(profileID),
               kind.isEnabled(in: saved, home: config.home),
               profile.savedRevision == saved.revision,
               profile.runtimeRevisionState == .applied(running: true),
               previousInstances.isDisjoint(with: profile.runningInstances),
               !profile.runtimeInstances.isEmpty,
               profile.runtimeInstances.allSatisfy({ $0.revision == saved.revision && $0.verified == true }) {
                message("已确认 \(profileID) 正在使用修订 \(saved.revision)，当前副本的权限检查通过。")
                if !profile.untrackedInstances.isEmpty {
                    message("历史进程跟踪仍有缺口，已保留原有提示。")
                }
                return
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw RepairError.message("权限已保存，但尚未确认重启后的运行副本；请检查程序状态")
    }

    private static func failure(_ response: HelperResponse) -> RepairError {
        if case let .failure(code) = response { return .message(HelperFailure.message(for: code)) }
        return .message("后台服务返回了未识别的响应")
    }

    private static func message(_ text: String) {
        print(text)
        fflush(stdout)
    }

    private enum RepairError: Error, CustomStringConvertible {
        case message(String)
        var description: String {
            switch self { case let .message(text): return text }
        }
    }
}
#endif
