#if os(macOS)
import AppKit
import Foundation
import GuardCore
import GuardPlatform
import ServiceManagement

/// Actions added for the task-based screens: stopping one run, startup routes, decisions on
/// pending items, activity, the app's own login item, and uninstalling.
extension AppModel {
    // MARK: Running

    /// Stops the managed copies for this login only. The login setting is untouched, so the next
    /// login starts the program again if it is set to.
    func stopManaged(_ id: String) {
        let running = status(for: id)?.runningInstances ?? []
        var lines = running.isEmpty ? ["结束 \(id) 仍在运行的受管进程（如果有）"]
            : ["结束 \(id) 正在运行的 \(running.count) 个副本（#\(running.map(String.init).joined(separator: "、#"))）及其子进程"]
        lines.append("本次登录期间不会自动重新启动")
        if profile(id)?.launch?.runAtLogin == true { lines.append("登录自启保持开启：下次登录 Mac 时仍会自动启动") }
        lines.append("正在进行的任务会被中断")
        Task {
            guard await askConfirmation("停止 \(id) 的本次运行", lines) else { return }
            await sendAsync(.stopManaged(profileID: id))
        }
    }

    /// Applies the saved login setting to the launch item without stopping the program.
    func applyLoginSetting(_ id: String) {
        Task { await sendAsync(.applyLoginSetting(profileID: id)) }
    }

    /// Saves the login setting and applies it right away; whether the program runs now is not changed.
    func setRunAtLogin(_ enabled: Bool, for id: String) {
        guard var profile = profile(id), var launch = profile.launch, launch.runAtLogin != enabled else { return }
        launch.runAtLogin = enabled
        profile.launch = launch
        profile.revision += 1
        Task {
            guard case .applied = await submitAsync(profile) else { return }
            await sendAsync(.applyLoginSetting(profileID: id))
        }
    }

    // MARK: Startup routes

    /// Launch items, disabled items and status sorted per program, for the tidy-up screen.
    func survey() async -> [ProgramSurvey] {
        let files = LaunchItemFiles(home: config.home, configRoot: config.configRoot, launcherPath: config.launcherPath,
                                    labelPrefix: AgentGuardConfig.labelPrefix)
        let disabledDirectory = files.backupDirectory + "/disabled"
        let found = await Task.detached { () -> ([LaunchEntry], [DisabledLaunchEntry]) in
            let entries = ((try? files.originals()) ?? []).map {
                LaunchEntry(label: $0.label, path: $0.path, executable: $0.executable, arguments: $0.arguments)
            }
            return (entries, LaunchItemController.disabledItems(in: disabledDirectory))
        }.value
        let profiles = (report?.profiles ?? []).compactMap { profile($0.profileID) }
        return InstallationSurvey.survey(profiles: profiles, entries: found.0, disabled: found.1, status: report?.profiles ?? [],
                                         resolver: config.environment.resolver, caseInsensitive: config.environment.caseInsensitive)
    }

    func disableLaunchItem(_ entry: LaunchEntry, for id: String) async -> Bool {
        let lines = ["备份 \(entry.path)", "停止并移除启动项 \(entry.label)：它不会再在 AgentGuard 之外启动程序",
                     "之后可以在“整理现有安装”中恢复它"]
        guard await askConfirmation("停用启动项 \(entry.label)", lines) else { return false }
        return await Task.detached {
            do {
                let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forDisabling: entry.label),
                                                         prompt: "AgentGuard 将停用启动项 \(entry.label)")
                return await self.sendAsync(.disableLaunchItem(profileID: id, label: entry.label, path: entry.path, authorization: token))
            } catch {
                await MainActor.run { self.lastError = "\(error)" }
                return false
            }
        }.value
    }

    func restoreLaunchItem(_ entry: DisabledLaunchEntry) async -> Bool {
        let lines = ["把 \(entry.label) 放回 \(entry.location) 并加载", "它会在 AgentGuard 之外启动程序，不受这里的权限限制"]
        guard await askConfirmation("恢复启动项 \(entry.label)", lines) else { return false }
        return await Task.detached {
            do {
                let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forRestoring: entry.label),
                                                         prompt: "AgentGuard 将恢复启动项 \(entry.label)，它将不受限制地运行")
                return await self.sendAsync(.restoreLaunchItem(label: entry.label, authorization: token))
            } catch {
                await MainActor.run { self.lastError = "\(error)" }
                return false
            }
        }.value
    }

    // MARK: Activity

    func loadActivity(_ id: String) {
        Task.detached {
            let response = try? HelperClient().send(.activity(profileID: id), timeout: 20)
            if case let .activity(log) = response { await MainActor.run { self.activity[id] = log } }
        }
    }

    /// Keeps a blocked access blocked, or archives a suggestion, without changing any permission.
    func decide(_ item: PendingItem, _ decision: SuggestionDecision, for id: String) {
        decide(item.suggestion, decision, for: id)
    }

    func decide(_ suggestion: Suggestion, _ decision: SuggestionDecision, for id: String) {
        Task {
            await sendAsync(.decide(profileID: id, suggestion: suggestion, decision: decision))
            if decision == .keepBlocked { lastNotice = "已保持阻止：\(suggestion.summary)。权限没有改变，相同的访问以后会归入这条记录。" }
            loadActivity(id)
        }
    }

    // MARK: Permissions

    /// A complete command to paste into Terminal, without placeholders; nil when no program is known yet.
    func command(for profile: Profile) -> String? {
        guard let target = profile.launch?.executable ?? profile.programs.first ?? profile.exec.first?.path else { return nil }
        let guardPath = config.appBundle + "/Contents/MacOS/guard"
        var command = LaunchArguments.format([guardPath, "run", profile.id, "--", target] + (profile.launch?.arguments ?? []))
        let directory = profile.launch?.workingDirectory
            ?? profile.files.first { $0.access == .readWrite && $0.kind == .directory && !$0.pattern }?.path
        if let directory { command = "cd " + LaunchArguments.format([directory]) + " && " + command }
        return command
    }

    func overview(_ profile: Profile) -> PermissionOverview {
        EffectivePermissions.overview(of: profile, templates: templates, environment: config.environment)
    }

    func removeExec(_ path: String, from id: String) {
        edit(id) { profile in profile.exec.removeAll { $0.path == path } }
    }

    func setRecordsMoreActivity(_ enabled: Bool, in id: String) {
        edit(id) { $0.mode = enabled ? .restrictedLearning : .enforce }
    }

    // MARK: AgentGuard itself

    var opensAtLogin: Bool { SMAppService.mainApp.status == .enabled }

    func setOpensAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            lastError = nil
        } catch {
            lastError = (enabled ? "未能设置登录时打开 AgentGuard：" : "未能取消登录时打开 AgentGuard：") + error.localizedDescription
        }
        if enabled, SMAppService.mainApp.status == .requiresApproval {
            lastWarning = "请在“系统设置 > 通用 > 登录项”中允许 AgentGuard。"
            SMAppService.openSystemSettingsLoginItems()
        }
        objectWillChange.send()
    }

    /// A text report of the installation for troubleshooting; contains no file contents.
    func diagnosticsText() -> String {
        var lines = ["AgentGuard \(AgentGuardVersion.current)", "生成时间：\(ISO8601DateFormatter().string(from: Date()))",
                     "Helper 可连接：\(helperReachable ? "是" : "否")", "Helper 协议：\(report?.helperProtocol ?? -1)（App 需要 \(HelperProtocol.version)）",
                     "登录时打开 AgentGuard：\(opensAtLogin ? "是" : "否")"]
        lines += (report?.collectorProblems ?? []).map { "活动记录：\($0)" }
        for status in report?.profiles ?? [] {
            lines.append("")
            lines.append("[\(status.profileID)] 修订 \(status.savedRevision) · \(status.mode.displayName) · \(status.revisionState.displayText)")
            lines.append("  运行副本：\(status.runningInstances)  跟踪不完整：\(status.untrackedInstances)  未受管：\(status.unmanagedProcesses)")
            if let agent = status.launchAgent { lines.append("  启动：\(agent.displayText)\(agent.problem.map { "（\($0)）" } ?? "")") }
            lines += status.verificationIssues.map { "  核对问题：\($0)" }
            if let profile = profile(status.profileID) {
                lines.append("  旧规则：\(profile.extraRules.count) 条")
                if let launch = profile.launch {
                    lines.append("  启动入口：\(launch.executable)，原启动项：\(launch.originalLabel ?? "无")，登录自启：\(launch.runAtLogin ? "开" : "关")")
                }
            }
        }
        return lines.joined(separator: "\n")
    }

    func exportDiagnostics() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "AgentGuard-诊断.txt"
        let text = diagnosticsText()
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do { try text.write(to: url, atomically: true, encoding: .utf8) }
            catch { Task { @MainActor in self.lastError = "未能保存诊断：\(error.localizedDescription)" } }
        }
    }

    /// Stops every managed program, removes AgentGuard's launch items, the collector and the Helper.
    /// Profiles, backups and the programs' working data stay on disk.
    func uninstall(restoreOriginals: Bool) {
        let profiles = report?.profiles ?? []
        var lines = ["停止全部受管程序：" + (profiles.isEmpty ? "无" : profiles.map(\.profileID).joined(separator: "、")),
                     "移除 AgentGuard 安装的启动项、活动记录采集器和后台服务"]
        let originals = profiles.compactMap { profile($0.profileID)?.launch?.originalLabel }
        if !originals.isEmpty {
            lines.append(restoreOriginals ? "恢复被替换的原启动项：\(originals.joined(separator: "、"))（之后它们不受任何限制）"
                                          : "不恢复被替换的原启动项（备份保留，可以手动恢复）")
        }
        lines.append("保留权限设置、启动项备份和程序的工作数据")
        lines.append("完成后把 AgentGuard 从“应用程序”文件夹移到废纸篓")
        Task {
            guard await askConfirmation(restoreOriginals ? "卸载 AgentGuard 并恢复原启动方式" : "卸载 AgentGuard", lines) else { return }
            let ok = await Task.detached { () -> Bool in
                do {
                    let token = try UserAuthorization.obtain(scope: HelperService.authorizationScope(forUninstall: restoreOriginals),
                                                             prompt: "AgentGuard 将停止受管程序并移除自身的后台组件")
                    return await self.sendAsync(.uninstall(restoreOriginals: restoreOriginals, authorization: token), refreshAfter: false)
                } catch {
                    await MainActor.run { self.lastError = "\(error)" }
                    return false
                }
            }.value
            guard ok else { return }
            do {
                try await SMAppService.daemon(plistName: AgentGuardConfig.helperPlistName).unregister()
            } catch {
                lastWarning = [lastWarning, "后台服务没有完全移除：\(error.localizedDescription)。请在“系统设置 > 通用 > 登录项”中关闭 AgentGuard。"]
                    .compactMap { $0 }.joined(separator: "\n")
            }
            try? SMAppService.mainApp.unregister()
            lastNotice = [lastNotice, "AgentGuard 的后台组件已移除。现在可以退出 AgentGuard，并把它从“应用程序”文件夹移到废纸篓。"]
                .compactMap { $0 }.joined(separator: "\n")
            refresh()
        }
    }
}
#endif
