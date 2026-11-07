#if os(macOS)
import Foundation
import GuardCore

/// Installs and starts the privileged collector daemon.
///
/// The daemon is copied once to `/Library/PrivilegedHelperTools` and is never replaced while it is
/// present: Full Disk Access is granted to that exact binary, and swapping it would invalidate the
/// grant. A new collector is shipped by removing the installed copy on purpose.
enum CollectorInstaller {
    enum Outcome: Equatable {
        case installed
        case alreadyPresent
        case wouldReplaceOutdated
        case failed(String)
    }

    static func ensureInstalled(bundleMacOSDirectory: String) -> Outcome {
        let bundled = FileManager.default.contents(atPath: bundleMacOSDirectory + "/agentguard-collector")
        let existing = FileManager.default.contents(atPath: AgentGuardConfig.collectorPath)
        switch CollectorInstall.plan(existing: existing, bundled: bundled) {
        case .keep:
            writePlistIfNeeded()
            bootstrapIfNeeded()
            return existing == nil ? .failed("App 包内没有 agentguard-collector") : .alreadyPresent

        case .keepOutdated:
            writePlistIfNeeded()
            bootstrapIfNeeded()
            return .wouldReplaceOutdated

        case .install:
            guard let bundled else { return .failed("App 包内没有 agentguard-collector") }
            do {
                try install(bundled)
            } catch {
                return .failed("安装 agentguard-collector 失败：\(error.localizedDescription)")
            }
            writePlistIfNeeded()
            bootstrapIfNeeded()
            return .installed
        }
    }

    /// Unloads and removes the collector daemon and its binary; returns what could not be removed.
    static func uninstall() -> [String] {
        var problems: [String] = []
        if Launchctl.run(["print", "system/" + AgentGuardConfig.collectorLabel]) == 0,
           Launchctl.run(["bootout", "system/" + AgentGuardConfig.collectorLabel]) != 0 {
            problems.append("采集器后台任务未能停止")
        }
        for path in [AgentGuardConfig.collectorPlistPath, AgentGuardConfig.collectorPath, AgentGuardConfig.collectorFileEventsFlagPath]
        where FileManager.default.fileExists(atPath: path) {
            do { try FileManager.default.removeItem(atPath: path) } catch { problems.append("未能删除 \(path)") }
        }
        return problems
    }

    private static func install(_ contents: Data) throws {
        let directory = AgentGuardConfig.privilegedHelperToolsDirectory
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let target = AgentGuardConfig.collectorPath
        let temporary = target + ".tmp"
        try contents.write(to: URL(fileURLWithPath: temporary))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: temporary)
        guard chown(temporary, 0, 0) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "chown 失败"])
        }
        try? FileManager.default.removeItem(atPath: target)
        try FileManager.default.moveItem(atPath: temporary, toPath: target)
    }

    private static func writePlistIfNeeded() {
        let path = AgentGuardConfig.collectorPlistPath
        let desired = plist()
        if let existing = FileManager.default.contents(atPath: path), existing == desired { return }
        do {
            try desired.write(to: URL(fileURLWithPath: path))
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
            _ = chown(path, 0, 0)
        } catch {
            FileHandle.standardError.write(Data("写入 \(path) 失败：\(error)\n".utf8))
        }
    }

    private static func plist() -> Data {
        let label = AgentGuardConfig.collectorLabel
        let text = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>Label</key><string>\(label)</string>
        <key>ProgramArguments</key><array><string>\(AgentGuardConfig.collectorPath)</string></array>
        <key>RunAtLoad</key><true/>
        <key>KeepAlive</key><true/>
        <key>ProcessType</key><string>Background</string>
        </dict></plist>
        """
        return Data(text.utf8)
    }

    private static func bootstrapIfNeeded() {
        if Launchctl.run(["print", "system/" + AgentGuardConfig.collectorLabel]) == 0 { return }
        _ = Launchctl.run(["bootstrap", "system", AgentGuardConfig.collectorPlistPath])
    }
}
#endif
