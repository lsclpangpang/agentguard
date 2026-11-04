#if os(macOS)
import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

@Suite struct LaunchdSmokeTests {
    /// Opt-in: only registers an isolated short-lived sleep job in the current user's domain.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["AGENTGUARD_LAUNCHD_SMOKE"] == "1"))
    func manualAndLoginLocationsUseTheSameVerifiedStartupPath() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("agentguard-smoke-" + UUID().uuidString)
        let launcher = root.appendingPathComponent("sleep-launcher.sh").path
        let id = UUID().uuidString.lowercased(), prefix = "com.lsclpangpang.agentguard.smoke"
        let domain = "gui/\(getuid())", label = prefix + "." + id
        defer {
            _ = LaunchctlClient.run(["bootout", domain + "/" + label])
            try? fm.removeItem(at: root)
        }
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("#!/bin/sh\nexec /bin/sleep 30\n".utf8).write(to: URL(fileURLWithPath: launcher))
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: launcher)
        let files = LaunchItemFiles(home: root.appendingPathComponent("home").path, configRoot: root.appendingPathComponent("config").path,
                                    launcherPath: launcher, labelPrefix: prefix, automaticDirectory: root.appendingPathComponent("automatic").path)
        let controller = LaunchItemController(files: files, domain: domain)
        let data = try LaunchAgentDefinition(labelPrefix: prefix, launcherPath: launcher, profileID: id, runAtLoad: true,
                                             restartOnCleanExit: false, throttleInterval: 1, logDirectory: root.path).xmlData()
        var launch = LaunchSettings(executable: "/bin/sleep", arguments: ["30"], workingDirectory: nil, originalLabel: nil,
                                    restartOnCleanExit: false, runAtLogin: false)
        for login in [false, true, false] {
            launch.runAtLogin = login
            try controller.install(profileID: id, launch: launch, label: label, plist: data, restart: true, stop: {})
            var status = controller.status(profileID: id, launch: launch)
            let deadline = Date().addingTimeInterval(2)
            while !status.running && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
                status = controller.status(profileID: id, launch: launch)
            }
            #expect(status.problem == nil && status.registered && status.running)
            #expect(status.runAtLogin == login)
        }
        try controller.remove(profileID: id, restoreOriginal: nil, stop: {})
        let stopped = controller.status(profileID: id, launch: launch)
        #expect(stopped.problem == nil && !stopped.registered && !stopped.runAtLogin)
    }
}
#endif
