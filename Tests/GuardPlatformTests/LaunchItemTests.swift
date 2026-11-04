import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

private final class StartupFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentguard-startup-" + UUID().uuidString).path
    let prefix = "com.test.agentguard.managed"
    let launcher = "/Applications/AgentGuard.app/Contents/MacOS/agentguard-launcher"
    var loaded: [String: Bool] = [:]
    var calls: [[String]] = []
    var failBootstrap: Set<String> = []
    var failBootout: Set<String> = []
    var failQueries = false
    var failDomainQuery = false
    var failJobQueries: Set<String> = []
    var domainOutput: String?
    var jobOutput: [String: String] = [:]

    var files: LaunchItemFiles {
        LaunchItemFiles(home: root + "/home", configRoot: root + "/config", launcherPath: launcher, labelPrefix: prefix,
                        automaticDirectory: root + "/automatic")
    }
    var controller: LaunchItemController { LaunchItemController(files: files, domain: "gui/501", execute: execute) }
    deinit { try? FileManager.default.removeItem(atPath: root) }

    func execute(_ args: [String]) -> LaunchctlClient.Result {
        calls.append(args)
        if args == ["print", "gui/501"] {
            return LaunchctlClient.Result(status: failQueries || failDomainQuery ? -1 : 0,
                                          output: domainOutput ?? "gui/501 = {\n services = {\n" + loaded.keys.sorted().map { "  0  -  " + $0 }.joined(separator: "\n") + "\n }\n}")
        }
        let label = String(args.last?.split(separator: "/").last ?? "")
        switch args.first {
        case "print":
            if failQueries || failJobQueries.contains(label) { return .init(status: -1, output: "permission denied") }
            guard let running = loaded[label] else { return .init(status: 113, output: "Could not find service \"\(label)\"") }
            return .init(status: 0, output: (jobOutput[label] ?? "") + (running ? "pid = 1234\n" : "state = not running\n"))
        case "bootstrap":
            guard let path = args.last, let data = FileManager.default.contents(atPath: path), let item = LaunchItem(path: path, data: data),
                  !failBootstrap.contains(item.label), loaded[item.label] == nil else { return .init(status: 5) }
            loaded[item.label] = true
            return .init(status: 0)
        case "bootout":
            guard !failBootout.contains(label), loaded.removeValue(forKey: label) != nil else { return .init(status: 5) }
            return .init(status: 0)
        case "kickstart":
            loaded[label] = true
            return .init(status: 0)
        default: return .init(status: 1)
        }
    }

    func plist(_ label: String, executable: String? = nil, args: [String]? = nil, extra: [String: Any] = [:]) throws -> Data {
        var p: [String: Any] = ["Label": label, "ProgramArguments": [executable ?? launcher] + (args ?? ["launch", "demo"]), "RunAtLoad": true]
        p.merge(extra) { _, new in new }
        return try PropertyListSerialization.data(fromPropertyList: p, format: .xml, options: 0)
    }
    @discardableResult func put(_ data: Data, _ path: String, mode: Int = 0o644) throws -> String {
        try FileManager.default.createDirectory(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
        return path
    }
    func managed(_ generation: String, manual: Bool = false, filename: String? = nil, running: Bool? = true) throws -> (String, String, Data) {
        let label = prefix + ".demo." + generation, data = try plist(prefix + ".demo." + generation)
        let path = (manual ? files.manualDirectory : files.automaticDirectory) + "/" + (filename ?? label) + ".plist"
        try put(data, path)
        loaded[label] = running
        return (label, path, data)
    }
    func launch(login: Bool = true, original: String? = nil, path: String? = nil) -> LaunchSettings {
        LaunchSettings(executable: "/bin/sleep", arguments: ["60"], workingDirectory: nil, originalLabel: original,
                       restartOnCleanExit: false, runAtLogin: login, originalPath: path)
    }
    func backup(_ label: String, destination: String) throws -> String {
        let path = files.backupDirectory + "/" + label + ".plist"
        try put(plist(label, executable: "/bin/sleep", args: ["60"]), path, mode: 0o600)
        try put(Data(destination.utf8), path + ".location", mode: 0o600)
        return path
    }
    func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }
    func orphan(_ label: String, executable: String? = nil, arguments: [String]? = nil) {
        loaded[label] = true
        let executable = executable ?? launcher
        jobOutput[label] = "program = \(executable)\narguments = {\n" + ([executable] + (arguments ?? ["launch", "demo"])).joined(separator: "\n") + "\n}\n"
    }
}

@Suite struct LaunchItemTests {
    @Test func detectsActualLabelsAcrossBothDirectoriesAndOldGenerations() throws {
        let f = StartupFixture()
        _ = try f.managed("old", filename: "unrelated-filename")
        var status = f.controller.status(profileID: "demo", launch: f.launch())
        #expect(status.registered && status.running && status.runAtLogin && status.problem == nil)
        try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {})
        _ = try f.managed("new", manual: true, running: false)
        status = f.controller.status(profileID: "demo", launch: f.launch(login: false))
        #expect(status.registered && !status.running && !status.runAtLogin)
    }

    @Test func orphanedRegistrationAndFailedQueriesRemainUnknown() throws {
        let f = StartupFixture()
        f.loaded[f.prefix + ".demo.old"] = true
        #expect(f.controller.status(profileID: "demo", launch: nil).problem != nil)
        f.loaded = [:]; f.failQueries = true
        #expect(f.controller.status(profileID: "demo", launch: nil).problem != nil)
        f.failQueries = false
        try f.put(Data("bad plist".utf8), f.files.automaticDirectory + "/" + f.prefix + ".demo.bad.plist")
        #expect(f.controller.status(profileID: "demo", launch: nil).problem != nil)
    }

    @Test func migratesLoginStartupToManualAndBack() throws {
        let f = StartupFixture()
        let (oldLabel, oldPath, _) = try f.managed("old")
        let label = f.prefix + ".demo.new", data = try f.plist(label)
        var stops = 0
        try f.controller.install(profileID: "demo", launch: f.launch(login: false), label: label, plist: data, restart: true) { stops += 1 }
        #expect(!f.exists(oldPath) && f.loaded[oldLabel] == nil)
        #expect(f.exists(f.files.manualDirectory + "/" + label + ".plist"))
        #expect(!f.controller.status(profileID: "demo", launch: nil).runAtLogin)
        try f.controller.install(profileID: "demo", launch: f.launch(), label: label, plist: data, restart: true) { stops += 1 }
        #expect(!f.exists(f.files.manualDirectory + "/" + label + ".plist"))
        #expect(f.controller.status(profileID: "demo", launch: nil).runAtLogin)
        #expect(stops == 2)
    }

    @Test func anAlreadyRegisteredJobIsStartedWithoutKillingIt() throws {
        let f = StartupFixture()
        let (label, _, data) = try f.managed("old", running: false)
        var stopped = false
        try f.controller.install(profileID: "demo", launch: f.launch(), label: label, plist: data, restart: false) { stopped = true }
        #expect(!stopped && f.loaded[label] == true)
        #expect(f.calls.contains(["kickstart", "gui/501/" + label]))
        #expect(!f.calls.contains(where: { $0.contains("-k") || $0.first == "bootout" || $0.first == "bootstrap" }))
    }

    @Test func bootstrapFailureRestoresThePreviousFileAndRegistration() throws {
        let f = StartupFixture()
        let (old, path, original) = try f.managed("old", manual: true)
        let label = f.prefix + ".demo.new"
        f.failBootstrap.insert(label)
        #expect(throws: LaunchItemError.self) {
            try f.controller.install(profileID: "demo", launch: f.launch(), label: label, plist: f.plist(label), restart: true, stop: {})
        }
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == original)
        #expect(f.loaded[old] == true && f.loaded[label] == nil)
        #expect(!f.exists(f.files.automaticDirectory + "/" + label + ".plist"))
    }

    @Test func missingBackupOrDestinationConflictDoesNotStopCurrentStartup() throws {
        let f = StartupFixture()
        let (label, path, _) = try f.managed("old")
        var stopped = false
        #expect(throws: LaunchItemError.self) { try f.controller.remove(profileID: "demo", restoreOriginal: "com.original", stop: { stopped = true }) }
        #expect(!stopped && f.exists(path) && f.loaded[label] == true)
        let destination = f.files.automaticDirectory + "/original.plist"
        _ = try f.backup("com.original", destination: destination)
        try f.put(Data("a file already here".utf8), destination)
        #expect(throws: LaunchItemError.self) { try f.controller.remove(profileID: "demo", restoreOriginal: "com.original", stop: { stopped = true }) }
        #expect(!stopped && f.loaded[label] == true)
    }

    @Test func takeoverAndRestorePreserveOriginalPathArgumentsAndPermissions() throws {
        let f = StartupFixture(), originalLabel = "com.original.agent"
        let path = f.files.originalDirectories[0] + "/not-the-label.plist"
        let data = try f.plist(originalLabel, executable: "/bin/sleep", args: ["two words", "", "a\\b"])
        try f.put(data, path, mode: 0o600)
        f.loaded[originalLabel] = true
        let newLabel = f.prefix + ".demo.new"
        try f.controller.install(profileID: "demo", launch: f.launch(original: originalLabel, path: path), label: newLabel,
                                 plist: f.plist(newLabel), restart: false, stop: {})
        let backup = f.files.backupDirectory + "/" + originalLabel + ".plist"
        #expect(!f.exists(path) && f.loaded[originalLabel] == nil)
        #expect((try FileManager.default.attributesOfItem(atPath: backup)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(f.controller.status(profileID: "demo", launch: f.launch(original: originalLabel)).canRestoreOriginal)
        try f.controller.remove(profileID: "demo", restoreOriginal: originalLabel, stop: {})
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == data)
        #expect((try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(f.loaded[originalLabel] == true && !f.exists(backup))
    }

    @Test func failedFirstTakeoverRestoresOriginalWithoutLosingExistingSidecars() throws {
        let f = StartupFixture(), originalLabel = "com.original.agent"
        let path = f.files.automaticDirectory + "/different.plist"
        let data = try f.plist(originalLabel, executable: "/bin/sleep", args: ["60"])
        try f.put(data, path, mode: 0o600); f.loaded[originalLabel] = true
        let label = f.prefix + ".demo.new"
        f.failBootstrap.insert(label)
        #expect(throws: LaunchItemError.self) {
            try f.controller.install(profileID: "demo", launch: f.launch(original: originalLabel, path: path), label: label,
                                     plist: f.plist(label), restart: false, stop: {})
        }
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == data)
        #expect(f.loaded[originalLabel] == true)
        let backup = f.files.backupDirectory + "/" + originalLabel + ".plist"
        #expect(!f.exists(backup))
        try f.put(Data("sentinel".utf8), backup + ".location")
        #expect(throws: (any Error).self) {
            try f.controller.install(profileID: "demo", launch: f.launch(original: originalLabel), label: label,
                                     plist: f.plist(label), restart: false, stop: {})
        }
        #expect(try String(contentsOfFile: backup + ".location", encoding: .utf8) == "sentinel")
        #expect(!f.exists(backup) && f.exists(path) && f.loaded[originalLabel] == true)
    }

    @Test func repeatedInstallNeverReplacesTheOriginalBackup() throws {
        let f = StartupFixture(), originalLabel = "com.original.agent"
        let destination = f.files.automaticDirectory + "/original.plist"
        let backup = try f.backup(originalLabel, destination: destination)
        let original = try Data(contentsOf: URL(fileURLWithPath: backup))
        _ = try f.managed("old")
        let label = f.prefix + ".demo.new"
        try f.controller.install(profileID: "demo", launch: f.launch(original: originalLabel), label: label,
                                 plist: f.plist(label), restart: true, stop: {})
        #expect(try Data(contentsOf: URL(fileURLWithPath: backup)) == original)
    }

    @Test func failedRestoreKeepsBackupAndRollsBackManagedStartup() throws {
        let f = StartupFixture(), originalLabel = "com.original.agent"
        let (label, path, _) = try f.managed("old", manual: true)
        let destination = f.files.automaticDirectory + "/original.plist"
        let backup = try f.backup(originalLabel, destination: destination)
        f.failBootstrap.insert(originalLabel)
        #expect(throws: LaunchItemError.self) { try f.controller.remove(profileID: "demo", restoreOriginal: originalLabel, stop: {}) }
        #expect(f.loaded[label] == true && f.exists(path) && f.exists(backup) && !f.exists(destination))
    }

    @Test func deletionCommitIsWrappedInBothDirectoryCleanupAndRollback() throws {
        enum ArchiveFailure: Error { case failed }
        let f = StartupFixture()
        let (a, ap, _) = try f.managed("old")
        let (m, mp, _) = try f.managed("new", manual: true)
        #expect(throws: ArchiveFailure.self) {
            try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {}, commit: {
                #expect(!f.exists(ap) && !f.exists(mp) && f.loaded.isEmpty)
                throw ArchiveFailure.failed
            })
        }
        #expect(f.exists(ap) && f.exists(mp) && f.loaded[a] == true && f.loaded[m] == true)
        try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {})
        #expect(!f.exists(ap) && !f.exists(mp) && f.loaded.isEmpty)
    }

    @Test func rollbackKeepsStoppedTasksStoppedWhileRestoringOtherRunningJobs() throws {
        let f = StartupFixture(), originalLabel = "com.original.agent"
        let originalPath = f.files.automaticDirectory + "/original.plist"
        try f.put(f.plist(originalLabel, executable: "/bin/sleep", args: ["60"]), originalPath)
        f.loaded[originalLabel] = false
        let (old, oldPath, _) = try f.managed("old", running: true)
        let new = f.prefix + ".demo.new"
        f.failBootstrap.insert(new)
        #expect(throws: LaunchItemError.rollbackLeftStopped) {
            try f.controller.install(profileID: "demo", launch: f.launch(original: originalLabel), label: new,
                                     plist: f.plist(new), restart: true, stop: {})
        }
        #expect(f.exists(originalPath) && f.loaded[originalLabel] == nil)
        #expect(f.exists(f.files.backupDirectory + "/" + originalLabel + ".plist"))
        #expect(!f.calls.contains(["bootstrap", "gui/501", originalPath]))
        #expect(f.exists(oldPath) && f.loaded[old] == true)
    }

    @Test func rollbackOfAStoppedManagedTaskReportsUnloadedState() throws {
        enum ArchiveFailure: Error { case failed }
        let f = StartupFixture()
        let (label, path, _) = try f.managed("old", manual: true, running: false)
        #expect(throws: LaunchItemError.rollbackLeftStopped) {
            try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {}, commit: { throw ArchiveFailure.failed })
        }
        #expect(f.exists(path) && f.loaded[label] == nil)
        #expect(!f.calls.contains(["bootstrap", "gui/501", path]))
    }

    @Test func originalLookupRejectsDuplicateLabelsAndEscapedLocations() throws {
        let f = StartupFixture(), label = "com.original"
        try f.put(f.plist(label), f.files.originalDirectories[0] + "/one.plist")
        try f.put(f.plist(label), f.files.originalDirectories[1] + "/two.plist")
        #expect(throws: LaunchItemError.self) { try f.files.original(label: label, selectedPath: nil) }
        #expect(!f.files.isOriginalLocation(f.root + "/outside.plist"))
        let path = try f.backup(label, destination: f.root + "/outside.plist")
        #expect(throws: LaunchItemError.self) { try f.files.backup(label: label) }
        try f.put(Data((f.files.automaticDirectory + "/one.plist").utf8), path + ".location")
        try f.put(f.plist("com.different"), path)
        #expect(throws: LaunchItemError.self) { try f.files.backup(label: label) }
    }

    @Test func importPreservesArgumentArraysAndRejectsUnrepresentableSettings() throws {
        let f = StartupFixture()
        let simple = try #require(LaunchItem(path: "/test.plist", data: f.plist("com.original", executable: "/bin/sleep", args: ["two words", ""])))
        #expect(simple.arguments == ["two words", ""] && simple.unsupportedKeys.isEmpty)
        let complex = try #require(LaunchItem(path: "/test.plist", data: f.plist("com.original", executable: "/bin/sleep", args: ["60"],
                                                                                              extra: ["Program": "/bin/cat", "EnvironmentVariables": ["A": "b"]])))
        #expect(complex.unsupportedKeys.contains("EnvironmentVariables") && complex.unsupportedKeys.contains("自定义 argv[0]"))
    }

    @Test func launchctlDistinguishesNotRunningMissingAndUnknown() throws {
        #expect(try #require(LaunchctlClient.registration(.init(status: 0, output: "state = exited"))).running == false)
        #expect(try #require(LaunchctlClient.registration(.init(status: 0, output: "  pid = 123\n"))).running)
        #expect(try #require(LaunchctlClient.registration(.init(status: 113, output: "Could not find service \"demo\""))).loaded == false)
        #expect(LaunchctlClient.registration(.init(status: -1, output: "timeout")) == nil)
        #expect(LaunchctlClient.labels(inDomain: .init(status: 0, output: "unexpected format")) == nil)
    }

    @Test func statusBatchSharesTheDomainQueryAcrossProfiles() throws {
        let f = StartupFixture()
        _ = try f.managed("old")
        let result = f.controller.statuses([.init(id: "demo", launch: f.launch()), .init(id: "other", launch: nil)])
        #expect(result["demo"]?.registered == true && result["other"]?.registered == false)
        #expect(f.calls.filter { $0 == ["print", "gui/501"] }.count == 1)
    }

    @Test func unrelatedDomainRowsDoNotInvalidateRecognizedLabels() {
        let result = LaunchctlClient.Result(status: 0, output: """
        gui/501 = {
            services = {
                PID STATUS LABEL
                unknown future header
                0 - com.example.stopped
                123 0 new-column com.example.running
            }
        }
        """)
        #expect(LaunchctlClient.labels(inDomain: result) == ["com.example.stopped", "com.example.running"])
    }

    @Test func deletingAProfileWithoutStartupNeverQueriesLaunchctl() throws {
        let f = StartupFixture()
        f.failQueries = true
        try f.put(Data("broken".utf8), f.files.automaticDirectory + "/" + f.prefix + ".other.bad.plist")
        var stopped = false, committed = false
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, hasLaunchSettings: false, deleting: true,
                                               stop: { stopped = true }, commit: { committed = true })
        #expect(stopped && committed && warnings.isEmpty && f.calls.isEmpty)
    }

    @Test func unrelatedDamagedFilesDoNotBlockInstallationOrRemoval() throws {
        let f = StartupFixture()
        try f.put(Data("broken".utf8), f.files.automaticDirectory + "/" + f.prefix + ".other.bad.plist")
        let label = f.prefix + ".demo.new"
        try f.controller.install(profileID: "demo", launch: f.launch(), label: label, plist: f.plist(label), restart: false, stop: {})
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {})
        #expect(warnings.isEmpty && f.loaded.isEmpty)
    }

    @Test func deletingWithADamagedOwnFileKeepsTheFileAndReportsCleanup() throws {
        let f = StartupFixture()
        let path = try f.put(Data("broken".utf8), f.files.automaticDirectory + "/" + f.prefix + ".demo.bad.plist")
        var committed = false
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, deleting: true, stop: {}, commit: { committed = true })
        #expect(committed && f.exists(path) && warnings.contains(where: { $0.contains(path) }))
    }

    @Test func domainFailureFallsBackToKnownJobsAndReturnsAWarning() throws {
        let f = StartupFixture()
        let (label, path, _) = try f.managed("old")
        f.failDomainQuery = true
        let status = f.controller.status(profileID: "demo", launch: f.launch())
        #expect(status.registered && status.running && status.problem != nil)
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, stop: {})
        #expect(!warnings.isEmpty && !f.exists(path) && f.loaded[label] == nil)
    }

    @Test func deletionPreservesJobsWhoseRegistrationCannotBeQueried() throws {
        let f = StartupFixture()
        let (label, path, _) = try f.managed("old")
        f.failJobQueries.insert(label)
        var committed = false
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, deleting: true, stop: {}, commit: { committed = true })
        #expect(committed && f.exists(path) && f.loaded[label] == true && !warnings.isEmpty)
        #expect(!f.calls.contains(where: { $0.first == "bootout" }))
    }

    @Test func orphanCleanupVerifiesTheProgramAndEveryArgument() throws {
        let f = StartupFixture()
        let ours = f.prefix + ".demo.ours", foreign = f.prefix + ".demo.foreign", wrongArgument = f.prefix + ".demo.wrong"
        f.orphan(ours)
        f.orphan(foreign, executable: "/bin/sleep", arguments: ["60"])
        f.orphan(wrongArgument, arguments: ["launch", "other"])
        let warnings = try f.controller.remove(profileID: "demo", restoreOriginal: nil, deleting: true, stop: {})
        #expect(f.loaded[ours] == nil && f.loaded[foreign] == true && f.loaded[wrongArgument] == true)
        #expect(warnings.count == 2)
        #expect(!f.calls.contains(["bootout", "gui/501/" + foreign]))
        #expect(!f.calls.contains(["bootout", "gui/501/" + wrongArgument]))
    }

    @Test func restoringOriginalStopsConfirmedOrphansBeforeStartingIt() throws {
        let f = StartupFixture(), original = "com.original"
        let orphan = f.prefix + ".demo.old"
        f.orphan(orphan)
        let destination = f.files.automaticDirectory + "/original.plist"
        let backup = try f.backup(original, destination: destination)
        try f.controller.remove(profileID: "demo", restoreOriginal: original, stop: { #expect(f.loaded[orphan] == nil) })
        let bootout = try #require(f.calls.firstIndex(of: ["bootout", "gui/501/" + orphan]))
        let bootstrap = try #require(f.calls.firstIndex(of: ["bootstrap", "gui/501", destination]))
        #expect(bootout < bootstrap && f.loaded[original] == true && !f.exists(backup))
    }

    @Test func restoringOriginalRejectsUnverifiedOrUnstoppableOrphans() throws {
        for canVerify in [false, true] {
            let f = StartupFixture(), original = "com.original"
            let orphan = f.prefix + ".demo.old"
            f.orphan(orphan, executable: canVerify ? nil : "/bin/sleep")
            if canVerify { f.failBootout.insert(orphan) }
            let destination = f.files.automaticDirectory + "/original.plist"
            let backup = try f.backup(original, destination: destination)
            #expect(throws: LaunchItemError.self) { try f.controller.remove(profileID: "demo", restoreOriginal: original, stop: {}) }
            #expect(f.loaded[orphan] == true && f.loaded[original] == nil && f.exists(backup) && !f.exists(destination))
            #expect(!f.calls.contains(where: { $0.first == "bootstrap" }))
        }
    }

    @Test func restoringOriginalRequiresReadableOwnFilesAndRegistry() throws {
        for failure in ["domain", "job", "file"] {
            let f = StartupFixture(), original = "com.original"
            let (label, path, _) = try f.managed("old")
            let destination = f.files.automaticDirectory + "/original.plist"
            let backup = try f.backup(original, destination: destination)
            if failure == "domain" { f.failDomainQuery = true }
            if failure == "job" { f.failJobQueries.insert(label) }
            if failure == "file" { try f.put(Data("broken".utf8), path) }
            #expect(throws: LaunchItemError.self) { try f.controller.remove(profileID: "demo", restoreOriginal: original, stop: {}) }
            #expect(f.loaded[label] == true && f.exists(backup) && !f.exists(destination))
            #expect(!f.calls.contains(where: { $0.first == "bootstrap" || $0.first == "bootout" }))
        }
    }

    @Test func failedRestoreOfAnOrphanKeepsBackupAndReportsTheStoppedJob() throws {
        let f = StartupFixture(), original = "com.original"
        let orphan = f.prefix + ".demo.old"
        f.orphan(orphan)
        let destination = f.files.automaticDirectory + "/original.plist"
        let backup = try f.backup(original, destination: destination)
        f.failBootstrap.insert(original)
        #expect(throws: LaunchItemError.rollbackLeftStopped) {
            try f.controller.remove(profileID: "demo", restoreOriginal: original, stop: {})
        }
        #expect(f.loaded[orphan] == nil && f.loaded[original] == nil && f.exists(backup) && !f.exists(destination))
    }
}
