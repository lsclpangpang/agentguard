import Foundation
import GuardCore

/// Coordinates startup-file and launchd changes. Injected execution makes failure/rollback paths
/// testable without registering jobs or running the Helper as root.
public struct LaunchItemController {
    public let files: LaunchItemFiles
    public let domain: String
    private let execute: ([String]) -> LaunchctlClient.Result
    private let fileOwner: Int?

    public init(files: LaunchItemFiles, domain: String, fileOwner: Int? = nil,
                execute: @escaping ([String]) -> LaunchctlClient.Result = LaunchctlClient.run) {
        self.files = files; self.domain = domain; self.fileOwner = fileOwner; self.execute = execute
    }

    private struct Saved {
        let item: LaunchItem
        let data: Data
        let metadata: Metadata
        let loaded: Bool
        let running: Bool
    }

    private struct Metadata: Codable {
        let mode: Int
        let uid: Int
        let gid: Int

        init(path: String) throws {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o644
            uid = (attributes[.ownerAccountID] as? NSNumber)?.intValue ?? 0
            gid = (attributes[.groupOwnerAccountID] as? NSNumber)?.intValue ?? 0
        }

        init(mode: Int, uid: Int, gid: Int) { self.mode = mode; self.uid = uid; self.gid = gid }
        var attributes: [FileAttributeKey: Any] {
            [.posixPermissions: mode, .ownerAccountID: uid, .groupOwnerAccountID: gid]
        }
    }

    private struct Backup {
        let path: String
        let destination: String
        let data: Data
        let metadata: Metadata
    }

    private func registration(_ label: String) throws -> (loaded: Bool, running: Bool) {
        guard let state = LaunchctlClient.registration(execute(["print", domain + "/" + label])) else { throw LaunchItemError.operationFailed }
        return state
    }

    private struct Snapshot {
        var saved: [Saved] = []
        var orphans: [String] = []
        var warnings: [String] = []
    }

    private func snapshot(_ id: String, domainResult: LaunchctlClient.Result? = nil, tolerateFileProblems: Bool = false, requireCompleteRegistry: Bool = false,
                          scan: (items: [LaunchItem], problems: [String])? = nil) throws -> Snapshot {
        let scan = try scan ?? files.managedScan(profileID: id)
        if !tolerateFileProblems && !scan.problems.isEmpty { throw LaunchItemError.invalidManagedItem }
        var result = Snapshot(warnings: scan.problems)
        let groups = Dictionary(grouping: scan.items, by: \.label)
        let labels = LaunchctlClient.labels(inDomain: domainResult ?? execute(["print", domain]))
        if let labels {
            result.orphans = labels.filter {
                LaunchAgentDefinition.isManagedLabel($0, profileID: id, labelPrefix: files.labelPrefix) && groups[$0] == nil
            }.sorted()
        } else {
            if requireCompleteRegistry { throw LaunchItemError.operationFailed }
            result.warnings.append("暂时无法完整读取系统启动列表，已按本配置的启动文件逐项检查。")
        }
        for (label, items) in groups.sorted(by: { $0.key < $1.key }) {
            guard items.count == 1, let item = items.first else {
                if tolerateFileProblems { result.warnings.append("同名启动文件重复，已保留：" + label); continue }
                throw LaunchItemError.invalidManagedItem
            }
            do {
                let state = try registration(label)
                result.saved.append(Saved(item: item, data: try Data(contentsOf: URL(fileURLWithPath: item.path)), metadata: try Metadata(path: item.path),
                                          loaded: state.loaded, running: state.running))
            } catch {
                if !tolerateFileProblems { throw error }
                result.warnings.append("无法确认启动任务状态，已保留：" + label)
            }
        }
        return result
    }

    /// One domain query per background batch, shared by every profile in the batch.
    public func statuses(_ requests: [LaunchStatusRequest]) -> [String: LaunchAgentStatus] {
        guard !requests.isEmpty else { return [:] }
        let domainResult = execute(["print", domain])
        return Dictionary(uniqueKeysWithValues: requests.map { ($0.id, status(profileID: $0.id, launch: $0.launch, domainResult: domainResult)) })
    }

    public func status(profileID: String, launch: LaunchSettings?) -> LaunchAgentStatus {
        status(profileID: profileID, launch: launch, domainResult: nil)
    }

    private func status(profileID: String, launch: LaunchSettings?, domainResult: LaunchctlClient.Result?) -> LaunchAgentStatus {
        do {
            let snapshot = try snapshot(profileID, domainResult: domainResult)
            let old = snapshot.saved
            let running = old.contains(where: \.running)
            var canRestore = false, originalProblem: String?
            if let label = launch?.originalLabel {
                let hasBackup = FileManager.default.fileExists(atPath: files.backupDirectory + "/" + label + ".plist")
                if hasBackup || !old.isEmpty {
                    do { _ = try checkedBackup(label); canRestore = true }
                    catch { originalProblem = String(describing: error) }
                }
            }
            let problem = snapshot.orphans.isEmpty ? snapshot.warnings.first : "系统中有缺少启动文件的任务，可尝试“停止并取消自启”清理。"
            return LaunchAgentStatus(registered: !snapshot.orphans.isEmpty || old.contains(where: \.loaded), running: running,
                                     runAtLogin: old.contains { URL(fileURLWithPath: $0.item.path).deletingLastPathComponent().path == files.automaticDirectory },
                                     canRestoreOriginal: canRestore, problem: problem, originalProblem: originalProblem)
        } catch {
            return LaunchAgentStatus(registered: false, running: false, runAtLogin: false, canRestoreOriginal: false,
                                     problem: String(describing: error))
        }
    }

    private func checkedBackup(_ label: String) throws -> Backup {
        let pair = try files.backup(label: label, requireEmptyDestination: true)
        guard (try files.originals()).allSatisfy({ $0.label != label }), !(try registration(label).loaded) else { throw LaunchItemError.destinationExists }
        let metadataPath = pair.path + ".metadata"
        let metadata: Metadata
        if FileManager.default.fileExists(atPath: metadataPath) {
            guard let value = try? JSONDecoder().decode(Metadata.self, from: Data(contentsOf: URL(fileURLWithPath: metadataPath))) else { throw LaunchItemError.invalidBackup }
            metadata = value
        } else {
            // Backups created before startup management stored only the plist and its location.
            metadata = Metadata(mode: 0o644, uid: fileOwner ?? Int(getuid()), gid: fileOwner == nil ? Int(getgid()) : 0)
        }
        return Backup(path: pair.path, destination: pair.destination, data: try Data(contentsOf: URL(fileURLWithPath: pair.path)), metadata: metadata)
    }

    /// Stage inside a private directory so an original plist containing secrets is never briefly
    /// created with the process umask's public permissions. moveItem refuses an existing target.
    private func writeNew(_ data: Data, path: String, metadata: Metadata) throws {
        let fm = FileManager.default, parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let staging = parent.appendingPathComponent(".agentguard-" + UUID().uuidString)
        try fm.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: staging) }
        let temporary = staging.appendingPathComponent("item")
        try data.write(to: temporary, options: .withoutOverwriting)
        try fm.setAttributes(metadata.attributes, ofItemAtPath: temporary.path)
        try fm.moveItem(at: temporary, to: URL(fileURLWithPath: path))
    }

    private func newBackup(for original: Saved) throws -> Backup {
        let backup = Backup(path: files.backupDirectory + "/" + original.item.label + ".plist", destination: original.item.path,
                            data: original.data, metadata: original.metadata)
        var created: [String] = []
        let privateMetadata = Metadata(mode: 0o600, uid: fileOwner ?? Int(getuid()), gid: fileOwner == nil ? Int(getgid()) : 0)
        do {
            for (path, data) in [(backup.path, backup.data), (backup.path + ".location", Data(backup.destination.utf8)),
                                 (backup.path + ".metadata", try JSONEncoder().encode(backup.metadata))] {
                try writeNew(data, path: path, metadata: privateMetadata)
                created.append(path)
            }
        } catch {
            for path in created { try? FileManager.default.removeItem(atPath: path) }
            throw error
        }
        return backup
    }

    private func discard(_ backup: Backup) {
        // A failed cleanup preserves an extra recovery copy; it must not undo a committed change.
        for suffix in ["", ".location", ".metadata"] { try? FileManager.default.removeItem(atPath: backup.path + suffix) }
    }

    private func unload(_ old: [Saved]) throws {
        for saved in old where saved.loaded {
            guard execute(["bootout", domain + "/" + saved.item.label]).status == 0 else { throw LaunchItemError.operationFailed }
        }
    }

    private func restore(_ old: [Saved]) throws -> Bool {
        var leftStoppedUnloaded = false
        for saved in old {
            if !FileManager.default.fileExists(atPath: saved.item.path) { try writeNew(saved.data, path: saved.item.path, metadata: saved.metadata) }
            guard try Data(contentsOf: URL(fileURLWithPath: saved.item.path)) == saved.data else { throw LaunchItemError.rollbackFailed }
            if saved.loaded, !(try registration(saved.item.label).loaded) {
                if saved.running {
                    guard execute(["bootstrap", domain, saved.item.path]).status == 0 else { throw LaunchItemError.rollbackFailed }
                } else {
                    // Bootstrap may run RunAtLoad/KeepAlive jobs immediately. Preserve a previously
                    // stopped task's stopped state, and explicitly report the missing registration.
                    leftStoppedUnloaded = true
                }
            }
        }
        return leftStoppedUnloaded
    }

    @discardableResult
    public func install(profileID: String, launch: LaunchSettings, label: String, plist: Data, restart: Bool, stop: () throws -> Void) throws -> [String] {
        let snapshot = try snapshot(profileID)
        guard snapshot.orphans.isEmpty else { throw LaunchItemError.invalidManagedItem }
        let old = snapshot.saved
        if !old.contains(where: { $0.item.label == label }), try registration(label).loaded { throw LaunchItemError.invalidManagedItem }
        let path = (launch.runAtLogin ? files.automaticDirectory : files.manualDirectory) + "/" + label + ".plist"
        if !restart, old.count == 1, let existing = old.first, existing.item.path == path, existing.data == plist, existing.loaded {
            guard execute(["kickstart", domain + "/" + label]).status == 0 else { throw LaunchItemError.operationFailed }
            return snapshot.warnings
        }
        if FileManager.default.fileExists(atPath: path) && !old.contains(where: { $0.item.path == path }) { throw LaunchItemError.destinationExists }
        var original: Saved?, backup: Backup?
        if let originalLabel = launch.originalLabel {
            if FileManager.default.fileExists(atPath: files.backupDirectory + "/" + originalLabel + ".plist") {
                _ = try checkedBackup(originalLabel)
            } else {
                let item = try files.original(label: originalLabel, selectedPath: launch.originalPath)
                let state = try registration(originalLabel)
                let saved = Saved(item: item, data: try Data(contentsOf: URL(fileURLWithPath: item.path)), metadata: try Metadata(path: item.path),
                                  loaded: state.loaded, running: state.running)
                backup = try newBackup(for: saved)
                original = saved
            }
        }
        var wroteNew = false
        do {
            if let original {
                try unload([original])
                try FileManager.default.removeItem(atPath: original.item.path)
            }
            try unload(old)
            try stop()
            for saved in old { try FileManager.default.removeItem(atPath: saved.item.path) }
            let metadata = Metadata(mode: 0o644, uid: fileOwner ?? Int(getuid()), gid: fileOwner == nil ? Int(getgid()) : 0)
            try writeNew(plist, path: path, metadata: metadata)
            wroteNew = true
            guard execute(["bootstrap", domain, path]).status == 0 else { throw LaunchItemError.operationFailed }
        } catch {
            let failure = error
            do {
                if wroteNew {
                    if try registration(label).loaded {
                        guard execute(["bootout", domain + "/" + label]).status == 0 else { throw LaunchItemError.rollbackFailed }
                    }
                    try FileManager.default.removeItem(atPath: path)
                }
                let managedLeftStopped = try restore(old)
                let originalLeftStopped = try original.map { try restore([$0]) } ?? false
                if managedLeftStopped || originalLeftStopped { throw LaunchItemError.rollbackLeftStopped }
                if let backup { discard(backup) }
            } catch LaunchItemError.rollbackLeftStopped { throw LaunchItemError.rollbackLeftStopped }
            catch { throw LaunchItemError.rollbackFailed }
            throw failure
        }
        return snapshot.warnings
    }

    /// Stops the profile's managed jobs for this login: they are unloaded so launchd does not start
    /// them again, but their files stay, so the next login follows the saved setting.
    @discardableResult
    public func stop(profileID: String, stop: () throws -> Void) throws -> [String] {
        let snapshot = try snapshot(profileID, tolerateFileProblems: true)
        try unload(snapshot.saved)
        var warnings = snapshot.warnings
        for orphan in snapshot.orphans {
            let job = execute(["print", domain + "/" + orphan])
            guard LaunchctlClient.isManagedJob(job, launcherPath: files.launcherPath, profileID: profileID) else {
                warnings.append("遗留任务无法确认归属，没有停止：" + orphan); continue
            }
            if execute(["bootout", domain + "/" + orphan]).status != 0 { warnings.append("遗留启动任务未能停止：" + orphan) }
        }
        try stop()
        return warnings
    }

    /// Moves the managed launch item between the login directory and AgentGuard's own directory to
    /// match `runAtLogin`, leaving a loaded job running: only the next login reads the location.
    /// Returns false when there is nothing to move.
    @discardableResult
    public func relocate(profileID: String, runAtLogin: Bool) throws -> Bool {
        let snapshot = try snapshot(profileID)
        let target = runAtLogin ? files.automaticDirectory : files.manualDirectory
        var moved = false
        for saved in snapshot.saved {
            let url = URL(fileURLWithPath: saved.item.path)
            guard url.deletingLastPathComponent().path != target else { continue }
            let destination = target + "/" + url.lastPathComponent
            if FileManager.default.fileExists(atPath: destination) { throw LaunchItemError.destinationExists }
            try writeNew(saved.data, path: destination, metadata: saved.metadata)
            do { try FileManager.default.removeItem(atPath: saved.item.path) } catch {
                try? FileManager.default.removeItem(atPath: destination)
                throw error
            }
            moved = true
        }
        return moved
    }

    /// Where launch items disabled because they start a managed program outside AgentGuard are kept.
    public var disabledDirectory: String { files.backupDirectory + "/disabled" }

    /// Backs up another launch item, unloads it and removes it from its directory, so it no longer
    /// starts the program outside AgentGuard. The backup lets `restoreDisabled` put it back exactly.
    public func disable(label: String, path: String) throws {
        let item = try files.original(label: label, selectedPath: path)
        let state = try registration(label)
        let saved = Saved(item: item, data: try Data(contentsOf: URL(fileURLWithPath: item.path)), metadata: try Metadata(path: item.path),
                          loaded: state.loaded, running: state.running)
        let base = disabledDirectory + "/" + label + ".plist"
        if FileManager.default.fileExists(atPath: base) { throw LaunchItemError.destinationExists }
        let privateMetadata = Metadata(mode: 0o600, uid: fileOwner ?? Int(getuid()), gid: fileOwner == nil ? Int(getgid()) : 0)
        // The location is not secret; the App lists it so the user can see what was disabled.
        let publicMetadata = Metadata(mode: 0o644, uid: privateMetadata.uid, gid: privateMetadata.gid)
        var created: [String] = []
        do {
            for (file, data, metadata) in [(base, saved.data, privateMetadata), (base + ".metadata", try JSONEncoder().encode(saved.metadata), privateMetadata),
                                           (base + ".location", Data(item.path.utf8), publicMetadata)] {
                try writeNew(data, path: file, metadata: metadata)
                created.append(file)
            }
            try unload([saved])
            try FileManager.default.removeItem(atPath: item.path)
        } catch {
            let failure = error
            if !FileManager.default.fileExists(atPath: item.path) { try? writeNew(saved.data, path: item.path, metadata: saved.metadata) }
            if saved.loaded, (try? registration(label).loaded) == false { _ = execute(["bootstrap", domain, item.path]) }
            for file in created { try? FileManager.default.removeItem(atPath: file) }
            throw failure
        }
    }

    /// Labels of launch items disabled by `disable`, with the location each came from.
    public func disabledItems() -> [(label: String, location: String)] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: disabledDirectory)) ?? []
        return names.filter { $0.hasSuffix(".plist") }.sorted().compactMap { name in
            let location = try? String(contentsOfFile: disabledDirectory + "/" + name + ".location", encoding: .utf8)
            return location.map { (String(name.dropLast(6)), $0) }
        }
    }

    /// Puts a disabled launch item back where it was and loads it; it then runs outside AgentGuard.
    public func restoreDisabled(label: String) throws {
        guard !label.isEmpty, label.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0) }),
              !label.hasPrefix(".") else { throw LaunchItemError.invalidBackup }
        let base = disabledDirectory + "/" + label + ".plist"
        guard let data = FileManager.default.contents(atPath: base), let item = LaunchItem(path: base, data: data), item.label == label,
              let destination = try? String(contentsOfFile: base + ".location", encoding: .utf8), files.isOriginalLocation(destination),
              let metadataData = FileManager.default.contents(atPath: base + ".metadata"),
              let metadata = try? JSONDecoder().decode(Metadata.self, from: metadataData) else { throw LaunchItemError.invalidBackup }
        if FileManager.default.fileExists(atPath: destination) { throw LaunchItemError.destinationExists }
        guard !(try registration(label).loaded) else { throw LaunchItemError.destinationExists }
        try writeNew(data, path: destination, metadata: metadata)
        guard execute(["bootstrap", domain, destination]).status == 0 else {
            try? FileManager.default.removeItem(atPath: destination)
            throw LaunchItemError.operationFailed
        }
        for suffix in ["", ".location", ".metadata"] { try? FileManager.default.removeItem(atPath: base + suffix) }
    }

    @discardableResult
    public func remove(profileID: String, restoreOriginal label: String?, hasLaunchSettings: Bool = true, deleting: Bool = false,
                       stop: () throws -> Void, commit: () throws -> Void = {}) throws -> [String] {
        // Explicit restoration still requires a valid backup. Ordinary deletion can complete with
        // a warning when the OS cannot enumerate unrelated jobs or a source file is damaged.
        let backup = try label.map(checkedBackup)
        let scan: (items: [LaunchItem], problems: [String])
        do { scan = try files.managedScan(profileID: profileID) }
        catch {
            guard deleting && label == nil else { throw error }
            try stop(); try commit()
            return ["配置已删除，但暂时无法检查系统启动文件，请检查是否有遗留启动任务。"]
        }
        if !hasLaunchSettings && scan.items.isEmpty && scan.problems.isEmpty && backup == nil {
            try stop(); try commit()
            return []
        }
        let snapshot = try snapshot(profileID, tolerateFileProblems: backup == nil, requireCompleteRegistry: backup != nil, scan: scan)
        let old = snapshot.saved
        // Restoring an unrestricted original is safe only after every previous managed job has
        // stopped. Preflight orphan identities before changing files or unloading known jobs.
        var verifiedOrphans: [String] = []
        if backup != nil {
            for orphan in snapshot.orphans {
                let job = execute(["print", domain + "/" + orphan])
                if LaunchctlClient.registration(job)?.loaded == false { continue }
                guard LaunchctlClient.isManagedJob(job, launcherPath: files.launcherPath, profileID: profileID) else {
                    throw LaunchItemError.invalidManagedItem
                }
                verifiedOrphans.append(orphan)
            }
        }
        var wroteOriginal = false
        var stoppedOrphans = false
        do {
            try unload(old)
            for orphan in verifiedOrphans {
                guard execute(["bootout", domain + "/" + orphan]).status == 0 else { throw LaunchItemError.operationFailed }
                stoppedOrphans = true
            }
            try stop()
            for saved in old { try FileManager.default.removeItem(atPath: saved.item.path) }
            if let backup {
                try writeNew(backup.data, path: backup.destination, metadata: backup.metadata)
                wroteOriginal = true
                guard execute(["bootstrap", domain, backup.destination]).status == 0 else { throw LaunchItemError.operationFailed }
            }
            try commit()
        } catch {
            let failure = error
            do {
                if wroteOriginal, let backup, let label {
                    if try registration(label).loaded {
                        guard execute(["bootout", domain + "/" + label]).status == 0 else { throw LaunchItemError.rollbackFailed }
                    }
                    try FileManager.default.removeItem(atPath: backup.destination)
                }
                let leftStopped = try restore(old)
                if leftStopped || stoppedOrphans { throw LaunchItemError.rollbackLeftStopped }
            } catch LaunchItemError.rollbackLeftStopped { throw LaunchItemError.rollbackLeftStopped }
            catch { throw LaunchItemError.rollbackFailed }
            throw failure
        }
        if let backup { discard(backup) }
        var warnings = snapshot.warnings
        for orphan in snapshot.orphans where backup == nil {
            let job = execute(["print", domain + "/" + orphan])
            guard LaunchctlClient.isManagedJob(job, launcherPath: files.launcherPath, profileID: profileID) else {
                warnings.append("遗留任务无法确认归属，已保留：" + orphan); continue
            }
            if execute(["bootout", domain + "/" + orphan]).status != 0 { warnings.append("遗留启动任务未能移除：" + orphan) }
        }
        return warnings
    }
}
