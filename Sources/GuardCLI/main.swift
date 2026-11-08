import Foundation
import GuardCore
import GuardPlatform

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

let command: CLICommand
do {
    command = try CLICommand.parse(Array(CommandLine.arguments.dropFirst()))
} catch let CLIError.usage(message) {
    fail("\(message)\n\n\(CLICommand.usage)", code: 64)
} catch {
    fail("\(error)")
}

switch command {
case .help:
    print(CLICommand.usage)
case .version:
    print("guard \(AgentGuardVersion.current)")
case let .run(profileID, arguments):
    do {
        try ManagedStart.run(profileID: profileID, kind: .interactive(command: arguments, workingDirectory: FileManager.default.currentDirectoryPath))
    } catch {
        // Fail closed: never fall back to running the command unprotected.
        fail("未启动：\(error)")
    }
case let .diagnoseRead(profileID, path, json):
    #if os(macOS)
    do {
        let response = try HelperClient().send(.status)
        guard case let .status(status) = response else {
            if case let .failure(code) = response { fail(HelperFailure.message(for: code)) }
            fail("意外的响应")
        }
        guard let profile = status.profiles.first(where: { $0.profileID == profileID }) else {
            fail("没有找到配置档：\(profileID)")
        }
        guard !profile.runtimeInstances.isEmpty else { fail("当前没有可核验的受管运行实例") }
        let reports = profile.runtimeInstances.sorted { $0.id < $1.id }.map { instance in
            AccessBoundaryDiagnostics.check(instanceID: instance.id, revision: instance.revision,
                                             pid: instance.checkedPID,
                                             expectedStartTime: instance.checkedProcessStartTime,
                                             path: path, processStartTime: ProcessFacts.startTime,
                                             probe: SystemSandboxProbe())
        }
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(reports), as: UTF8.self))
        } else {
            print("当前权限核验：\(path)")
            print("此检查不读取目标内容，也不证明历史访问读取了正文。")
            for report in reports {
                print("实例 \(report.instanceID)，修订 \(report.revision)：\(report.identity.displayText)")
                if let read = report.contentRead, let metadata = report.metadataRead, let write = report.contentWrite {
                    print("  正文读取：\(read.displayText)；属性查询：\(metadata.displayText)；写入：\(write.displayText)")
                }
            }
        }
    } catch {
        fail("\(error)")
    }
    #else
    fail(PlatformError.unsupported.description)
    #endif
case .list, .status:
    #if os(macOS)
    do {
        let response = try HelperClient().send(.status)
        guard case let .status(report) = response else {
            if case let .failure(code) = response { fail(HelperFailure.message(for: code)) }
            fail("意外的响应")
        }
        if case .status(json: true) = command {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(report), as: UTF8.self))
        } else {
            for profile in report.profiles {
                let pending = profile.pendingCount > 0 ? "，\(profile.pendingCount) 个待定项" : ""
                print("\(profile.profileID)\t修订 \(profile.savedRevision)\t\(profile.mode.displayName)\t\(profile.revisionState.displayText)\(pending)")
            }
            if report.profiles.isEmpty { print("还没有配置档") }
            for problem in report.collectorProblems { print("采集器：\(problem)") }
        }
    } catch {
        fail("\(error)")
    }
    #else
    fail(PlatformError.unsupported.description)
    #endif
}
