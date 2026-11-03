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
