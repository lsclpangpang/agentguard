import Foundation
import GuardCore
import GuardPlatform

// Started by the root-owned LaunchAgent: `agentguard-launcher launch <profile>`.
func fail(_ message: String, code: Int32) -> Never {
    FileHandle.standardError.write(Data(("agentguard-launcher: " + message + "\n").utf8))
    exit(code)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 2, arguments[0] == "launch", ProfileID.isValid(arguments[1]) else {
    fail("用法：agentguard-launcher launch <配置档>", code: 64)
}
guard getuid() != 0 else { fail("不能以 root 启动受管对象", code: 78) }

do {
    let config = try ManagedStart.config(uid: getuid())
    // /Library/LaunchAgents loads for every GUI user; only the owner runs managed objects.
    if let data = FileManager.default.contents(atPath: config.ownerPath), let owner = try? OwnerRecord.decode(data), owner.uid != Int(getuid()) {
        exit(0)
    }
    try ManagedStart.run(profileID: arguments[1], kind: .agent)
} catch {
    // Exit non-zero and stay stopped; launchd retries per the job's throttle, never unprotected.
    fail("未启动：\(error)", code: 78)
}
