import Foundation

#if os(macOS)
import GuardCore
import GuardPlatform

final class HelperSession: NSObject, AgentGuardHelperXPC {
    private let core: HelperCore
    private let identity: CallerIdentity
    private let process: ProcessKey

    init(core: HelperCore, identity: CallerIdentity, process: ProcessKey) {
        self.core = core
        self.identity = identity
        self.process = process
    }

    func handle(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        core.queue.async { reply(self.core.handle(request, identity: self.identity, process: self.process)) }
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let core: HelperCore

    init(core: HelperCore) {
        self.core = core
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let token = CodeSigning.auditToken(of: connection),
              let identity = try? CodeSigning.identity(of: token, uid: Int(connection.effectiveUserIdentifier))
        else { return false }
        if let requirement = core.codeSigningRequirement { connection.setCodeSigningRequirement(requirement) }
        connection.exportedInterface = NSXPCInterface(with: AgentGuardHelperXPC.self)
        connection.exportedObject = HelperSession(core: core, identity: identity, process: CodeSigning.processKey(token))
        connection.resume()
        return true
    }
}

// Both when Bundle.main resolves to AgentGuard.app and when it does not, the executable's
// directory is Contents/MacOS, where the binaries we trust live.
let macOSDirectory = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).deletingLastPathComponent().path
let core = HelperCore(bundleMacOSDirectory: macOSDirectory)
UserAuthorization.ensureRightDefinition()
let delegate = ListenerDelegate(core: core)
let listener = NSXPCListener(machServiceName: AgentGuardConfig.helperServiceName)
listener.delegate = delegate
listener.resume()
core.start()
RunLoop.main.run()
#else
FileHandle.standardError.write(Data("agentguard-helper 只能在 macOS 上运行\n".utf8))
exit(1)
#endif
