#if os(macOS)
import Foundation
import GuardCore

/// The only XPC method: a JSON-encoded HelperRequest in, a JSON-encoded HelperResponse out.
@objc public protocol AgentGuardHelperXPC {
    func handle(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

private final class ReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Result<Data, Error>?

    func set(_ value: Result<Data, Error>) {
        lock.lock(); defer { lock.unlock() }
        if stored == nil { stored = value }
    }

    var value: Result<Data, Error>? {
        lock.lock(); defer { lock.unlock() }
        return stored
    }
}

public final class HelperClient {
    public init() {}

    public func send(_ request: HelperRequest, timeout: TimeInterval = 60) throws -> HelperResponse {
        let connection = NSXPCConnection(machServiceName: AgentGuardConfig.helperServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AgentGuardHelperXPC.self)
        connection.resume()
        defer { connection.invalidate() }

        let payload = try HelperWire.encode(request)
        let box = ReplyBox()
        let done = DispatchSemaphore(value: 0)
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            box.set(.failure(error))
            done.signal()
        }
        guard let helper = proxy as? AgentGuardHelperXPC else { throw PlatformError.helper("无法连接，请先在 App 中安装 Helper") }
        helper.handle(payload) { reply in
            box.set(.success(reply))
            done.signal()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut { throw PlatformError.helper("响应超时") }
        guard let result = box.value else { throw PlatformError.helper("没有响应") }
        switch result {
        case let .success(data): return try HelperWire.decodeResponse(data)
        case let .failure(error): throw PlatformError.helper(error.localizedDescription)
        }
    }
}
#endif
