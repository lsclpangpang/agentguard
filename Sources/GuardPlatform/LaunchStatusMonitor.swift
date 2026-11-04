import Foundation
import GuardCore

public struct LaunchStatusRequest: Equatable, Sendable {
    public let id: String
    public let launch: LaunchSettings?
    public init(id: String, launch: LaunchSettings?) { self.id = id; self.launch = launch }
}

/// Slow system queries never run on the Helper's request/event queue. Repeated refreshes coalesce,
/// and a result started before an edit or startup operation cannot overwrite the newer state.
public final class LaunchStatusMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private let worker: DispatchQueue
    private let fetch: @Sendable ([LaunchStatusRequest]) -> [String: LaunchAgentStatus]
    private let clock: @Sendable () -> Date
    private let maximumAge: TimeInterval
    private var requests: [LaunchStatusRequest] = []
    private var generation = 0
    private var inFlight = false
    private var refreshPending = false
    private var cached: [String: LaunchAgentStatus] = [:]
    private var updatedAt: Date?

    public init(maximumAge: TimeInterval = 30, clock: @escaping @Sendable () -> Date = { Date() },
                fetch: @escaping @Sendable ([LaunchStatusRequest]) -> [String: LaunchAgentStatus]) {
        self.maximumAge = maximumAge; self.clock = clock; self.fetch = fetch
        worker = DispatchQueue(label: "com.lsclpangpang.agentguard.startup-status", qos: .utility)
    }

    public func refresh(_ latest: [LaunchStatusRequest], invalidate: Bool = false) {
        lock.lock()
        if requests != latest || invalidate {
            generation += 1
            cached = cached.filter { id, _ in latest.contains { $0.id == id && requests.contains($0) } }
            requests = latest
            updatedAt = nil
        }
        if inFlight { refreshPending = true; lock.unlock(); return }
        inFlight = true
        let capturedGeneration = generation
        lock.unlock()
        worker.async { [self] in
            var batch = latest, batchGeneration = capturedGeneration
            while true {
                let result = fetch(batch)
                lock.lock()
                if generation == batchGeneration { cached = result; updatedAt = clock() }
                if refreshPending {
                    refreshPending = false
                    batch = requests; batchGeneration = generation
                    lock.unlock()
                } else {
                    inFlight = false
                    lock.unlock()
                    return
                }
            }
        }
    }

    /// A bounded lock-only read: no filesystem access, process launch, or waiting for a refresh.
    public func status(for id: String) -> LaunchAgentStatus {
        lock.lock(); defer { lock.unlock() }
        var status = cached[id] ?? LaunchAgentStatus(registered: false, running: false, runAtLogin: false, canRestoreOriginal: false)
        if updatedAt == nil { status.problem = "正在更新启动状态…" }
        else if clock().timeIntervalSince(updatedAt!) > maximumAge { status.problem = "启动状态暂未更新，下面的状态可能已变化" }
        return status
    }
}
