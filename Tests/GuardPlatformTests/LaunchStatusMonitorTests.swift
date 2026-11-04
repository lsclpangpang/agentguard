import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

private final class StatusFetchFixture: @unchecked Sendable {
    let started = DispatchSemaphore(value: 0)
    let proceed = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var batches: [[LaunchStatusRequest]] = []
    private var date = Date(timeIntervalSince1970: 100)

    var calls: [[LaunchStatusRequest]] { lock.lock(); defer { lock.unlock() }; return batches }
    func clock() -> Date { lock.lock(); defer { lock.unlock() }; return date }
    func advance(_ seconds: TimeInterval) { lock.lock(); date += seconds; lock.unlock() }

    func fetch(_ requests: [LaunchStatusRequest]) -> [String: LaunchAgentStatus] {
        lock.lock(); batches.append(requests); lock.unlock()
        started.signal()
        proceed.wait()
        return Dictionary(uniqueKeysWithValues: requests.map {
            ($0.id, LaunchAgentStatus(registered: true, running: true, runAtLogin: $0.launch?.runAtLogin ?? false, canRestoreOriginal: false))
        })
    }
}

private func eventually(_ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(2)
    while !condition() {
        guard Date() < deadline else { return false }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
    return true
}

@Suite struct LaunchStatusMonitorTests {
    @Test func repeatedStatusReadsFinishWhileSystemQueriesAreBlocked() {
        let f = StatusFetchFixture(), readFinished = DispatchSemaphore(value: 0)
        let monitor = LaunchStatusMonitor(fetch: f.fetch)
        defer { f.proceed.signal() }
        monitor.refresh([.init(id: "demo", launch: nil)])
        #expect(f.started.wait(timeout: .now() + 2) == .success)
        DispatchQueue.global().async {
            for _ in 0..<200 { _ = monitor.status(for: "demo") }
            readFinished.signal()
        }
        #expect(readFinished.wait(timeout: .now() + 1) == .success)
        #expect(f.calls.count == 1)
        #expect(monitor.status(for: "demo").problem != nil)
    }

    @Test func refreshesCoalesceAndOldResultsCannotRestoreADeletedProfile() async {
        let f = StatusFetchFixture(), old = [LaunchStatusRequest(id: "old", launch: nil)]
        let latest = [LaunchStatusRequest(id: "new", launch: nil)]
        let monitor = LaunchStatusMonitor(fetch: f.fetch)
        defer { f.proceed.signal(); f.proceed.signal() }
        monitor.refresh(old)
        #expect(f.started.wait(timeout: .now() + 2) == .success)
        for _ in 0..<100 { monitor.refresh(latest) }
        f.proceed.signal()
        #expect(f.started.wait(timeout: .now() + 2) == .success)
        // The old query completed, but its result must still be discarded while the new one waits.
        #expect(!monitor.status(for: "old").registered)
        #expect(monitor.status(for: "new").problem != nil)
        f.proceed.signal()
        #expect(await eventually { monitor.status(for: "new").problem == nil })
        #expect(monitor.status(for: "new").registered && !monitor.status(for: "old").registered)
        #expect(f.calls == [old, latest])
    }

    @Test func explicitInvalidationDiscardsAnOlderQueryForTheSameProfile() async {
        let f = StatusFetchFixture(), requests = [LaunchStatusRequest(id: "demo", launch: nil)]
        let monitor = LaunchStatusMonitor(fetch: f.fetch)
        defer { f.proceed.signal(); f.proceed.signal() }
        monitor.refresh(requests)
        #expect(f.started.wait(timeout: .now() + 2) == .success)
        monitor.refresh(requests, invalidate: true)
        f.proceed.signal()
        #expect(f.started.wait(timeout: .now() + 2) == .success)
        #expect(!monitor.status(for: "demo").registered && monitor.status(for: "demo").problem != nil)
        f.proceed.signal()
        #expect(await eventually { monitor.status(for: "demo").problem == nil })
        #expect(monitor.status(for: "demo").registered && f.calls.count == 2)
    }

    @Test func changedLaunchSettingsCannotShowTheOldStartupModeAsCurrent() async {
        let f = StatusFetchFixture()
        let monitor = LaunchStatusMonitor(fetch: f.fetch)
        defer { f.proceed.signal(); f.proceed.signal() }
        let automatic = LaunchSettings(executable: "/bin/sleep", arguments: ["60"], workingDirectory: nil, originalLabel: nil,
                                       restartOnCleanExit: false, runAtLogin: true)
        var manual = automatic; manual.runAtLogin = false
        monitor.refresh([.init(id: "demo", launch: automatic)])
        f.proceed.signal()
        #expect(await eventually { monitor.status(for: "demo").problem == nil })
        #expect(monitor.status(for: "demo").runAtLogin)
        monitor.refresh([.init(id: "demo", launch: manual)])
        #expect(!monitor.status(for: "demo").runAtLogin && monitor.status(for: "demo").problem != nil)
        f.proceed.signal()
        #expect(await eventually { monitor.status(for: "demo").problem == nil })
        #expect(!monitor.status(for: "demo").runAtLogin)
    }

    @Test func expiredCacheRetainsTheLastStateWithAnExplicitWarning() async {
        let f = StatusFetchFixture()
        let monitor = LaunchStatusMonitor(maximumAge: 30, clock: f.clock, fetch: f.fetch)
        defer { f.proceed.signal() }
        monitor.refresh([.init(id: "demo", launch: nil)])
        f.proceed.signal()
        #expect(await eventually { monitor.status(for: "demo").problem == nil })
        f.advance(31)
        #expect(monitor.status(for: "demo").registered && monitor.status(for: "demo").problem?.contains("暂未更新") == true)
        #expect(f.calls.count == 1)
    }
}
