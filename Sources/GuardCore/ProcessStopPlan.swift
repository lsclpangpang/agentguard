/// Only previously established identity baselines may authorize signaling a process. Missing
/// collector data reduces coverage; it does not turn a stop/restart into an all-or-nothing action.
public struct ProcessStopPlan: Equatable, Sendable {
    public var targets: [Int32: UInt64] = [:]
    public var skipped: [Int32] = []

    public init(processes: [ProcessKey], births: [ProcessKey: UInt64], currentBirth: (Int32) -> UInt64?) {
        for key in processes.sorted() {
            guard let current = currentBirth(key.pid) else { continue }
            guard let expected = births[key] else { skipped.append(key.pid); continue }
            if expected == current { targets[key.pid] = expected }
        }
        skipped = Array(Set(skipped)).sorted()
    }

    public var warnings: [String] {
        skipped.isEmpty ? [] : ["有 \(skipped.count) 个子程序缺少可靠的身份记录，已跳过直接终止。请检查是否有旧程序继续运行。"]
    }
}

/// What a stop actually achieved, so "stopped" is only claimed for processes seen to exit.
public struct StopOutcome: Codable, Equatable, Sendable {
    /// Exited after the polite request.
    public var stopped: [Int32]
    /// Exited only after being killed.
    public var forced: [Int32]
    /// Still running after being killed.
    public var survivors: [Int32]
    /// Not signaled: no reliable identity record.
    public var skipped: [Int32]
    /// Instances whose process tree is not fully known (restored after a Helper restart, or the
    /// collector lost events): processes started outside our view may still be running.
    public var untrackedInstances: [Int]

    public init(stopped: [Int32] = [], forced: [Int32] = [], survivors: [Int32] = [], skipped: [Int32] = [], untrackedInstances: [Int] = []) {
        self.stopped = stopped
        self.forced = forced
        self.survivors = survivors
        self.skipped = skipped
        self.untrackedInstances = untrackedInstances
    }

    public var isComplete: Bool { survivors.isEmpty && skipped.isEmpty && untrackedInstances.isEmpty }

    /// Confirmed results, for an informational notice.
    public var confirmed: [String] {
        let ended = (stopped + forced).sorted()
        guard !ended.isEmpty else { return ["没有需要停止的受管进程"] }
        var lines = ["已停止本次跟踪到的 \(ended.count) 个进程（PID \(Self.list(ended))）"]
        if !forced.isEmpty { lines.append("其中 PID \(Self.list(forced)) 没有及时退出，已强制结束") }
        return lines
    }

    /// What could not be confirmed, for a warning.
    public var unconfirmed: [String] {
        var lines: [String] = []
        if !survivors.isEmpty { lines.append("PID \(Self.list(survivors)) 强制结束后仍在运行，请手动检查") }
        if !skipped.isEmpty { lines.append("PID \(Self.list(skipped)) 缺少可靠的身份记录，没有被结束，请检查它们是否仍在运行") }
        if !untrackedInstances.isEmpty {
            lines.append("运行副本 #\(untrackedInstances.map(String.init).joined(separator: "、#")) 的子进程没有被完整跟踪（Helper 重启或活动记录中断），可能还有子进程在运行")
        }
        return lines
    }

    private static func list(_ pids: [Int32]) -> String { pids.sorted().map(String.init).joined(separator: "、") }
}

/// Result of an action that changed what is running, returned instead of a bare success.
public struct OperationReport: Codable, Equatable, Sendable {
    public var stop: StopOutcome?
    public var warnings: [String]

    public init(stop: StopOutcome? = nil, warnings: [String] = []) {
        self.stop = stop
        self.warnings = warnings
    }

    public var notes: [String] { stop?.confirmed ?? [] }
    public var problems: [String] { (stop?.unconfirmed ?? []) + warnings }
}
