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
