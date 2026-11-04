import Testing
@testable import GuardCore

@Suite struct ProcessStopPlanTests {
    @Test func missingIdentityDoesNotBlockVerifiedTargets() {
        let known = ProcessKey(pid: 10, version: 1), unknown = ProcessKey(pid: 20, version: 1)
        let plan = ProcessStopPlan(processes: [unknown, known], births: [known: 100], currentBirth: { $0 == 10 ? 100 : 200 })
        #expect(plan.targets == [10: 100])
        #expect(plan.skipped == [20] && plan.warnings.count == 1)
    }

    @Test func recycledPIDsAndExitedProcessesAreNeverTargets() {
        let reused = ProcessKey(pid: 10, version: 1), exited = ProcessKey(pid: 20, version: 1)
        let plan = ProcessStopPlan(processes: [reused, exited], births: [reused: 100, exited: 200], currentBirth: { $0 == 10 ? 101 : nil })
        #expect(plan.targets.isEmpty && plan.skipped.isEmpty && plan.warnings.isEmpty)
    }

    @Test func duplicateUnknownProcessesOnlyWarnOnce() {
        let unknown = ProcessKey(pid: 20, version: 1)
        let plan = ProcessStopPlan(processes: [unknown, unknown], births: [:], currentBirth: { _ in 200 })
        #expect(plan.targets.isEmpty && plan.skipped == [20])
    }
}
