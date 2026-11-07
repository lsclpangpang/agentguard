import Foundation
import Testing
@testable import GuardCore

@Suite struct PresentationTests {
    @Test func failureCodesHaveChineseMessages() {
        #expect(HelperFailure.message(for: "managed_caller") == "受管进程不能修改权限或再启动受管实例")
        #expect(HelperFailure.message(for: "authorization_missing") == "没有完成本次变更的系统认证")
        #expect(HelperFailure.message(for: "something_new") == "Helper 拒绝了请求（something_new）")
    }

    @Test func revisionStatesHaveDisplayText() {
        #expect(RevisionState.applied(running: true).displayText == "当前权限已生效")
        #expect(RevisionState.applied(running: false).displayText == "未运行")
        #expect(RevisionState.oldInstancesAlive(residual: [ProcessKey(pid: 1, version: 1), ProcessKey(pid: 2, version: 1)], newInstanceRunning: true).displayText == "运行中 · 权限待更新（旧副本还有 2 个进程）")
        #expect(RevisionState.unconfirmed(instances: [3]).displayText == "子进程跟踪记录不完整")
        #expect(RevisionState.awaitingVerification.displayText == "正在确认保护")
        #expect(RevisionState.verificationFailed.displayText == "保护未通过确认")
        #expect(RevisionState.inconsistent.displayText == "运行中的权限与保存的不一致")
    }

    @Test func homebrewPrefixDetection() {
        #expect(AgentGuardConfig.detectHomebrewPrefix { $0 == "/opt/homebrew/bin/brew" } == "/opt/homebrew")
        #expect(AgentGuardConfig.detectHomebrewPrefix { $0 == "/usr/local/bin/brew" } == "/usr/local")
        #expect(AgentGuardConfig.detectHomebrewPrefix { _ in false } == "/opt/homebrew")
    }

    @Test func ownerRecordRoundTrips() throws {
        let owner = OwnerRecord(uid: 501, home: "/Users/me")
        #expect(try OwnerRecord.decode(owner.encode()) == owner)
        #expect(throws: (any Error).self) { try OwnerRecord.decode(Data("{}".utf8)) }
    }

    @Test func modeDisplayNames() {
        #expect(Mode.enforce.displayName == "保护中")
        #expect(Mode.restrictedLearning.displayName == "保护中 · 记录更多活动")
        #expect(Mode.unprotectedObserve.displayName == "无保护观察")
    }

    /// The Helper answers every one of these with the single code `compile_error`. Nothing else in
    /// the UI can say which path was refused, so each case has to carry its own instruction.
    @Test func compileErrorsNameThePathThatWasRefused() {
        #expect(CompileError.overlapsProtectedPath(grant: "/Users/me/Library", protected: "/Users/me/Library/LaunchAgents").message
                == "/Users/me/Library 与受保护目录 /Users/me/Library/LaunchAgents 重叠，请选 /Users/me/Library/LaunchAgents 之外更具体的目录")
        #expect(CompileError.forbiddenPath("/Users/me").message
                    .hasPrefix("/Users/me 不能整体放行"))
        #expect(CompileError.forbiddenPath("/").message.hasPrefix("/ 不能整体放行"))
        #expect(CompileError.invalidPath("/x", .notAbsolute("x")).message == "/x 不是可用的路径：不是绝对路径（x）")
        #expect(CompileError.nestedReadOnlyInsideReadWrite(inner: "/a", outer: "/").message
                == "/a 是只读，但外层的 / 是读写，两条规则互相矛盾。要收回写权限，请先将外层目录改为只读或移除它的读写授权")
        #expect(CompileError.mutableExecutableWithoutHash("/opt/bin").message
                == "/opt/bin 落在受管程序可写的目录里，程序可以替换它，所以不能直接放行执行。请改为放行不可写位置的程序")
    }

    @Test func everyCompileErrorHasAMessage() {
        let all: [CompileError] = [
            .invalidProfileID("Bad"), .invalidRawRule("(deny)"), .invalidPath("/x", .empty),
            .unknownTemplate("gone"), .templateVersionMismatch(id: "t", requested: 2, available: 1),
            .forbiddenPath("/"), .overlapsProtectedPath(grant: "/a", protected: "/b"),
            .nestedReadOnlyInsideReadWrite(inner: "/ba", outer: "/b"), .invalidPort(0),
            .invalidHash("zz"), .conflictingHashes("/e"), .mutableExecutableWithoutHash("/e"),
            .invalidLaunchLabel("bad label"),
        ]
        for error in all {
            #expect(!error.message.isEmpty)
            #expect(!error.message.contains("Optional("))
        }
    }
}

@Suite struct ProgramStatusSummaryTests {
    func status(_ state: RevisionState, unmanaged: [Int32] = [], untracked: [Int] = []) -> ProfileStatusReport {
        ProfileStatusReport(profileID: "knodo", savedRevision: 2, mode: .enforce, revisionState: state, runningInstances: [1], pendingCount: 0,
                            unmanagedProcesses: unmanaged, untrackedInstances: untracked)
    }

    @Test func savedButNotAppliedSaysRestartAndApply() {
        let s = ProgramStatusSummary.evaluate(status(.oldInstancesAlive(residual: [ProcessKey(pid: 1, version: 1)], newInstanceRunning: false)),
                                              freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.headline == "运行中 · 权限待更新")
        #expect(s.impact.contains("重启 Knodo 可让这些进程加载新权限"))
        #expect(s.next == .restartAndApply)
    }

    @Test func unprotectedObservationIsNeverGreen() {
        var report = status(.applied(running: true))
        report.mode = .unprotectedObserve
        let s = ProgramStatusSummary.evaluate(report, freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.level == .problem && s.headline == "运行中 · 没有保护")
        var stopped = status(.applied(running: false))
        stopped.mode = .unprotectedObserve
        stopped.runningInstances = []
        #expect(ProgramStatusSummary.evaluate(stopped, freshness: .current, programName: "Knodo", hasLaunch: true).level == .problem)
    }

    @Test func staleIsNeverGreen() {
        let s = ProgramStatusSummary.evaluate(status(.applied(running: true)), freshness: .stale(confirmedAt: nil), programName: "Knodo", hasLaunch: true)
        #expect(s.headline == "状态待确认" && s.level == .attention)
    }

    @Test func untrackedCopiesAreNotClaimedProtected() {
        let s = ProgramStatusSummary.evaluate(status(.applied(running: true), untracked: [1]), freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.level == .attention && s.next == .checkAndRecover)
        #expect(s.impact.contains("不代表所有旧权限已经收回"))
    }

    @Test func unmanagedCopiesAreAProblem() {
        let s = ProgramStatusSummary.evaluate(status(.applied(running: true), unmanaged: [9]), freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.level == .problem && s.next == .stopUnmanaged)
        #expect(s.headline == "运行中 · 当前副本的权限检查已通过")
    }

    @Test func missingPathsArePendingAndDoNotRecommendRestart() {
        var report = status(.awaitingVerification)
        report.verificationPending = ["路径暂不存在，尚未核验：/tmp/transient.lock"]
        let s = ProgramStatusSummary.evaluate(report, freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.headline == "部分权限暂未确认" && s.level == .attention)
        #expect(s.next == .checkAndRecover)
        #expect(s.impact.contains("自动重新检查"))
    }

    @Test func currentVerificationAndHistoricalGapAreBothVisible() {
        var report = status(.unconfirmed(instances: [1]), untracked: [1])
        report.runtimeRevisionState = .applied(running: true)
        report.runningInstances = [4]
        report.verificationDeferred = ["/tmp/transient.lock"]
        let s = ProgramStatusSummary.evaluate(report, freshness: .current, programName: "Knodo", hasLaunch: true)
        #expect(s.headline == "运行中 · 当前副本的权限检查已通过")
        #expect(s.level == .attention && s.next == .checkAndRecover)
        #expect(s.impact.contains("跟踪记录不完整"))
        #expect(s.impact.contains("出现后自动补查"))
        report.runtimeRevisionState = .verificationFailed
        #expect(ProgramStatusSummary.evaluate(report, freshness: .current, programName: "Knodo", hasLaunch: true).level == .problem)
    }
}
