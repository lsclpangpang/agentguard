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
        #expect(RevisionState.applied(running: true).displayText == "已生效")
        #expect(RevisionState.applied(running: false).displayText == "已停止")
        #expect(RevisionState.oldInstancesAlive(residual: [ProcessKey(pid: 1, version: 1), ProcessKey(pid: 2, version: 1)], newInstanceRunning: true).displayText == "待生效：旧实例仍有 2 个进程")
        #expect(RevisionState.unconfirmed(instances: [3]).displayText == "无法确认旧实例是否已退出")
        #expect(RevisionState.awaitingVerification.displayText == "等待验收")
        #expect(RevisionState.verificationFailed.displayText == "验收失败")
        #expect(RevisionState.inconsistent.displayText == "运行修订与已保存修订不一致")
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
        #expect(Mode.enforce.displayName == "强制保护")
        #expect(Mode.restrictedLearning.displayName == "受限学习")
        #expect(Mode.unprotectedObserve.displayName == "无保护观察")
    }
}
