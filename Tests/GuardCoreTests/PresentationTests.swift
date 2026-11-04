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
                == "/opt/bin 落在可写目录里，必须限定哈希才能执行")
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
