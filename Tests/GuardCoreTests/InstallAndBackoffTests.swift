import Testing
@testable import GuardCore

@Suite struct HelperInstallTests {
    @Test func alreadyEnabledNeedsNothing() {
        let outcome = HelperInstallOutcome.evaluate(statusAfter: .enabled, registerError: nil)
        #expect(outcome == HelperInstallOutcome(notice: nil, error: nil, openLoginItems: false))
    }

    @Test func firstRegistrationRejectionMeansAwaitingApproval() {
        // smd refuses to bootstrap a new daemon until the user allows it, but the item is registered.
        let outcome = HelperInstallOutcome.evaluate(statusAfter: .requiresApproval, registerError: .notPermitted)
        #expect(outcome.error == nil)
        #expect(outcome.notice == "Helper 已登记，请在“系统设置 > 通用 > 登录项 > 允许在后台”中允许 AgentGuard")
        #expect(outcome.openLoginItems)
    }

    @Test func approvalPendingWithoutErrorIsTheSame() {
        #expect(HelperInstallOutcome.evaluate(statusAfter: .requiresApproval, registerError: nil).openLoginItems)
    }

    @Test func otherErrorsAreReported() {
        let outcome = HelperInstallOutcome.evaluate(statusAfter: .notRegistered, registerError: .other("签名无效"))
        #expect(outcome.error == "安装 Helper 失败：签名无效")
        #expect(!outcome.openLoginItems)
    }

    @Test func notPermittedWithoutRegistrationIsAFailure() {
        let outcome = HelperInstallOutcome.evaluate(statusAfter: .notFound, registerError: .notPermitted)
        #expect(outcome.error != nil)
    }

    @Test func classifiesServiceManagementErrors() {
        #expect(HelperRegisterError.classify(domain: "SMAppServiceErrorDomain", code: 1, description: "x") == .notPermitted)
        #expect(HelperRegisterError.classify(domain: "SMAppServiceErrorDomain", code: 3, description: "x") == .other("x"))
        #expect(HelperRegisterError.classify(domain: "NSCocoaErrorDomain", code: 1, description: "y") == .other("y"))
    }
}

@Suite struct RestartBackoffTests {
    @Test func doublesOnConsecutiveFailuresUpToCap() {
        var b = RestartBackoff(base: 30, maximum: 600)
        #expect((0..<7).map { _ in b.nextDelay() } == [30, 60, 120, 240, 480, 600, 600])
    }

    @Test func resetsAfterProgress() {
        var b = RestartBackoff(base: 30, maximum: 600)
        _ = b.nextDelay()
        _ = b.nextDelay()
        b.recordProgress()
        #expect(b.nextDelay() == 30)
    }
}

@Suite struct HelperInstallRepairTests {
    @Test func answersNeedsNoRepair() {
        #expect(HelperInstallRepair.action(status: .enabled, reachable: true) == .none)
        #expect(HelperInstallRepair.action(status: .requiresApproval, reachable: true) == .none)
    }

    @Test func silentRegisteredServiceIsReRegistered() {
        // A re-signed build leaves the BTM record holding the previous cdhashes.
        #expect(HelperInstallRepair.action(status: .enabled, reachable: false) == .reregister)
    }

    @Test func neverRegisteredServiceIsRegistered() {
        #expect(HelperInstallRepair.action(status: .notRegistered, reachable: false) == .register)
    }

    @Test func pendingApprovalOrMissingPlistIsNotTouched() {
        #expect(HelperInstallRepair.action(status: .requiresApproval, reachable: false) == .none)
        #expect(HelperInstallRepair.action(status: .notFound, reachable: false) == .none)
    }
}
