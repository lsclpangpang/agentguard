import Testing
@testable import GuardCore

@Suite struct LegacyPermissionSummaryTests {
    @Test func familiarCompleteFormsExplainTheirActualScope() {
        let rules = [
            "(allow file-read-metadata)", "(allow process-fork)", "(allow signal (target self))", "(allow sysctl-read)",
            #"(allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))"#,
            #"(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.mDNSResponder"))"#,
            #"(allow network-bind (local ip "localhost:*"))"#,
            #"(allow network-inbound (local ip "localhost:*"))"#,
        ]
        let result = LegacyPermissionSummary(rules: rules)
        #expect(result.items.count == 8 && result.unknown.isEmpty)
        #expect(result.allowsLocalBind && result.allowsLocalInbound)
        #expect(result.localNetworkNotice?.contains("任意端口") == true)
        #expect(result.items.first?.detail.contains("不授予读取文件内容") == true)
        // Human-readable presentation must not alter revocation analysis.
        let analysis = LegacyRuleAnalysis(rules: rules, resolver: AliasResolver(aliases: [:]), caseInsensitive: false)
        #expect(analysis.networkRules.count == 2)
        #expect(analysis.unverifiedPermissions.count == rules.count)
    }

    @Test func mixedBroadOrUnknownFormsAreNeverExplainedAsNarrowAllowances() {
        let rules = [
            "(allow default)", "(allow process*)", "(allow file-read-metadata file-read*)",
            #"(allow network-bind (local ip "*:*"))"#,
            #"(allow network-inbound (local ip "localhost:*") (remote ip "*:*"))"#,
            #"(allow mach-lookup (global-name "com.apple.system.logger") (global-name "unknown"))"#,
            "(allow sysctl-read sysctl-write)", "(allow signal)", "(allow process-fork) (allow default)",
        ]
        let result = LegacyPermissionSummary(rules: rules)
        #expect(result.items.isEmpty)
        #expect(result.unknown == rules)
        #expect(result.localNetworkNotice == nil)
    }
}
