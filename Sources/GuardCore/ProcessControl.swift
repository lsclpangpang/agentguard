/// A scoped signal grant for task cancellation and process cleanup. It deliberately uses the
/// inherited sandbox identity, not the user ID: unrelated processes of the same user stay outside.
public enum ProcessControl {
    public static let rule = "(allow signal (target same-sandbox))"
    public static let title = "管理本次运行的进程"
    public static let detail = "允许程序及其工具控制同一次受保护运行中的进程，用于取消任务、结束子程序和清理残留进程。权限范围仅限本次受保护运行。"

    public static func isEnabled(in profile: Profile) -> Bool {
        isEnabled(in: profile.extraRules)
    }

    public static func enable(in profile: inout Profile) {
        if !isEnabled(in: profile) { profile.extraRules.append(rule) }
    }

    /// Removes only this explicit grant. Existing self rules and all other migrated rules remain.
    public static func disable(in profile: inout Profile) {
        profile.extraRules.removeAll(where: matches)
    }

    static func isEnabled(in rules: [String]) -> Bool {
        rules.contains(where: matches)
    }

    static func matches(_ rule: String) -> Bool {
        SExpression.parse(rule) == .list([
            .atom("allow"), .atom("signal"), .list([.atom("target"), .atom("same-sandbox")]),
        ])
    }

    /// A kernel-reported relationship, never a PID or executable-name guess. Other targets remain
    /// in recent refusals but cannot turn into a broader signal permission.
    static func covers(denialTarget: String) -> Bool {
        guard let relation = denialTarget.split(whereSeparator: \.isWhitespace).first else { return false }
        return relation == "children" || relation == "same-sandbox"
    }
}
