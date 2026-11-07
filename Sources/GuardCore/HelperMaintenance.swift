/// Invalidates asynchronous status/repair work whenever the user removes or reinstalls the Helper.
/// The App persists `enabled` so reopening it after uninstall cannot silently register services.
public struct HelperMaintenance: Equatable, Sendable {
    public private(set) var enabled: Bool
    public private(set) var generation: UInt64 = 0

    public init(enabled: Bool = true) { self.enabled = enabled }

    public mutating func suspend() {
        generation &+= 1
        enabled = false
    }

    public mutating func resume() {
        generation &+= 1
        enabled = true
    }

    public func accepts(_ generation: UInt64) -> Bool { enabled && self.generation == generation }
}
