import Foundation

/// Logging is an independent preference, never a permission revision or a protection-mode change.
/// The platform supplies a FileStore rooted in the protected configuration directory.
public struct AccessLogSettingStore: Sendable {
    public let root: String
    private let files: any FileStore
    private struct Record: Codable { var enabled: Bool }

    public init(root: String, files: any FileStore) {
        self.root = root
        self.files = files
    }

    public func isEnabled(_ profileID: String) -> Bool {
        guard ProfileID.isValid(profileID) else { return false }
        guard let data = try? files.read(path(profileID)) else { return true }
        // A damaged preference is not proof that recording was intentionally disabled.
        return (try? JSONDecoder().decode(Record.self, from: data))?.enabled ?? true
    }

    public func setEnabled(_ enabled: Bool, profileID: String) throws {
        guard ProfileID.isValid(profileID) else { throw StoreError.invalidProfileID(profileID) }
        try files.writeAtomically(try JSONEncoder().encode(Record(enabled: enabled)), to: path(profileID))
    }

    private func path(_ profileID: String) -> String { root + "/access-log-settings/" + profileID + ".json" }
}
