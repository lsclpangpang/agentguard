import Foundation

/// What the Helper needs to put a running instance back after it restarts: the root process,
/// identified by PID plus start time so a reused PID is never mistaken for it.
public struct InstanceRecord: Codable, Equatable, Sendable {
    public var instance: Int
    public var profileID: String
    public var revision: Int
    public var pid: Int32
    public var startTime: UInt64
    public var supervisedByLaunchd: Bool
    public var bootSessionID: String?

    public init(instance: Int, profileID: String, revision: Int, pid: Int32, startTime: UInt64, supervisedByLaunchd: Bool,
                bootSessionID: String? = nil) {
        self.instance = instance
        self.profileID = profileID
        self.revision = revision
        self.pid = pid
        self.startTime = startTime
        self.supervisedByLaunchd = supervisedByLaunchd
        self.bootSessionID = bootSessionID
    }

    public func isFromEarlierBoot(current: String?) -> Bool {
        guard let recorded = bootSessionID, let current else { return false }
        return recorded != current
    }
}

/// Run records, one file per instance: `<root>/instances/<profile id>/<instance>.json`.
///
/// The root must be somewhere managed software can never write. The profile's own state directory
/// is read-write inside its sandbox, so a record kept there could be forged by the very process it
/// describes. No verification result is stored: the Helper checks the sandbox again after a restart.
public struct InstanceRecordStore: Sendable {
    public let root: String
    private let files: any FileStore

    public init(root: String, files: any FileStore) {
        self.root = root
        self.files = files
    }

    public func save(_ record: InstanceRecord) throws {
        try files.writeAtomically(try JSONEncoder().encode(record), to: try path(record.profileID, record.instance))
    }

    public func remove(profileID: String, instance: Int) throws {
        try files.remove(try path(profileID, instance))
    }

    public func removeAll(profileID: String) throws {
        guard ProfileID.isValid(profileID) else { throw StoreError.invalidProfileID(profileID) }
        for name in try files.list(directory + "/" + profileID) { try files.remove(directory + "/" + profileID + "/" + name) }
    }

    /// Every record that still decodes and sits where its own contents say it should.
    public func all() throws -> [InstanceRecord] {
        var records: [InstanceRecord] = []
        for profileID in try files.list(directory).filter(ProfileID.isValid) {
            for name in try files.list(directory + "/" + profileID) where name.hasSuffix(".json") {
                guard let instance = Int(name.dropLast(5)),
                      let data = try files.read(directory + "/" + profileID + "/" + name),
                      let record = try? JSONDecoder().decode(InstanceRecord.self, from: data),
                      record.profileID == profileID, record.instance == instance
                else { continue }
                records.append(record)
            }
        }
        return records.sorted { ($0.profileID, $0.instance) < ($1.profileID, $1.instance) }
    }

    private var directory: String { root + "/instances" }

    private func path(_ profileID: String, _ instance: Int) throws -> String {
        guard ProfileID.isValid(profileID) else { throw StoreError.invalidProfileID(profileID) }
        return directory + "/" + profileID + "/" + String(instance) + ".json"
    }
}
