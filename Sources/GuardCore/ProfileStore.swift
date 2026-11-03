import Foundation

public protocol FileStore: Sendable {
    func read(_ path: String) throws -> Data?
    func writeAtomically(_ data: Data, to path: String) throws
    /// Names of entries directly inside `directory`, sorted; empty when it does not exist.
    func list(_ directory: String) throws -> [String]
    /// Moves a file or directory; the destination's parent is created if needed.
    func move(_ source: String, to destination: String) throws
}

public final class InMemoryFileStore: FileStore, @unchecked Sendable {
    private var files: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func read(_ path: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return files[path]
    }

    public func writeAtomically(_ data: Data, to path: String) throws {
        lock.lock(); defer { lock.unlock() }
        files[path] = data
    }

    public func list(_ directory: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        let prefix = directory.hasSuffix("/") ? directory : directory + "/"
        let names = files.keys.filter { $0.hasPrefix(prefix) }.compactMap { $0.dropFirst(prefix.count).split(separator: "/").first.map(String.init) }
        return Array(Set(names)).sorted()
    }

    public func move(_ source: String, to destination: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard !files.keys.contains(where: { $0 == destination || $0.hasPrefix(destination + "/") }) else {
            throw CocoaError(.fileWriteFileExists)
        }
        for (path, data) in files where path == source || path.hasPrefix(source + "/") {
            files.removeValue(forKey: path)
            files[destination + path.dropFirst(source.count)] = data
        }
    }
}

public struct LocalFileStore: FileStore {
    public init() {}

    public func read(_ path: String) throws -> Data? {
        FileManager.default.fileExists(atPath: path) ? try Data(contentsOf: URL(fileURLWithPath: path)) : nil
    }

    public func writeAtomically(_ data: Data, to path: String) throws {
        let url = URL(fileURLWithPath: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    public func list(_ directory: String) throws -> [String] {
        guard FileManager.default.fileExists(atPath: directory) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: directory).sorted()
    }

    public func move(_ source: String, to destination: String) throws {
        let parent = URL(fileURLWithPath: destination).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try FileManager.default.moveItem(atPath: source, toPath: destination)
    }
}

public enum StoreError: Error, Equatable, Sendable {
    case invalidProfileID(String)
    case approvalMismatch
    case revisionConflict(expectedBase: Int, latest: Int)
}

/// Approved profile revisions, one immutable file per revision: `<root>/profiles/<id>/<revision>.json`.
public struct ProfileStore: Sendable {
    public let root: String
    private let files: any FileStore

    public init(root: String, files: any FileStore) {
        self.root = root
        self.files = files
    }

    public func profileIDs() throws -> [String] {
        try files.list(root + "/profiles").filter(ProfileID.isValid)
    }

    public func revisions(_ id: String) throws -> [Int] {
        try files.list(try directory(id))
            .filter { $0.hasSuffix(".json") && !$0.hasSuffix(".approval.json") }
            .compactMap { Int($0.dropLast(5)) }
            .sorted()
    }

    public func latest(_ id: String) throws -> Profile? {
        guard let last = try revisions(id).last else { return nil }
        return try revision(id, last)
    }

    public func revision(_ id: String, _ revision: Int) throws -> Profile? {
        try files.read(try path(id, revision, suffix: ".json")).map(ProfileCodec.decode)
    }

    public func approval(_ id: String, revision: Int) throws -> ApprovedChange? {
        try files.read(try path(id, revision, suffix: ".approval.json")).map {
            try JSONDecoder().decode(ApprovedChange.self, from: $0)
        }
    }

    public func save(_ profile: Profile, approval: ApprovedChange) throws {
        guard profile.id == approval.profileID, profile.revision == approval.newRevision,
              approval.newRevision == approval.baseRevision + 1
        else { throw StoreError.approvalMismatch }
        let latest = try revisions(profile.id).last ?? 0
        guard latest == approval.baseRevision else { throw StoreError.revisionConflict(expectedBase: approval.baseRevision, latest: latest) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try files.writeAtomically(try encoder.encode(approval), to: try path(profile.id, profile.revision, suffix: ".approval.json"))
        try files.writeAtomically(try ProfileCodec.encode(profile), to: try path(profile.id, profile.revision, suffix: ".json"))
    }

    /// Moves every revision of `id` to `<root>/deleted/<id>-<stamp>`, so the name is free again but the
    /// approved history is kept.
    public func archive(_ id: String, stamp: String) throws {
        let existing = Set(try archivedProfiles())
        var name = id + "-" + stamp
        var counter = 1
        while existing.contains(name) {
            counter += 1
            name = id + "-" + stamp + "-" + String(counter)
        }
        try files.move(try directory(id), to: root + "/deleted/" + name)
    }

    /// Names of archived profile directories, oldest first.
    public func archivedProfiles() throws -> [String] {
        try files.list(root + "/deleted")
    }

    private func directory(_ id: String) throws -> String {
        guard ProfileID.isValid(id) else { throw StoreError.invalidProfileID(id) }
        return root + "/profiles/" + id
    }

    private func path(_ id: String, _ revision: Int, suffix: String) throws -> String {
        try directory(id) + "/" + String(revision) + suffix
    }
}
