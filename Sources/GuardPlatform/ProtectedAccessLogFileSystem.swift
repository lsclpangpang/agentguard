import Foundation
import GuardCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Access-log operations are relative to verified directory descriptors. Existing entries must
/// have the expected owner, exact private mode, regular type and a single hard link.
public final class ProtectedAccessLogFileSystem: AccessLogFileSystem, @unchecked Sendable {
    private let rootFD: Int32
    private let ownerUID: uid_t
    private let maximumEntries: Int

    public init(root: String, ownerUID: uid_t = 0, maxDirectoryEntries: Int = 8192) throws {
        guard root.hasPrefix("/"), !root.contains("\0"), !root.hasSuffix("/") else {
            throw AccessLogError.storageUnavailable("access-log root must be an absolute directory")
        }
        self.ownerUID = ownerUID
        self.maximumEntries = max(1, maxDirectoryEntries)
        // Opening one component at a time rejects symlinked ancestors as well as the leaf.
        // The caller supplies a canonical protected root, never a caller-controlled query path.
        let components = root.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !components.isEmpty, components.allSatisfy({ $0 != "." && $0 != ".." }) else {
            throw AccessLogError.storageUnavailable("invalid access-log root")
        }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parent >= 0 else { throw Self.failure("open root directory") }
        do {
            for (index, component) in components.enumerated() {
                let leaf = index == components.count - 1
                var next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                if next < 0 && errno == ENOENT && leaf {
                    guard mkdirat(parent, component, 0o700) == 0 || errno == EEXIST else { throw Self.failure("create access-log root") }
                    next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                    guard fsync(parent) == 0 else { throw Self.failure("sync access-log parent") }
                }
                guard next >= 0 else { throw Self.failure("open protected directory") }
                Self.closeFD(parent); parent = next
            }
            try Self.verify(parent, ownerUID: ownerUID, directory: true)
            rootFD = parent
        } catch { Self.closeFD(parent); throw error }
    }
    deinit { Self.closeFD(rootFD) }

    public func profiles() throws -> [String] {
        try Self.verify(rootFD, ownerUID: ownerUID, directory: true)
        return try names(in: rootFD).map { name in
            try validate(name, profile: true)
            let fd = openat(rootFD, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw Self.failure("open log profile") }
            defer { Self.closeFD(fd) }
            try Self.verify(fd, ownerUID: ownerUID, directory: true)
            return name
        }.sorted()
    }
    public func createProfile(_ profileID: String) throws {
        try validate(profileID, profile: true)
        try Self.verify(rootFD, ownerUID: ownerUID, directory: true)
        guard mkdirat(rootFD, profileID, 0o700) == 0 || errno == EEXIST else { throw Self.failure("create log profile") }
        let fd = try profileFD(profileID)
        Self.closeFD(fd)
        guard fsync(rootFD) == 0 else { throw Self.failure("sync log profile directory") }
    }
    public func files(profileID: String) throws -> [AccessLogFileInfo] {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        return try names(in: directory).map { name in
            try validate(name)
            let fd = try fileFD(directory, name: name, flags: O_RDONLY)
            defer { Self.closeFD(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_size >= 0 else { throw Self.failure("stat log file") }
            return .init(name: name, size: UInt64(info.st_size), isRegular: true)
        }.sorted { $0.name < $1.name }
    }
    public func read(profileID: String, name: String, offset: UInt64, limit: Int) throws -> Data {
        guard limit >= 0, limit <= 4 * 1024 * 1024, offset <= UInt64(Int64.max) else {
            throw AccessLogError.storageUnavailable("log read exceeds bounded range")
        }
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        let fd = try fileFD(directory, name: name, flags: O_RDONLY)
        defer { Self.closeFD(fd) }
        var data = Data(count: limit)
        let count = try data.withUnsafeMutableBytes { raw -> Int in
            if limit == 0 { return 0 }
            while true {
                let result = pread(fd, raw.baseAddress!, limit, off_t(offset))
                if result < 0 && errno == EINTR { continue }
                guard result >= 0 else { throw Self.failure("read log file") }
                return result
            }
        }
        data.count = count
        return data
    }
    public func append(profileID: String, name: String, data: Data) throws {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        try validate(name)
        var info = stat()
        let existed = fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0
        if !existed && errno != ENOENT { throw Self.failure("inspect log file") }
        let fd = try fileFD(directory, name: name, flags: O_WRONLY | O_APPEND | O_CREAT)
        defer { Self.closeFD(fd) }
        try Self.writeAll(fd, data)
        if !existed, fsync(directory) != 0 { throw Self.failure("sync new log directory entry") }
    }
    public func replace(profileID: String, name: String, data: Data) throws {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        try validate(name)
        try inspectIfPresent(directory, name: name)
        let temporary = ".accesslog-" + UUID().uuidString + ".tmp"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Self.failure("create atomic log metadata") }
        defer { Self.closeFD(fd); _ = unlinkat(directory, temporary, 0) }
        try Self.verify(fd, ownerUID: ownerUID, directory: false)
        try Self.writeAll(fd, data)
        guard fsync(fd) == 0 else { throw Self.failure("sync log metadata") }
        try inspectIfPresent(directory, name: name)
        guard renameat(directory, temporary, directory, name) == 0 else { throw Self.failure("replace log metadata") }
        guard fsync(directory) == 0 else { throw Self.failure("sync replaced log metadata") }
    }
    public func truncate(profileID: String, name: String, size: UInt64) throws {
        guard size <= UInt64(Int64.max) else { throw AccessLogError.storageUnavailable("invalid log truncate size") }
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        let fd = try fileFD(directory, name: name, flags: O_WRONLY)
        defer { Self.closeFD(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, size <= UInt64(max(0, info.st_size)) else {
            throw AccessLogError.storageUnavailable("log recovery may only shorten a file")
        }
        guard ftruncate(fd, off_t(size)) == 0 else { throw Self.failure("truncate incomplete log tail") }
    }
    public func rename(profileID: String, from: String, to: String) throws {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        try validate(to)
        let source = try fileFD(directory, name: from, flags: O_RDONLY)
        defer { Self.closeFD(source) }
        var destination = stat()
        if fstatat(directory, to, &destination, AT_SYMLINK_NOFOLLOW) == 0 {
            throw AccessLogError.storageUnavailable("log rename destination already exists")
        }
        guard errno == ENOENT else { throw Self.failure("inspect log rename destination") }
        #if canImport(Darwin)
        guard renameatx_np(directory, from, directory, to, UInt32(RENAME_EXCL)) == 0 else {
            throw Self.failure("seal log segment")
        }
        #else
        // The directory is private to its verified owner. linkat refuses replacement; the
        // original is removed only after the destination has been created successfully.
        guard linkat(directory, from, directory, to, 0) == 0 else { throw Self.failure("seal log segment") }
        guard unlinkat(directory, from, 0) == 0 else { throw Self.failure("remove old log segment name") }
        #endif
        guard fsync(directory) == 0 else { throw Self.failure("sync sealed log segment") }
    }
    public func remove(profileID: String, name: String) throws {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        let fd = try fileFD(directory, name: name, flags: O_RDONLY)
        defer { Self.closeFD(fd) }
        guard unlinkat(directory, name, 0) == 0 else { throw Self.failure("remove log file") }
        guard fsync(directory) == 0 else { throw Self.failure("sync removed log entry") }
    }
    public func synchronize(profileID: String, name: String) throws {
        let directory = try profileFD(profileID)
        defer { Self.closeFD(directory) }
        let fd = try fileFD(directory, name: name, flags: O_RDONLY)
        defer { Self.closeFD(fd) }
        guard fsync(fd) == 0 else { throw Self.failure("sync log file") }
    }
    public func availableBytes() throws -> UInt64? {
        var info = statvfs()
        guard fstatvfs(rootFD, &info) == 0 else { throw Self.failure("inspect free space") }
        let (value, overflow) = UInt64(info.f_bavail).multipliedReportingOverflow(by: UInt64(info.f_frsize))
        return overflow ? UInt64.max : value
    }
    private func profileFD(_ id: String) throws -> Int32 {
        try validate(id, profile: true)
        try Self.verify(rootFD, ownerUID: ownerUID, directory: true)
        let fd = openat(rootFD, id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw Self.failure("open protected log profile") }
        do { try Self.verify(fd, ownerUID: ownerUID, directory: true); return fd }
        catch { Self.closeFD(fd); throw error }
    }
    private func fileFD(_ directory: Int32, name: String, flags: Int32) throws -> Int32 {
        try validate(name)
        let fd = openat(directory, name, flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw Self.failure("open protected log file") }
        do { try Self.verify(fd, ownerUID: ownerUID, directory: false); return fd }
        catch { Self.closeFD(fd); throw error }
    }
    private func inspectIfPresent(_ directory: Int32, name: String) throws {
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
            let fd = try fileFD(directory, name: name, flags: O_RDONLY)
            Self.closeFD(fd)
        } else if errno != ENOENT { throw Self.failure("inspect protected log metadata") }
    }
    private func names(in directory: Int32) throws -> [String] {
        // An independent descriptor also gives each enumeration its own directory offset.
        let copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard copy >= 0 else { throw Self.failure("open log enumeration") }
        guard let stream = fdopendir(copy) else { Self.closeFD(copy); throw Self.failure("enumerate log directory") }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                if errno != 0 { throw Self.failure("read log directory") }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                String(cString: UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self))
            }
            if name == "." || name == ".." { continue }
            guard names.count < maximumEntries else { throw AccessLogError.storageUnavailable("log directory entry budget exceeded") }
            names.append(name)
        }
        return names
    }
    private func validate(_ value: String, profile: Bool = false) throws {
        let valid = !value.isEmpty && value != "." && value != ".." && value.utf8.count <= (profile ? 128 : 200)
            && value.utf8.allSatisfy {
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                    || $0 == 45 || $0 == 95 || (!profile && $0 == 46)
            }
        guard valid else { throw profile ? AccessLogError.invalidProfileID : AccessLogError.storageUnavailable("invalid log file name") }
    }
    private static func verify(_ fd: Int32, ownerUID: uid_t, directory: Bool) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw failure("verify log entry") }
        let expectedType = directory ? mode_t(S_IFDIR) : mode_t(S_IFREG)
        let mode = directory ? mode_t(0o700) : mode_t(0o600)
        guard info.st_mode & mode_t(S_IFMT) == expectedType, info.st_uid == ownerUID,
              info.st_mode & 0o7777 == mode, directory || info.st_nlink == 1 else {
            throw AccessLogError.storageUnavailable("unsafe log entry owner, type, permissions or hard-link count")
        }
    }
    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                #if canImport(Darwin)
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                #else
                let count = Glibc.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                #endif
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure("append log bytes") }
                offset += count
            }
        }
    }
    private static func failure(_ operation: String) -> AccessLogError {
        .storageUnavailable("\(operation) failed (errno \(errno))")
    }
    private static func closeFD(_ fd: Int32) {
        #if canImport(Darwin)
        _ = Darwin.close(fd)
        #else
        _ = Glibc.close(fd)
        #endif
    }
}

public final class DispatchAccessLogScheduler: AccessLogScheduling, @unchecked Sendable {
    private let writer = DispatchQueue(label: "com.lsclpangpang.agentguard.access-log-writer", qos: .utility)
    private let reader = DispatchQueue(label: "com.lsclpangpang.agentguard.access-log-reader", qos: .utility)
    public init() {}
    public func write(after delay: TimeInterval, _ work: @escaping @Sendable () -> Void) {
        if delay <= 0 { writer.async(execute: work) }
        else { writer.asyncAfter(deadline: .now() + delay, execute: work) }
    }
    public func read(_ work: @escaping @Sendable () -> Void) { reader.async(execute: work) }
}
