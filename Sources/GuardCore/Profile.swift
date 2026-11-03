import Foundation

public enum Access: String, Codable, Sendable, Comparable {
    case readOnly = "read_only"
    case readWrite = "read_write"

    public static func < (lhs: Access, rhs: Access) -> Bool { lhs == .readOnly && rhs == .readWrite }
}

public enum PathKind: String, Codable, Sendable {
    case file
    case directory
}

public enum Toggle: String, Codable, Sendable {
    case allowed
    case denied
}

public enum Mode: String, Codable, Sendable {
    case enforce
    case restrictedLearning = "restricted_learning"
    case unprotectedObserve = "unprotected_observe"

    /// Only unprotected observation lifts the deny-by-default boundary.
    var liftsBoundary: Bool { self == .unprotectedObserve }
}

public struct FileGrant: Codable, Hashable, Sendable {
    public var path: String
    public var kind: PathKind
    public var access: Access
    public var readsSecrets: Bool
    public var expiresAt: Date?

    public init(path: String, kind: PathKind, access: Access, readsSecrets: Bool = false, expiresAt: Date? = nil) {
        self.path = path
        self.kind = kind
        self.access = access
        self.readsSecrets = readsSecrets
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case path, kind, access
        case readsSecrets = "reads_secrets"
        case expiresAt = "expires_at"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        kind = try c.decode(PathKind.self, forKey: .kind)
        access = try c.decode(Access.self, forKey: .access)
        readsSecrets = try c.decodeIfPresent(Bool.self, forKey: .readsSecrets) ?? false
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
    }
}

public struct ExecGrant: Codable, Hashable, Sendable {
    public var path: String
    public var sha256: String?

    public init(path: String, sha256: String? = nil) {
        self.path = path
        self.sha256 = sha256
    }
}

public struct NetworkPolicy: Codable, Hashable, Sendable {
    public var loopbackTCPConnect: [Int]
    public var outboundTCP: Toggle
    public var listen: Toggle
    public var udp: Toggle

    public init(loopbackTCPConnect: [Int] = [], outboundTCP: Toggle = .denied, listen: Toggle = .denied, udp: Toggle = .denied) {
        self.loopbackTCPConnect = loopbackTCPConnect
        self.outboundTCP = outboundTCP
        self.listen = listen
        self.udp = udp
    }

    enum CodingKeys: String, CodingKey {
        case loopbackTCPConnect = "loopback_tcp_connect"
        case outboundTCP = "outbound_tcp"
        case listen, udp
    }
}

public struct TemplateRef: Codable, Hashable, Sendable {
    public var id: String
    public var version: Int

    public init(id: String, version: Int) {
        self.id = id
        self.version = version
    }
}

public struct Template: Hashable, Sendable {
    public var id: String
    public var version: Int
    public var files: [FileGrant]
    public var exec: [ExecGrant]
    public var loopbackPorts: [Int]

    public init(id: String, version: Int, files: [FileGrant], exec: [ExecGrant], loopbackPorts: [Int]) {
        self.id = id
        self.version = version
        self.files = files
        self.exec = exec
        self.loopbackPorts = loopbackPorts
    }
}

public struct TemplateCatalog: Sendable {
    public let templates: [String: Template]

    public init(_ templates: [Template]) {
        self.templates = Dictionary(templates.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
    }
}

/// How a LaunchAgent-type object is started once its launcher has applied the sandbox.
public struct LaunchSettings: Codable, Hashable, Sendable {
    public var executable: String
    public var arguments: [String]
    public var workingDirectory: String?
    public var originalLabel: String?
    public var restartOnCleanExit: Bool

    public init(executable: String, arguments: [String], workingDirectory: String?, originalLabel: String?, restartOnCleanExit: Bool) {
        self.executable = executable
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.originalLabel = originalLabel
        self.restartOnCleanExit = restartOnCleanExit
    }

    enum CodingKeys: String, CodingKey {
        case executable, arguments
        case workingDirectory = "working_directory"
        case originalLabel = "original_label"
        case restartOnCleanExit = "restart_on_clean_exit"
    }
}

public struct Profile: Codable, Hashable, Sendable {
    public var id: String
    public var revision: Int
    public var mode: Mode
    public var templates: [TemplateRef]
    public var files: [FileGrant]
    public var exec: [ExecGrant]
    public var network: NetworkPolicy
    /// Allows executing any program. Only set when migrating an installation that already allowed it.
    public var unrestrictedExec: Bool
    /// Verbatim single-form allow rules carried over from a migrated installation.
    public var extraRules: [String]
    public var launch: LaunchSettings?
    /// Executables this profile manages, whether started by `guard run` or by the launcher. They are
    /// granted read and exec automatically, and a copy running outside AgentGuard is reported.
    public var programs: [String]

    public init(id: String, revision: Int, mode: Mode, templates: [TemplateRef], files: [FileGrant], exec: [ExecGrant], network: NetworkPolicy,
                unrestrictedExec: Bool = false, extraRules: [String] = [], launch: LaunchSettings? = nil, programs: [String] = []) {
        self.id = id
        self.revision = revision
        self.mode = mode
        self.templates = templates
        self.files = files
        self.exec = exec
        self.network = network
        self.unrestrictedExec = unrestrictedExec
        self.extraRules = extraRules
        self.launch = launch
        self.programs = programs
    }

    enum CodingKeys: String, CodingKey {
        case id, revision, mode, templates, files, exec, network, launch, programs
        case unrestrictedExec = "unrestricted_exec"
        case extraRules = "extra_rules"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        revision = try c.decode(Int.self, forKey: .revision)
        mode = try c.decode(Mode.self, forKey: .mode)
        templates = try c.decode([TemplateRef].self, forKey: .templates)
        files = try c.decode([FileGrant].self, forKey: .files)
        exec = try c.decode([ExecGrant].self, forKey: .exec)
        network = try c.decode(NetworkPolicy.self, forKey: .network)
        unrestrictedExec = try c.decodeIfPresent(Bool.self, forKey: .unrestrictedExec) ?? false
        extraRules = try c.decodeIfPresent([String].self, forKey: .extraRules) ?? []
        launch = try c.decodeIfPresent(LaunchSettings.self, forKey: .launch)
        programs = try c.decodeIfPresent([String].self, forKey: .programs) ?? []
    }

    /// Drops file grants whose expiry has passed; the caller turns the result into a tightening revision.
    public func removingExpiredGrants(at now: Date) -> (profile: Profile, removed: [FileGrant]) {
        var copy = self
        let removed = files.filter { grant in grant.expiresAt.map { $0 <= now } ?? false }
        copy.files = files.filter { !removed.contains($0) }
        return (copy, removed)
    }

    public var nextExpiry: Date? {
        files.compactMap(\.expiresAt).min()
    }
}

public enum ProfileCodec {
    public static func encode(_ profile: Profile) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(profile)
    }

    public static func decode(_ data: Data) throws -> Profile {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(Profile.self, from: data)
    }
}
