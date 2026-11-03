public struct CompileEnvironment: Sendable {
    public var homeDirectory: String
    public var protectedPaths: [String]
    public var helperServiceName: String
    public var resolver: any PathResolver
    public var caseInsensitive: Bool
    /// Set only after the M0 nested-path counterexamples pass on this system.
    public var allowsNestedReadOnly: Bool
    /// Readable but never writable by managed software: release copies, our app bundle, launchd directories.
    public var writeProtectedPaths: [String]
    /// Each profile gets `<stateRoot>/<profile id>` read-write for private config copies and TMPDIR.
    public var stateRoot: String?
    /// Rules emitted right after `(deny default)`, e.g. imports of system profiles validated in M0.
    public var baseRules: [String]

    public init(homeDirectory: String, protectedPaths: [String], helperServiceName: String, resolver: any PathResolver, caseInsensitive: Bool,
                allowsNestedReadOnly: Bool, writeProtectedPaths: [String], stateRoot: String?, baseRules: [String]) {
        self.homeDirectory = homeDirectory
        self.protectedPaths = protectedPaths
        self.helperServiceName = helperServiceName
        self.resolver = resolver
        self.caseInsensitive = caseInsensitive
        self.allowsNestedReadOnly = allowsNestedReadOnly
        self.writeProtectedPaths = writeProtectedPaths
        self.stateRoot = stateRoot
        self.baseRules = baseRules
    }
}

public enum CompileError: Error, Equatable, Sendable {
    case invalidProfileID(String)
    case invalidRawRule(String)
    case invalidPath(String, PathError)
    case unknownTemplate(String)
    case templateVersionMismatch(id: String, requested: Int, available: Int)
    case forbiddenPath(String)
    case overlapsProtectedPath(grant: String, protected: String)
    case nestedReadOnlyInsideReadWrite(inner: String, outer: String)
    case invalidPort(Int)
    case invalidHash(String)
    case conflictingHashes(String)
    case mutableExecutableWithoutHash(String)
}

public struct EffectiveFileGrant: Hashable, Sendable {
    public var path: String
    public var kind: PathKind
    public var access: Access
    public var readsSecrets: Bool

    public init(path: String, kind: PathKind, access: Access, readsSecrets: Bool) {
        self.path = path
        self.kind = kind
        self.access = access
        self.readsSecrets = readsSecrets
    }
}

public struct EffectiveExecGrant: Hashable, Sendable {
    public var path: String
    public var sha256: String?

    public init(path: String, sha256: String?) {
        self.path = path
        self.sha256 = sha256
    }
}

public struct EffectivePolicy: Hashable, Sendable {
    public var profileID: String
    public var revision: Int
    public var mode: Mode
    public var files: [EffectiveFileGrant]
    public var exec: [EffectiveExecGrant]
    public var network: NetworkPolicy
    public var unrestrictedExec: Bool
    public var extraRules: [String]
    public var stateDirectory: String?
    public var launch: LaunchSettings?
    /// Canonical, sorted, unique `Profile.programs`.
    public var programs: [String] = []

    /// Executables whose copies running outside AgentGuard count as unmanaged: the programs plus the
    /// launch executable.
    public var detectionTargets: [String] {
        Array(Set(programs + (launch.map { [$0.executable] } ?? []))).sorted()
    }
}

public enum ProfileID {
    /// Lowercase letters, digits and hyphens; safe as a single path component.
    public static func isValid(_ id: String) -> Bool {
        guard (1...64).contains(id.count), let first = id.unicodeScalars.first, first != "-" else { return false }
        return id.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }
    }
}

/// Turns a profile plus its templates into one canonical, order-independent policy, or refuses it.
public struct PolicyCompiler: Sendable {
    public let environment: CompileEnvironment

    public init(environment: CompileEnvironment) {
        self.environment = environment
    }

    public func compile(_ profile: Profile, catalog: TemplateCatalog) throws -> EffectivePolicy {
        guard ProfileID.isValid(profile.id) else { throw CompileError.invalidProfileID(profile.id) }
        let templates = try resolveTemplates(profile.templates, catalog: catalog)
        let stateDirectory = environment.stateRoot.map { $0 + "/" + profile.id }
        let stateGrant = stateDirectory.map { FileGrant(path: $0, kind: .directory, access: .readWrite) }
        var files = try compileFiles(profile.files + templates.flatMap(\.files) + (stateGrant.map { [$0] } ?? []))
        var launch = profile.launch
        if let settings = launch {
            launch?.executable = try canonical(settings.executable).value
        }
        let programs = Array(Set(try profile.programs.map { try canonical($0).value })).sorted()
        // The launcher and `guard run` apply the sandbox before exec, so every target they start must
        // be readable and executable inside it.
        let targets = (launch.map { [$0.executable] } ?? []) + programs
        for target in targets {
            let executable = try canonical(target)
            if !files.contains(where: { $0.kind == .directory ? $0.path.contains(executable, caseInsensitive: caseInsensitive) : $0.path.isSame(as: executable, caseInsensitive: caseInsensitive) }) {
                files.append(CanonicalFileGrant(path: executable, kind: .file, access: .readOnly, readsSecrets: false))
                files.sort { $0.path.value < $1.path.value }
                try validateProtected(files)
            }
        }
        let targetExec = targets.map { ExecGrant(path: $0) }
        let exec = try compileExec(profile.exec + templates.flatMap(\.exec) + targetExec, files: files)
        var network = profile.network
        network.loopbackTCPConnect = try compilePorts(profile.network.loopbackTCPConnect + templates.flatMap(\.loopbackPorts))
        return EffectivePolicy(
            profileID: profile.id,
            revision: profile.revision,
            mode: profile.mode,
            files: files.map { EffectiveFileGrant(path: $0.path.value, kind: $0.kind, access: $0.access, readsSecrets: $0.readsSecrets) },
            exec: exec,
            network: network,
            unrestrictedExec: profile.unrestrictedExec,
            extraRules: try compileRawRules(profile.extraRules),
            stateDirectory: try stateDirectory.map { try canonical($0).value },
            launch: launch,
            programs: programs
        )
    }

    private func compileRawRules(_ rules: [String]) throws -> [String] {
        for rule in rules where !Self.isSingleAllowForm(rule) { throw CompileError.invalidRawRule(rule) }
        return Array(Set(rules)).sorted()
    }

    /// One balanced `(allow ...)` form on one line; never `(allow default)`.
    static func isSingleAllowForm(_ rule: String) -> Bool {
        guard rule.hasPrefix("(allow "), rule.hasSuffix(")"), !rule.contains("\n"), rule != "(allow default)" else { return false }
        var depth = 0
        var inString = false
        var escaped = false
        for (index, char) in rule.enumerated() {
            if inString {
                if escaped { escaped = false } else if char == "\\" { escaped = true } else if char == "\"" { inString = false }
                continue
            }
            switch char {
            case "\"": inString = true
            case "(": depth += 1
            case ")":
                depth -= 1
                if depth == 0 && index != rule.count - 1 { return false }
            default: break
            }
            if depth < 0 { return false }
        }
        return depth == 0 && !inString
    }

    private struct CanonicalFileGrant {
        var path: CanonicalPath
        var kind: PathKind
        var access: Access
        var readsSecrets: Bool
    }

    private var caseInsensitive: Bool { environment.caseInsensitive }

    private func canonical(_ raw: String) throws -> CanonicalPath {
        do {
            return try CanonicalPath(raw, resolver: environment.resolver)
        } catch let error as PathError {
            throw CompileError.invalidPath(raw, error)
        }
    }

    private func resolveTemplates(_ refs: [TemplateRef], catalog: TemplateCatalog) throws -> [Template] {
        try refs.sorted { $0.id < $1.id }.map { ref in
            guard let template = catalog.templates[ref.id] else { throw CompileError.unknownTemplate(ref.id) }
            guard template.version == ref.version else {
                throw CompileError.templateVersionMismatch(id: ref.id, requested: ref.version, available: template.version)
            }
            return template
        }
    }

    private func compileFiles(_ grants: [FileGrant]) throws -> [CanonicalFileGrant] {
        var merged: [String: CanonicalFileGrant] = [:]
        for grant in grants {
            let path = try canonical(grant.path)
            let key = path.comparisonKey(caseInsensitive: caseInsensitive)
            let incoming = CanonicalFileGrant(path: path, kind: grant.kind, access: grant.access, readsSecrets: grant.readsSecrets)
            guard var existing = merged[key] else {
                merged[key] = incoming
                continue
            }
            if incoming.path.value < existing.path.value { existing.path = incoming.path }
            if incoming.kind == .directory { existing.kind = .directory }
            existing.access = max(existing.access, incoming.access)
            existing.readsSecrets = existing.readsSecrets || incoming.readsSecrets
            merged[key] = existing
        }
        let files = merged.values.sorted { $0.path.value < $1.path.value }
        try validateForbidden(files)
        try validateProtected(files)
        try validateNesting(files)
        return files
    }

    private func validateForbidden(_ files: [CanonicalFileGrant]) throws {
        let home = try canonical(environment.homeDirectory)
        for grant in files where grant.path.isRoot || grant.path.isSame(as: home, caseInsensitive: caseInsensitive) {
            throw CompileError.forbiddenPath(grant.path.value)
        }
    }

    private func validateProtected(_ files: [CanonicalFileGrant]) throws {
        let protected = try environment.protectedPaths.map(canonical)
        let writeProtected = try environment.writeProtectedPaths.map(canonical)
        for grant in files {
            let writable = grant.access == .readWrite
            let writableAncestor = { (area: CanonicalPath) in writable && grant.kind == .directory && grant.path.contains(area, caseInsensitive: self.caseInsensitive) }
            for area in protected where area.contains(grant.path, caseInsensitive: caseInsensitive) || writableAncestor(area) {
                throw CompileError.overlapsProtectedPath(grant: grant.path.value, protected: area.value)
            }
            for area in writeProtected where (writable && area.contains(grant.path, caseInsensitive: caseInsensitive)) || writableAncestor(area) {
                throw CompileError.overlapsProtectedPath(grant: grant.path.value, protected: area.value)
            }
        }
    }

    private func validateNesting(_ files: [CanonicalFileGrant]) throws {
        guard !environment.allowsNestedReadOnly else { return }
        let writableDirs = files.filter { $0.access == .readWrite && $0.kind == .directory }
        for inner in files where inner.access == .readOnly {
            if let outer = writableDirs.first(where: { $0.path.contains(inner.path, caseInsensitive: caseInsensitive) }) {
                throw CompileError.nestedReadOnlyInsideReadWrite(inner: inner.path.value, outer: outer.path.value)
            }
        }
    }

    private func compileExec(_ grants: [ExecGrant], files: [CanonicalFileGrant]) throws -> [EffectiveExecGrant] {
        var merged: [String: (path: CanonicalPath, sha256: String?, unrestricted: Bool)] = [:]
        for grant in grants {
            let path = try canonical(grant.path)
            let hash = try grant.sha256.map { try normalizedHash($0, for: path.value) }
            let key = path.comparisonKey(caseInsensitive: caseInsensitive)
            guard let existing = merged[key] else {
                merged[key] = (path, hash, hash == nil)
                continue
            }
            if let a = existing.sha256, let b = hash, a != b { throw CompileError.conflictingHashes(path.value) }
            // A grant without a hash allows any binary at that path, so it wins the merge.
            let unrestricted = existing.unrestricted || hash == nil
            let chosenPath = path.value < existing.path.value ? path : existing.path
            merged[key] = (chosenPath, unrestricted ? nil : existing.sha256, unrestricted)
        }
        let writable = files.filter { $0.access == .readWrite }
        let result = merged.values.sorted { $0.path.value < $1.path.value }
        for entry in result where entry.sha256 == nil {
            let mutable = writable.contains { grant in
                grant.kind == .directory
                    ? grant.path.contains(entry.path, caseInsensitive: caseInsensitive)
                    : grant.path.isSame(as: entry.path, caseInsensitive: caseInsensitive)
            }
            if mutable { throw CompileError.mutableExecutableWithoutHash(entry.path.value) }
        }
        return result.map { EffectiveExecGrant(path: $0.path.value, sha256: $0.sha256) }
    }

    private func normalizedHash(_ raw: String, for path: String) throws -> String {
        let lower = raw.lowercased()
        guard lower.count == 64, lower.allSatisfy({ $0.isHexDigit }) else { throw CompileError.invalidHash(path) }
        return lower
    }

    private func compilePorts(_ ports: [Int]) throws -> [Int] {
        if let bad = ports.first(where: { !(1...65535).contains($0) }) { throw CompileError.invalidPort(bad) }
        return Array(Set(ports)).sorted()
    }
}
