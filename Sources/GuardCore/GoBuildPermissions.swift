public enum GoBuildPermissionsError: Error, Equatable, Sendable, CustomStringConvertible {
    case scopeConflict(path: String)
    case unexpectedChange

    public var description: String {
        switch self {
        case let .scopeConflict(path):
            return "Go 权限与现有设置在 \(path) 发生范围冲突，合并后会超出本次授权范围；没有生成权限变更。"
        case .unexpectedChange:
            return "Go 权限合并产生了约定四项之外的变化；没有生成权限变更。"
        }
    }
}

/// The four explicit grants needed for the reviewed Go workflow. This does not grant module
/// cache writes, change Go's environment, or infer access to any other directory.
public enum GoBuildPermissions {
    public static func requiredGrants(home: String) -> [FileGrant] {
        let home = home.hasSuffix("/") ? String(home.dropLast()) : home
        return [
            FileGrant(path: "/usr/local/go", kind: .directory, access: .readOnly),
            FileGrant(path: home + "/Library/Application Support/go/env", kind: .file, access: .readOnly),
            FileGrant(path: home + "/Library/Caches/go-build", kind: .directory, access: .readWrite),
            FileGrant(path: home + "/go/pkg/mod", kind: .directory, access: .readOnly),
        ]
    }

    public static func isEnabled(in profile: Profile, home: String) -> Bool {
        requiredGrants(home: home).allSatisfy { required in
            profile.files.contains { samePermanentGrant($0, required) && $0.access >= required.access }
        }
    }

    /// Validates the actual compiled change, including aliases and grants inherited from templates.
    /// An existing writable file must not combine with a requested read-only directory into a
    /// newly writable directory. Existing stronger permissions are left unchanged.
    public static func validatedProfile(from profile: Profile, home: String,
                                        environment: CompileEnvironment, catalog: TemplateCatalog) throws -> Profile {
        var candidate = profile
        enable(in: &candidate, home: home)

        let compiler = PolicyCompiler(environment: environment)
        let before = try compiler.compile(profile, catalog: catalog)
        let after = try compiler.compile(candidate, catalog: catalog)
        let grants = requiredGrants(home: home)
        let reference = try compiler.compile(
            Profile(id: profile.id, revision: profile.revision, mode: profile.mode, templates: [],
                    files: grants, exec: [], network: NetworkPolicy()),
            catalog: catalog)

        func key(_ compiledPath: String) -> String {
            environment.caseInsensitive ? compiledPath.lowercased() : compiledPath
        }
        let canonicalGrants = try grants.map { grant in
            (grant, try CanonicalPath(grant.path, resolver: environment.resolver).value)
        }
        let reviewedKeys = Set(canonicalGrants.map { key($0.1) })
        // Compilation may add a private state directory. It is not one of this repair's grants.
        let expected = Dictionary(uniqueKeysWithValues: reference.files
            .filter { reviewedKeys.contains(key($0.path)) }
            .map { (key($0.path), $0) })
        let actual = Dictionary(uniqueKeysWithValues: after.files.map { (key($0.path), $0) })

        // Two reviewed paths must not alias to one another and combine into a wider reference.
        for (grant, path) in canonicalGrants {
            guard let compiled = expected[key(path)], compiled.kind == grant.kind, compiled.access == grant.access else {
                throw GoBuildPermissionsError.scopeConflict(path: path)
            }
        }
        func validateScope(at path: String) throws {
            guard let allowed = expected[key(path)], let resulting = actual[key(path)],
                  resulting.kind == allowed.kind, resulting.access == allowed.access else {
                throw GoBuildPermissionsError.scopeConflict(path: path)
            }
        }
        for change in PolicyDiff(from: before, to: after).changes {
            switch change {
            case let .fileAdded(grant):
                try validateScope(at: grant.path)
                guard grant.readsSecrets == expected[key(grant.path)]?.readsSecrets else {
                    throw GoBuildPermissionsError.scopeConflict(path: grant.path)
                }
            case let .fileAccessChanged(path, _, _), let .fileKindChanged(path, _, _):
                try validateScope(at: path)
            default:
                throw GoBuildPermissionsError.unexpectedChange
            }
        }
        return candidate
    }

    /// Prepares the raw grants only. Use `validatedProfile` before proposing or saving a change:
    /// compilation can combine grants for the same canonical path into a wider permission.
    public static func enable(in profile: inout Profile, home: String) {
        for required in requiredGrants(home: home) {
            if profile.files.contains(where: { samePermanentGrant($0, required) && $0.access >= required.access }) {
                continue
            }
            if let index = profile.files.firstIndex(where: { samePermanentGrant($0, required) }) {
                // Only the build cache can need a read-only → read-write upgrade. Preserve the
                // existing entry's other fields rather than replacing it or appending a duplicate.
                profile.files[index].access = required.access
            } else {
                profile.files.append(required)
            }
        }
    }

    private static func samePermanentGrant(_ grant: FileGrant, _ required: FileGrant) -> Bool {
        grant.path == required.path && grant.kind == required.kind && grant.expiresAt == nil
    }
}
