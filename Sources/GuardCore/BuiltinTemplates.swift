public struct TemplateContext: Sendable {
    public var home: String
    public var uid: Int
    public var homebrewPrefix: String

    public init(home: String, uid: Int, homebrewPrefix: String) {
        self.home = home
        self.uid = uid
        self.homebrewPrefix = homebrewPrefix
    }
}

/// Built-in runtime templates. Paths for Claude Code and Codex writable data must be re-checked
/// against the tools actually installed on the target Mac before relying on them.
public enum BuiltinTemplates {
    public static func all(_ c: TemplateContext) -> [Template] {
        [systemBase(), claudeCode(c), codex(c), homebrewPython(c), git(c)]
    }

    static func ro(_ path: String) -> FileGrant { FileGrant(path: path, kind: .directory, access: .readOnly) }
    static func rw(_ path: String) -> FileGrant { FileGrant(path: path, kind: .directory, access: .readWrite) }
    static func roFile(_ path: String) -> FileGrant { FileGrant(path: path, kind: .file, access: .readOnly) }
    static func rwFile(_ path: String) -> FileGrant { FileGrant(path: path, kind: .file, access: .readWrite) }

    static func systemBase() -> Template {
        Template(
            id: "system-base", version: 1,
            files: ["/System", "/usr/lib", "/usr/share", "/usr/bin", "/bin", "/usr/libexec", "/private/var/db/timezone"].map(ro)
                + ["/dev/urandom", "/dev/random", "/private/etc/hosts", "/private/etc/services", "/private/etc/protocols"].map(roFile)
                + [rwFile("/dev/null"), rwFile("/dev/tty")],
            exec: ["/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/env"].map { ExecGrant(path: $0) },
            loopbackPorts: []
        )
    }

    static func claudeCode(_ c: TemplateContext) -> Template {
        let dir = c.home + "/.claude"
        return Template(
            id: "claude-code", version: 1,
            files: [ro(dir), rwFile(c.home + "/.claude.json"), rw("/private/tmp/claude-\(c.uid)")]
                + ["projects", "todos", "shell-snapshots", "statsig", "ide"].map { rw(dir + "/" + $0) },
            exec: [],
            loopbackPorts: []
        )
    }

    static func codex(_ c: TemplateContext) -> Template {
        let dir = c.home + "/.codex"
        return Template(
            id: "codex", version: 1,
            files: [ro(dir)] + ["sessions", "log"].map { rw(dir + "/" + $0) },
            exec: [],
            loopbackPorts: []
        )
    }

    static func homebrewPython(_ c: TemplateContext) -> Template {
        let p = c.homebrewPrefix
        return Template(
            id: "homebrew-python", version: 1,
            files: ["Cellar", "opt", "lib", "Frameworks", "etc/openssl@3"].map { ro(p + "/" + $0) },
            exec: ["python3", "python3.9", "python3.13"].map { ExecGrant(path: p + "/bin/" + $0) },
            loopbackPorts: []
        )
    }

    static func git(_ c: TemplateContext) -> Template {
        Template(
            id: "git", version: 1,
            files: [ro("/Library/Developer/CommandLineTools"), roFile(c.home + "/.gitconfig"),
                    FileGrant(path: c.home + "/.ssh", kind: .directory, access: .readOnly, readsSecrets: true)],
            exec: [ExecGrant(path: "/usr/bin/git")],
            loopbackPorts: []
        )
    }
}
