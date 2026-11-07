import Foundation

/// What a new profile needs so the chosen program can actually start inside the sandbox.
///
/// A Mach-O binary is the program itself. A script (an npm-installed `claude`, for example) runs in
/// its interpreter: the sandbox must allow executing both and reading the script's package, and
/// copies started outside AgentGuard cannot be detected because the process is the interpreter.
public struct ProgramSetupPlan: Equatable, Sendable {
    /// What to start: the real path, symlinks resolved.
    public var command: String
    /// Pin a script's resolved interpreter for background launches, independent of launchd's PATH.
    public var launchExecutable: String
    public var launchArguments: [String]
    /// The executable to watch for unmanaged copies; nil for a script.
    public var program: String?
    /// Additional executables the program needs to start.
    public var exec: [String]
    /// Read-only grants the program needs to start.
    public var files: [FileGrant]
    /// One line per extra permission, saying why it is needed.
    public var reasons: [String]

    public init(command: String, program: String?, exec: [String] = [], files: [FileGrant] = [], reasons: [String] = [],
                launchExecutable: String? = nil, launchArguments: [String] = []) {
        self.command = command
        self.program = program
        self.exec = exec
        self.files = files
        self.reasons = reasons
        self.launchExecutable = launchExecutable ?? command
        self.launchArguments = launchArguments
    }

    public func launch(arguments: [String], workingDirectory: String?, runAtLogin: Bool) -> LaunchSettings {
        LaunchSettings(executable: launchExecutable, arguments: launchArguments + arguments, workingDirectory: workingDirectory,
                       originalLabel: nil, restartOnCleanExit: false, runAtLogin: runAtLogin,
                       scriptPath: program == nil ? command : nil)
    }
}

public enum ProgramSetup {
    public static func analyze(_ input: String, home: String, homebrewPrefix: String, probe: some ProgramFileProbe) -> Result<ProgramSetupPlan, ProgramPathError> {
        switch ProgramPath.validate(input, home: home, probe: probe) {
        case let .success(real):
            var plan = ProgramSetupPlan(command: real, program: real)
            if let keg = kegDirectory(of: real, homebrewPrefix: homebrewPrefix), keg != real {
                plan.files.append(FileGrant(path: keg, kind: .directory, access: .readOnly))
                plan.reasons.append("读取 \(keg)：程序安装目录里的资源和库")
            }
            return .success(plan)
        case let .failure(.script(name)):
            return script(input, interpreter: name, home: home, homebrewPrefix: homebrewPrefix, probe: probe)
        case let .failure(error):
            return .failure(error)
        }
    }

    private static func script(_ input: String, interpreter name: String?, home: String, homebrewPrefix: String,
                               probe: some ProgramFileProbe) -> Result<ProgramSetupPlan, ProgramPathError> {
        var path = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if path.hasPrefix("~/") { path = home + path.dropFirst() }
        guard let scriptReal = probe.realPath(path),
              let header = probe.header(scriptReal, count: 512),
              let shebang = ScriptShebang.parse(header),
              let interpreter = locate(shebang.interpreter, homebrewPrefix: homebrewPrefix, probe: probe),
              case .success = ProgramPath.validate(interpreter, home: home, probe: probe)
        else { return .failure(.script(interpreter: name)) }
        var plan = ProgramSetupPlan(command: scriptReal, program: nil, exec: [scriptReal, interpreter],
                                    launchExecutable: interpreter, launchArguments: shebang.arguments + [scriptReal])
        plan.reasons.append("运行 \(interpreter)：这个程序是脚本，由它来执行")
        if shebang.usesEnv {
            plan.exec.append("/usr/bin/env")
            plan.reasons.append("运行 /usr/bin/env：脚本通过它查找解释器")
        }
        if let package = packageRoot(of: scriptReal) {
            plan.files.append(FileGrant(path: package, kind: .directory, access: .readOnly))
            plan.reasons.append("读取 \(package)：脚本所在的软件包")
        } else {
            plan.files.append(FileGrant(path: scriptReal, kind: .file, access: .readOnly))
        }
        if let keg = kegDirectory(of: interpreter, homebrewPrefix: homebrewPrefix) {
            plan.files.append(FileGrant(path: keg, kind: .directory, access: .readOnly))
            plan.reasons.append("读取 \(keg)：解释器的安装目录")
        } else {
            plan.files.append(FileGrant(path: interpreter, kind: .file, access: .readOnly))
        }
        return .success(plan)
    }

    /// The interpreter's real path: as written when absolute, otherwise the first match in the
    /// usual locations (never the user's PATH, which the sandboxed launch does not inherit).
    static func locate(_ name: String, homebrewPrefix: String, probe: some ProgramFileProbe) -> String? {
        if name.hasPrefix("/") { return probe.realPath(name) }
        guard !name.contains("/") else { return nil }
        for directory in [homebrewPrefix + "/bin", "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"] {
            let candidate = directory + "/" + name
            if probe.kind(candidate) == .file, let real = probe.realPath(candidate), probe.isExecutable(real) { return real }
        }
        return nil
    }

    /// `<prefix>/Cellar/<formula>/<version>` for a file inside a Homebrew keg.
    static func kegDirectory(of path: String, homebrewPrefix: String) -> String? {
        let cellar = homebrewPrefix + "/Cellar/"
        guard path.hasPrefix(cellar) else { return nil }
        let parts = path.dropFirst(cellar.count).split(separator: "/")
        guard parts.count >= 3 else { return nil }
        return cellar + parts[0] + "/" + parts[1]
    }

    /// The package directory right below the last `node_modules`, including an `@scope`.
    static func packageRoot(of path: String) -> String? {
        let parts = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard let index = parts.lastIndex(of: "node_modules"), index + 1 < parts.count - 1 else { return nil }
        let end = parts[index + 1].hasPrefix("@") ? index + 2 : index + 1
        guard end < parts.count - 1 else { return nil }
        return "/" + parts[...end].joined(separator: "/")
    }
}

/// Supported shebang forms whose invocation can be preserved exactly. Environment assignments,
/// env flags other than -S, and env -S expansions require user setup rather than silently changing
/// their meaning while pinning an interpreter.
struct ScriptShebang {
    var interpreter: String
    var arguments: [String]
    var usesEnv: Bool

    static func parse(_ header: Data) -> ScriptShebang? {
        guard header.starts(with: Array("#!".utf8)),
              header.contains(0x0a) || header.count < 512 else { return nil }
        let line = String(decoding: header.dropFirst(2).prefix { $0 != 0x0a }, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
        guard let first = parts.first, first.hasPrefix("/") else { return nil }
        let tail = parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : ""
        if first == "/usr/bin/env" {
            var arguments: [String]
            if tail.hasPrefix("-S ") || tail.hasPrefix("-S\t") {
                let text = String(tail.dropFirst(3))
                guard !text.contains("$"), !text.contains("\\"), let parsed = try? LaunchArguments.parse(text) else { return nil }
                arguments = parsed
            } else {
                // Without -S env receives a single optional shebang argument.
                guard !tail.contains(where: \.isWhitespace) else { return nil }
                arguments = [tail]
            }
            guard let interpreter = arguments.first, !interpreter.isEmpty,
                  !interpreter.hasPrefix("-"), !interpreter.contains("=") else { return nil }
            return ScriptShebang(interpreter: interpreter, arguments: Array(arguments.dropFirst()), usesEnv: true)
        }
        return ScriptShebang(interpreter: String(first), arguments: tail.isEmpty ? [] : [tail], usesEnv: false)
    }
}
