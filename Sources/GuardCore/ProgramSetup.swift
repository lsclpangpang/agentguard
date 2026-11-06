import Foundation

/// What a new profile needs so the chosen program can actually start inside the sandbox.
///
/// A Mach-O binary is the program itself. A script (an npm-installed `claude`, for example) runs in
/// its interpreter: the sandbox must allow executing both and reading the script's package, and
/// copies started outside AgentGuard cannot be detected because the process is the interpreter.
public struct ProgramSetupPlan: Equatable, Sendable {
    /// What to start: the real path, symlinks resolved.
    public var command: String
    /// The executable to watch for unmanaged copies; nil for a script.
    public var program: String?
    /// Additional executables the program needs to start.
    public var exec: [String]
    /// Read-only grants the program needs to start.
    public var files: [FileGrant]
    /// One line per extra permission, saying why it is needed.
    public var reasons: [String]

    public init(command: String, program: String?, exec: [String] = [], files: [FileGrant] = [], reasons: [String] = []) {
        self.command = command
        self.program = program
        self.exec = exec
        self.files = files
        self.reasons = reasons
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
        guard let scriptReal = probe.realPath(path), let name,
              let interpreter = locate(name, homebrewPrefix: homebrewPrefix, probe: probe),
              case .success = ProgramPath.validate(interpreter, home: home, probe: probe)
        else { return .failure(.script(interpreter: name)) }
        var plan = ProgramSetupPlan(command: scriptReal, program: nil, exec: [scriptReal, interpreter])
        plan.reasons.append("运行 \(interpreter)：这个程序是脚本，由它来执行")
        let header = probe.header(scriptReal, count: 128) ?? Data()
        if String(decoding: header.prefix { $0 != 0x0a }, as: UTF8.self).contains("/env ") {
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
