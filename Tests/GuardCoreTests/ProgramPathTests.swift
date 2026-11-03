import Foundation
import Testing
@testable import GuardCore

struct FakeProgramProbe: ProgramFileProbe {
    var files: [String: Data] = [:]
    var directories: Set<String> = []
    var links: [String: String] = [:]
    var notExecutable: Set<String> = []

    func kind(_ path: String) -> ProgramFileKind {
        var target = links[path] ?? path
        if target.count > 1, target.hasSuffix("/") { target.removeLast() }
        if directories.contains(target) { return .directory }
        return files[target] == nil ? .missing : .file
    }
    func isExecutable(_ path: String) -> Bool { !notExecutable.contains(path) }
    func realPath(_ path: String) -> String? { links[path] ?? (files[path] == nil ? nil : path) }
    func header(_ path: String, count: Int) -> Data? { files[path].map { $0.prefix(count) } }
}

@Suite struct ProgramPathTests {
    static let machO = Data([0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01])
    static let universal = Data([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02])

    let probe = FakeProgramProbe(
        files: [
            "/opt/homebrew/Cellar/claude/1.0/bin/claude": machO,
            "/usr/bin/python3": universal,
            "/Users/me/bin/tool": machO,
            "/opt/knodo/knodo-agent": Data("#!/bin/bash\nexec knodo-agentd\n".utf8),
            "/opt/tools/run": Data("#!/usr/bin/env -S node --flag\n".utf8),
            "/opt/tools/readme": Data("hello".utf8),
            "/opt/tools/data.bin": machO,
        ],
        directories: ["/Applications/Foo.app", "/opt/tools"],
        links: ["/opt/homebrew/bin/claude": "/opt/homebrew/Cellar/claude/1.0/bin/claude"],
        notExecutable: ["/opt/tools/data.bin"]
    )

    func check(_ input: String) -> Result<String, ProgramPathError> {
        ProgramPath.validate(input, home: "/Users/me", probe: probe)
    }

    @Test func symlinksAreStoredAsTheirRealPath() {
        #expect(check("/opt/homebrew/bin/claude") == .success("/opt/homebrew/Cellar/claude/1.0/bin/claude"))
    }

    @Test func universalBinariesAndTildePathsAreAccepted() {
        #expect(check("  /usr/bin/python3\n") == .success("/usr/bin/python3"))
        #expect(check("~/bin/tool") == .success("/Users/me/bin/tool"))
    }

    @Test func relativeAndEmptyPathsAreRejected() {
        #expect(check("usr/bin/python3") == .failure(.notAbsolute))
        #expect(check("   ") == .failure(.empty))
    }

    @Test func scriptsAreRejectedNamingTheirInterpreter() {
        #expect(check("/opt/knodo/knodo-agent") == .failure(.script(interpreter: "/bin/bash")))
        #expect(check("/opt/tools/run") == .failure(.script(interpreter: "node")))
    }

    @Test func appBundlesDirectoriesAndOtherFilesAreRejected() {
        #expect(check("/Applications/Foo.app/") == .failure(.appBundle))
        #expect(check("/opt/tools") == .failure(.directory))
        #expect(check("/opt/tools/readme") == .failure(.notMachO))
        #expect(check("/opt/tools/data.bin") == .failure(.notExecutable))
        #expect(check("/opt/nothing") == .failure(.missing))
    }

    @Test func everyErrorHasItsOwnMessage() {
        let errors: [ProgramPathError] = [.empty, .notAbsolute, .missing, .appBundle, .directory, .notExecutable, .script(interpreter: nil), .notMachO]
        #expect(Set(errors.map(ProgramPath.message(for:))).count == errors.count)
    }

    @Test func theLocalProbeResolvesSymlinks() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try Self.machO.write(to: URL(fileURLWithPath: dir + "/real"))
        try FileManager.default.createSymbolicLink(atPath: dir + "/link", withDestinationPath: dir + "/real")
        let probe = LocalProgramFileProbe()
        #expect(probe.realPath(dir + "/link") == probe.realPath(dir + "/real"))
        #expect(probe.header(dir + "/link", count: 4) == Self.machO.prefix(4))
        #expect(probe.kind(dir) == .directory)
    }
}
