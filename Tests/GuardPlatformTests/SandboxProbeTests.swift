#if os(macOS)
import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

@Suite struct SandboxProbeTests {
    /// A real sandboxed child performs I/O before the parent queries the same policy. No user
    /// profile or launch item is changed; all resources live in this test's temporary directory.
    @Test func kernelChecksDistinguishExistingMissingAndDeniedPaths() throws {
        let fm = FileManager.default
        let temporary = try CanonicalPath(fm.temporaryDirectory.path, resolver: AliasResolver.macOSDefault)
        let root = URL(fileURLWithPath: temporary.value).appendingPathComponent("agentguard-sandbox-" + UUID().uuidString)
        defer { try? fm.removeItem(at: root) }
        for name in ["rw", "ro", "denied"] {
            try fm.createDirectory(at: root.appendingPathComponent(name), withIntermediateDirectories: true)
        }
        try Data("readable".utf8).write(to: root.appendingPathComponent("ro/file"))
        try Data("blocked".utf8).write(to: root.appendingPathComponent("denied/file"))
        func quote(_ path: String) -> String { "\"" + path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }
        let rw = root.appendingPathComponent("rw").path, ro = root.appendingPathComponent("ro").path
        let denied = root.appendingPathComponent("denied").path
        let sbpl = """
        (version 1)
        (deny default)
        (import "bsd.sb")
        (allow process*)
        (allow file-read-metadata)
        (allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (literal "/dev/null"))
        (allow file-write* (literal "/dev/null"))
        (allow file-read* file-write* (subpath \(quote(rw))))
        (allow file-read* (subpath \(quote(ro))))
        (deny file-read* file-write* (subpath \(quote(denied))))
        (deny mach-lookup (global-name "com.example.agentguard.test-helper"))
        """
        let script = """
        printf created > "$1/rw/created" || exit 20
        /bin/cat "$1/ro/file" > /dev/null || exit 21
        if (printf forbidden > "$1/ro/file") 2>/dev/null; then exit 22; fi
        if /bin/cat "$1/denied/file" > /dev/null 2>&1; then exit 23; fi
        printf ready > "$1/rw/ready"
        exec /bin/sleep 20
        """
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        child.arguments = ["-p", sbpl, "/bin/sh", "-c", script, "probe", root.path]
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        defer { if child.isRunning { child.terminate() }; child.waitUntilExit() }
        let ready = root.appendingPathComponent("rw/ready").path
        let deadline = Date().addingTimeInterval(5)
        while !fm.fileExists(atPath: ready) && child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        try #require(fm.fileExists(atPath: ready), "child must complete real allowed/denied I/O before probing")
        #expect(try String(contentsOf: root.appendingPathComponent("rw/created"), encoding: .utf8) == "created")
        #expect(try String(contentsOf: root.appendingPathComponent("ro/file"), encoding: .utf8) == "readable")

        let probe = SystemSandboxProbe(), pid = child.processIdentifier
        #expect(probe.isSandboxed(pid: pid) == true)
        #expect(probe.check(pid: pid, operation: .fileRead, target: rw) == .allowed)
        #expect(probe.check(pid: pid, operation: .fileWrite, target: rw) == .allowed)
        #expect(probe.check(pid: pid, operation: .fileWrite, target: rw + "/created") == .allowed)
        #expect(probe.check(pid: pid, operation: .fileRead, target: ro + "/file") == .allowed)
        #expect(probe.check(pid: pid, operation: .fileWrite, target: ro + "/file") == .denied)
        #expect(probe.check(pid: pid, operation: .fileRead, target: denied + "/file") == .denied)
        #expect(probe.check(pid: pid, operation: .fileRead, target: rw + "/missing") == .missing)
        #expect(probe.check(pid: pid, operation: .fileWrite, target: rw + "/missing") == .missing)
        #expect(probe.check(pid: pid, operation: .fileWrite, target: denied + "/missing") == .missing)

        let environment = CompileEnvironment(homeDirectory: root.path, protectedPaths: [denied],
                                             helperServiceName: "com.example.agentguard.test-helper",
                                             resolver: AliasResolver(aliases: [:]), caseInsensitive: false,
                                             allowsNestedReadOnly: false, writeProtectedPaths: [], stateRoot: nil, baseRules: [])
        let profile = Profile(id: "probe", revision: 1, mode: .enforce, templates: [],
                              files: [FileGrant(path: rw, kind: .directory, access: .readWrite),
                                      FileGrant(path: ro, kind: .directory, access: .readOnly)],
                              exec: [], network: NetworkPolicy())
        let policy = try PolicyCompiler(environment: environment).compile(profile, catalog: TemplateCatalog([]))
        let expected = SandboxVerification.expectations(for: policy, environment: environment)
        #expect(SandboxVerification.verify(pid: pid, expectations: expected, probe: probe) == .passed)

        let absent = SandboxExpectation(operation: .fileWrite, target: rw + "/missing", allowed: true, failure: "write refused")
        #expect(SandboxVerification.verify(pid: pid, expectations: expected + [absent], probe: probe)
                == .passedWithDeferred([rw + "/missing"]))
        let absentDenied = SandboxExpectation(operation: .fileWrite, target: denied + "/missing", allowed: false, failure: "write allowed")
        #expect(SandboxVerification.verify(pid: pid, expectations: expected + [absent, absentDenied], probe: probe)
                == .inconclusive(["路径暂不存在，尚未核验限制：" + denied + "/missing"]))
        try Data().write(to: URL(fileURLWithPath: rw + "/missing"))
        #expect(SandboxVerification.verify(pid: pid, expectations: expected + [absent], probe: probe) == .passed)
    }
}
#endif
