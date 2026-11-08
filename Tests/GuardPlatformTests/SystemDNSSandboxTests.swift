#if os(macOS)
import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

@Suite struct SystemDNSSandboxTests {
    /// Real connect/send operations plus an independent kernel check of the same child. The DNS
    /// connection sends no request; other targets are private local test listeners.
    @Test func exactServiceGrantAndRevocationMatchRealConnections() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ag-dns-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("probe.c"), executable = root.appendingPathComponent("probe")
        try Self.source.write(to: source, atomically: true, encoding: .utf8)
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
        compiler.arguments = [source.path, "-o", executable.path]
        try compiler.run()
        compiler.waitUntilExit()
        try #require(compiler.terminationStatus == 0)

        // Only runtime necessities are broad here; network decisions come from the rendered
        // policy, except in the third case which tests revocation over a legacy broad allow.
        let environment = CompileEnvironment(homeDirectory: root.path, protectedPaths: [],
                                             helperServiceName: "com.example.agentguard.dns-test",
                                             resolver: AliasResolver.macOSDefault, caseInsensitive: true,
                                             allowsNestedReadOnly: false, writeProtectedPaths: [], stateRoot: nil,
                                             baseRules: ["(allow default)", "(deny network*)"])
        let cases: [(Toggle?, [String], [Int])] = [
            (nil, [], [0, 0, 0, 0]),
            (.allowed, [], [1, 0, 0, 0]),
            (.denied, ["(allow network*)"], [0, 1, 1, 1]),
        ]
        for (index, entry) in cases.enumerated() {
            let (setting, legacy, expected) = entry
            let profile = Profile(id: "dns-test", revision: 1, mode: .enforce, templates: [], files: [], exec: [],
                                  network: NetworkPolicy(systemDNS: setting), extraRules: legacy)
            let policy = try PolicyCompiler(environment: environment).compile(profile, catalog: TemplateCatalog([]))
            let sbpl = SBPLRenderer(environment: environment).render(policy)
            let child = Process(), output = Pipe()
            child.executableURL = executable
            // Keep sockaddr_un's path below its 104-byte limit on macOS.
            child.arguments = [sbpl, "/private/tmp/ag-dns-" + UUID().uuidString]
            child.standardOutput = output
            child.standardError = FileHandle.standardError
            try child.run()
            defer {
                if child.isRunning { child.terminate() }
                child.waitUntilExit()
                try? FileManager.default.removeItem(atPath: child.arguments![1])
            }
            let bytes = output.fileHandleForReading.availableData
            try #require(!bytes.isEmpty, "child must report its real connection results")
            let actual = String(decoding: bytes, as: UTF8.self).split(whereSeparator: \.isWhitespace).compactMap { Int($0) }
            #expect(actual == expected, "case \(index): DNS, unrelated Unix socket, TCP, UDP")
            #expect(SystemSandboxProbe().check(pid: child.processIdentifier, operation: .unixConnect,
                                              target: SystemDNS.socketPath) == (expected[0] == 1 ? .allowed : .denied))
        }
    }

    private static let source = #"""
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <errno.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <netinet/in.h>
    extern int sandbox_init(const char *, unsigned long long, char **);
    static int result(int rc) { return rc >= 0 ? 1 : errno == EPERM ? 0 : -errno; }
    static int unix_connect(const char *path) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
        int answer = result(connect(fd, (struct sockaddr *)&address, sizeof(address)));
        close(fd); return answer;
    }
    int main(int argc, char **argv) {
        if (argc != 3) return 2;
        int local = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", argv[2]);
        if (bind(local, (struct sockaddr *)&address, sizeof(address)) || listen(local, 4)) return 3;
        int server = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in remote = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t size = sizeof(remote);
        if (bind(server, (struct sockaddr *)&remote, size) || listen(server, 4) ||
            getsockname(server, (struct sockaddr *)&remote, &size)) return 4;
        char *error = NULL;
        if (sandbox_init(argv[1], 0, &error)) { fprintf(stderr, "%s\n", error); return 5; }
        int dns = unix_connect("/private/var/run/mDNSResponder"), other = unix_connect(argv[2]);
        int tcp = socket(AF_INET, SOCK_STREAM, 0);
        int tcp_result = result(connect(tcp, (struct sockaddr *)&remote, size));
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        int udp_result = result(sendto(udp, "x", 1, 0, (struct sockaddr *)&remote, size));
        printf("%d %d %d %d\n", dns, other, tcp_result, udp_result);
        fflush(stdout);
        sleep(10);
        return 0;
    }
    """#
}
#endif
