#if os(macOS)
import Foundation
import GuardCore
import Testing

@Suite struct ProcessControlSandboxTests {
    /// Exercise real signals, including a sibling `/bin/kill` and a grandchild in its own group.
    /// The probe also creates outside targets before applying the worker's sandbox, so a broad
    /// signal allowance cannot accidentally pass the positive checks.
    @Test func sameSandboxSignalsStopTheInheritedTreeAndKeepOtherInstancesIsolated() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ag-signal-" + UUID().uuidString)
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

        let environment = CompileEnvironment(homeDirectory: root.path, protectedPaths: [],
                                             helperServiceName: "com.example.agentguard.signal-test",
                                             resolver: AliasResolver.macOSDefault, caseInsensitive: true,
                                             allowsNestedReadOnly: false, writeProtectedPaths: [], stateRoot: nil,
                                             baseRules: ["(allow default)", "(deny signal)"])
        let cases: [(Bool, [Int])] = [
            (false, [0, 0, 0, 0, 0, 1, 1]),
            (true, [1, 1, 1, 0, 0, 1, 1]),
        ]
        for (index, entry) in cases.enumerated() {
            var profile = Profile(id: "signal-test", revision: 1, mode: .enforce, templates: [], files: [], exec: [],
                                  network: NetworkPolicy(), extraRules: ["(allow signal (target self))"])
            if entry.0 { ProcessControl.enable(in: &profile) }
            let policy = try PolicyCompiler(environment: environment).compile(profile, catalog: TemplateCatalog([]))
            let sbpl = SBPLRenderer(environment: environment).render(policy)
            let child = Process(), output = Pipe()
            child.executableURL = executable
            child.arguments = [sbpl]
            child.standardOutput = output
            child.standardError = FileHandle.standardError
            try child.run()
            // The unsandboxed C controller owns and cleans all of its disposable targets,
            // including those the baseline worker is deliberately forbidden to stop.
            let data = output.fileHandleForReading.readDataToEndOfFile()
            child.waitUntilExit()
            try #require(child.terminationStatus == 0)
            let actual = String(decoding: data, as: UTF8.self).split(whereSeparator: \.isWhitespace).compactMap { Int($0) }
            #expect(actual == entry.1,
                    "case \(index): child group, external kill, grandchild group, outside signal, separate instance signal, outside alive, separate instance alive")
        }
    }

    private static let source = #"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <sys/wait.h>
    extern int sandbox_init(const char *, unsigned long long, char **);

    struct event { int kind; int value; };
    static int reports = -1;
    static void report(int kind, int value) {
        struct event event = {kind, value};
        if (write(reports, &event, sizeof(event)) != sizeof(event)) _exit(90);
    }
    static int apply(const char *profile) {
        char *error = NULL;
        if (!sandbox_init(profile, 0, &error)) return 0;
        fprintf(stderr, "sandbox_init: %s\n", error ? error : "unknown error");
        return -1;
    }
    static void target_loop(void) {
        alarm(10); /* Last-resort lifetime bound, including an unexpected controller exit. */
        while (1) pause();
    }
    static pid_t target(const char *profile) {
        int ready[2];
        if (pipe(ready)) _exit(91);
        pid_t pid = fork();
        if (pid < 0) _exit(92);
        if (!pid) {
            close(ready[0]);
            if (reports >= 0) close(reports);
            if (setsid() < 0 || (profile && apply(profile))) _exit(93);
            if (write(ready[1], "r", 1) != 1) _exit(94);
            close(ready[1]);
            target_loop();
        }
        close(ready[1]);
        char byte;
        if (read(ready[0], &byte, 1) != 1) _exit(95);
        close(ready[0]);
        return pid;
    }
    static int signal_result(int result) {
        return result == 0 ? 1 : errno == EPERM ? 0 : -errno;
    }
    static int wait_for_term(pid_t pid) {
        int status;
        return waitpid(pid, &status, 0) == pid &&
               WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM;
    }
    static void worker(const char *profile, pid_t outside, pid_t separate) {
        alarm(10);
        if (apply(profile)) _exit(96);
        pid_t direct = target(NULL);
        report(1, direct);
        int result = signal_result(kill(-direct, SIGTERM));
        if (result == 1 && !wait_for_term(direct)) result = -100;
        report(2, result);

        pid_t sibling = target(NULL);
        report(1, sibling);
        pid_t tool = fork();
        if (!tool) {
            close(reports);
            char group[32];
            snprintf(group, sizeof(group), "-%d", sibling);
            freopen("/dev/null", "w", stderr);
            execl("/bin/kill", "kill", "-TERM", group, NULL);
            _exit(97);
        }
        int status;
        if (tool < 0 || waitpid(tool, &status, 0) != tool) _exit(98);
        result = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
        if (result == 1 && !wait_for_term(sibling)) result = -101;
        report(3, result);

        int descendants[2];
        if (pipe(descendants)) _exit(99);
        pid_t relay = fork();
        if (!relay) {
            close(descendants[0]);
            close(reports);
            reports = -1;
            if (setsid() < 0) _exit(100);
            pid_t grandchild = target(NULL);
            if (write(descendants[1], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) _exit(101);
            close(descendants[1]);
            _exit(wait_for_term(grandchild) ? 0 : 102);
        }
        close(descendants[1]);
        if (relay < 0) _exit(103);
        report(1, relay);
        pid_t grandchild;
        if (read(descendants[0], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) _exit(104);
        close(descendants[0]);
        report(1, grandchild);
        result = signal_result(kill(-grandchild, SIGTERM));
        if (result == 1) {
            if (waitpid(relay, &status, 0) != relay || !WIFEXITED(status) || WEXITSTATUS(status)) result = -102;
        }
        report(4, result);
        report(5, signal_result(kill(outside, SIGTERM)));
        report(6, signal_result(kill(separate, SIGTERM)));
        _exit(0);
    }
    int main(int argc, char **argv) {
        if (argc != 2) return 2;
        alarm(15);
        /* Both targets precede the worker's sandbox; the second independently applies identical rules. */
        pid_t outside = target(NULL), separate = target(argv[1]);
        int stream[2];
        if (pipe(stream)) return 3;
        pid_t child = fork();
        if (!child) {
            close(stream[0]);
            reports = stream[1];
            worker(argv[1], outside, separate);
        }
        close(stream[1]);
        pid_t owned[16] = {outside, separate};
        int owned_count = 2, answers[7] = {-9, -9, -9, -9, -9, 0, 0};
        struct event event;
        while (read(stream[0], &event, sizeof(event)) == sizeof(event)) {
            if (event.kind == 1 && owned_count < 16) owned[owned_count++] = event.value;
            else if (event.kind >= 2 && event.kind <= 6) answers[event.kind - 2] = event.value;
        }
        close(stream[0]);
        int status;
        int okay = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status);
        answers[5] = waitpid(outside, &status, WNOHANG) == 0;
        answers[6] = waitpid(separate, &status, WNOHANG) == 0;
        for (int i = 0; i < owned_count; i++) kill(-owned[i], SIGTERM);
        usleep(20000);
        for (int i = 0; i < owned_count; i++) kill(-owned[i], SIGKILL);
        waitpid(outside, NULL, 0);
        waitpid(separate, NULL, 0);
        for (int i = 0; i < 7; i++) printf("%d%c", answers[i], i == 6 ? '\n' : ' ');
        return okay ? 0 : 4;
    }
    """#
}
#endif
