import Foundation
import Testing
import GuardCore

@Suite struct ShellCommandTests {
    @Test func pastedArgumentsAreLiteralInRealShells() throws {
        let arguments = ["$(printf EXPANDED)", "`printf EXPANDED`", "one'quote", "\"double\"", "",
                         "a b", "a\nb", "*.txt", "$HOME", "; printf BAD", "a\\b", "中文"]
        for shell in ["/bin/sh", "/bin/zsh"] where FileManager.default.isExecutableFile(atPath: shell) {
            let process = Process(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: shell)
            process.arguments = ["-c", ShellCommand.format(["/usr/bin/printf", "%s\\0"] + arguments)]
            process.standardOutput = output
            try process.run()
            let bytes = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            #expect(process.terminationStatus == 0)
            #expect(bytes == Data((arguments.joined(separator: "\0") + "\0").utf8))
        }
    }
}
