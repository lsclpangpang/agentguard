#if os(macOS)
import Foundation
import GuardCore
import Testing
@testable import GuardPlatform

@Suite struct ComponentSigningIdentityTests {
    @Test func runningIdentityMatchesTheValidatedTestExecutable() throws {
        let path = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
        let running = try CodeSigning.runningCDHash()
        #expect(running.count == 40)
        #expect(running == (try CodeSigning.validatedCDHash(atPath: path)))
        #expect(throws: PlatformError.self) {
            try CodeSigning.validatedCDHash(atPath: path, expectedIdentifier: "com.agentguard.wrong-component")
        }
    }

    @Test func readingAnEmbeddedHashCannotReplaceCheckingItsSignature() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("agentguard-signature-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("candidate")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: CommandLine.arguments[0]), to: target)
        let original = try CodeSigning.validatedCDHash(atPath: target.path)
        let data = try Data(contentsOf: target)
        try #require(data.count > 4096)
        let writer = try FileHandle(forWritingTo: target)
        try writer.seek(toOffset: 4096)
        try writer.write(contentsOf: Data([data[4096] ^ 1]))
        try writer.close()
        // Only the disposable copy changed; the running test executable and App are untouched.
        #expect(try CodeSigning.cdhash(atPath: target.path) == original)
        #expect(throws: PlatformError.self) {
            try CodeSigning.validatedCDHash(atPath: target.path)
        }
    }
}
#endif
