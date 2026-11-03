import Foundation
import Testing
@testable import GuardPlatform

@Suite struct ExecTests {
    @Test func absolutePathIsUsedAsIs() {
        #expect(Exec.resolve("/usr/bin/git", searchPath: "/x", isExecutable: { $0 == "/usr/bin/git" }) == "/usr/bin/git")
        #expect(Exec.resolve("/usr/bin/git", searchPath: "/x", isExecutable: { _ in false }) == nil)
    }

    @Test func searchesPathInOrder() {
        let exists: Set<String> = ["/opt/homebrew/bin/python3", "/usr/bin/python3"]
        #expect(Exec.resolve("python3", searchPath: "/opt/homebrew/bin:/usr/bin", isExecutable: exists.contains) == "/opt/homebrew/bin/python3")
        #expect(Exec.resolve("python3", searchPath: ":/usr/bin", isExecutable: exists.contains) == "/usr/bin/python3")
        #expect(Exec.resolve("nope", searchPath: "/usr/bin", isExecutable: exists.contains) == nil)
    }

    @Test func relativePathWithSlashIsNotSearched() {
        #expect(Exec.resolve("./run.sh", searchPath: "/usr/bin", isExecutable: { $0 == "./run.sh" }) == "./run.sh")
    }

    @Test func homeLookupWorksForCurrentUser() {
        #expect(UserAccount.home(uid: getuid()) != nil)
    }
}
