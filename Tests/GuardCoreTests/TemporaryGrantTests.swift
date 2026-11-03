import Foundation
import Testing
@testable import GuardCore

@Suite struct TemporaryGrantTests {
    typealias F = Fixtures
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test func removesOnlyExpiredGrants() {
        var temp = F.ro("/Users/me/docs")
        temp.expiresAt = now
        var later = F.ro("/Users/me/later")
        later.expiresAt = now.addingTimeInterval(60)
        let profile = F.profile(files: [F.rw("/Users/me/easyops"), temp, later])
        let result = profile.removingExpiredGrants(at: now)
        #expect(result.removed == [temp])
        #expect(result.profile.files == [F.rw("/Users/me/easyops"), later])
    }

    @Test func expiryRemovalIsATighteningDiff() throws {
        var temp = F.ro("/Users/me/docs")
        temp.expiresAt = now
        let before = F.profile(files: [temp])
        let after = before.removingExpiredGrants(at: now).profile
        let diff = PolicyDiff(from: try F.compile(before), to: try F.compile(after))
        #expect(!diff.requiresAuthorization)
        #expect(diff.changes.count == 1)
    }

    @Test func nextExpiryIsTheEarliest() {
        var a = F.ro("/Users/me/a"); a.expiresAt = now.addingTimeInterval(100)
        var b = F.ro("/Users/me/b"); b.expiresAt = now.addingTimeInterval(50)
        #expect(F.profile(files: [a, b, F.ro("/Users/me/c")]).nextExpiry == now.addingTimeInterval(50))
        #expect(F.profile().nextExpiry == nil)
    }
}
