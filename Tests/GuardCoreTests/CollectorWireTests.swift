import Foundation
import Testing
@testable import GuardCore

@Suite struct CollectorWireTests {
    @Test func roundTripsEveryEvent() {
        let events: [CollectorEvent] = [
            .eslogger(#"{"process":{"executable":{"path":"/bin/ls"}}}"#),
            .sandbox(#"{"eventMessage":"Sandbox: ls(77) deny(1) file-read-data /x"}"#),
            .error("Failed to open service: 0xe00002d8: Caller lacks TCC authorization for Full Disk Access"),
        ]
        for event in events {
            #expect(CollectorWire.decode(CollectorWire.encode(event)) == event)
        }
    }

    @Test func keepsPayloadsWithNewlinesAndQuotesIntact() {
        let payload = "line one\nline \"two\" \\ end"
        let encoded = CollectorWire.encode(.error(payload))
        #expect(!encoded.contains("\n"))
        #expect(CollectorWire.decode(encoded) == .error(payload))
    }

    @Test func rejectsGarbage() {
        #expect(CollectorWire.decode("not json") == nil)
        #expect(CollectorWire.decode(#"{"k":"other","v":"x"}"#) == nil)
        #expect(CollectorWire.decode(#"{"k":"es"}"#) == nil)
    }
}

@Suite struct CollectorInstallTests {
    static let bundled = Data([0x01, 0x02, 0x03])

    @Test func installsWhenNothingIsThere() {
        #expect(CollectorInstall.plan(existing: nil, bundled: Self.bundled) == .install)
    }

    @Test func identicalCopyIsLeftAlone() {
        #expect(CollectorInstall.plan(existing: Self.bundled, bundled: Self.bundled) == .keep)
    }

    @Test func differentCopyIsNotReplaced() {
        // Replacing it would invalidate the Full Disk Access grant bound to that exact binary.
        #expect(CollectorInstall.plan(existing: Data([0x09]), bundled: Self.bundled) == .keepOutdated)
    }

    @Test func missingBundledCopyNeverRemovesTheInstalledOne() {
        #expect(CollectorInstall.plan(existing: Data([0x09]), bundled: nil) == .keep)
        #expect(CollectorInstall.plan(existing: nil, bundled: nil) == .keep)
    }
}
