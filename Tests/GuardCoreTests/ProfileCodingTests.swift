import Foundation
import Testing
@testable import GuardCore

@Suite struct ProfileCodingTests {
    typealias F = Fixtures

    @Test func roundTripsThroughJSON() throws {
        var secret = FileGrant(path: "/Users/me/.ssh", kind: .directory, access: .readOnly, readsSecrets: true)
        secret.expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let profile = F.profile(
            files: [F.rw("/Users/me/easyops"), secret],
            exec: [ExecGrant(path: "/usr/bin/git", sha256: String(repeating: "c", count: 64))],
            network: NetworkPolicy(loopbackTCPConnect: [9910], outboundTCP: .allowed, listen: .denied),
            mode: .restrictedLearning,
            templates: [TemplateRef(id: "git", version: 2)],
            revision: 9
        )
        let data = try ProfileCodec.encode(profile)
        #expect(try ProfileCodec.decode(data) == profile)
    }

    @Test func encodingIsDeterministic() throws {
        let profile = F.profile(files: [F.rw("/Users/me/easyops")], network: NetworkPolicy(loopbackTCPConnect: [9910]))
        #expect(try ProfileCodec.encode(profile) == ProfileCodec.encode(profile))
        let text = String(decoding: try ProfileCodec.encode(profile), as: UTF8.self)
        #expect(text.contains("\"loopback_tcp_connect\""))
        #expect(text.contains("\"read_write\""))
    }

    @Test func exportImportPreservesEffectivePolicy() throws {
        let profile = F.profile(files: [F.rw("/tmp"), F.ro("/Users/me/docs/")], exec: [ExecGrant(path: "/usr/bin/../bin/git")])
        let reimported = try ProfileCodec.decode(try ProfileCodec.encode(profile))
        #expect(try F.compile(reimported) == F.compile(profile))
    }

    @Test func rejectsUnknownMode() {
        let json = #"{"id":"x","revision":1,"mode":"yolo","templates":[],"files":[],"exec":[],"network":{"loopback_tcp_connect":[],"outbound_tcp":"denied","listen":"denied","udp":"denied"}}"#
        #expect(throws: (any Error).self) { try ProfileCodec.decode(Data(json.utf8)) }
    }

    @Test func statusFromAnOlderHelperDecodesWithoutDetachedInstances() throws {
        let json = #"{"profileID":"knodo","savedRevision":2,"mode":"enforce","revisionState":{"applied":{"running":true}},"runningInstances":[1],"pendingCount":0}"#
        let report = try JSONDecoder().decode(ProfileStatusReport.self, from: Data(json.utf8))
        #expect(report.runningInstances == [1])
        #expect(report.detachedInstances == [])
    }
}
