import Foundation
import Testing
@testable import GuardCore

@Suite struct AccessLogHelperTests {
    @Test func persistenceRequiresTheNewHelperProtocol() {
        #expect(HelperProtocol.version == 9)
    }

    @Test func instanceRecordsPreserveStableRunIdentityAcrossHelpers() throws {
        let data = Data(#"{"instance":4,"profileID":"knodo","revision":7,"pid":42,"startTime":1700000000123456,"supervisedByLaunchd":false,"runUUID":"run-stable","instanceOrigin":"original-helper"}"#.utf8)
        let record = try JSONDecoder().decode(InstanceRecord.self, from: data)
        let encoded = try JSONEncoder().encode(record)
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["runUUID"] as? String == "run-stable")
        #expect(object["instanceOrigin"] as? String == "original-helper")
    }

    @Test func oldInstanceRecordsRemainReadableAndMigrationIsExplicit() throws {
        let data = Data(#"{"instance":4,"profileID":"knodo","revision":7,"pid":42,"startTime":1700000000123456,"supervisedByLaunchd":false}"#.utf8)
        let old = try JSONDecoder().decode(InstanceRecord.self, from: data)
        #expect(old.runUUID == nil && old.instanceOrigin == nil)
        let f = try HelperLogFixture()
        f.service.restoreInstance(id: old.instance, profileID: old.profileID, revision: old.revision,
                                  root: .init(pid: old.pid, version: 0), supervisedByLaunchd: false,
                                  rootStartTime: old.startTime)
        let migrated = try #require(f.service.instances(ofProfile: "knodo").first)
        #expect(migrated.runUUID == "run-test")
        #expect(migrated.instanceOrigin == "legacy-restored:helper-test")
        #expect(migrated.trackingIncomplete)

        f.service.restoreInstance(id: 8, profileID: "knodo", revision: 1, root: .init(pid: 80, version: 2),
                                  supervisedByLaunchd: true, runUUID: "original-run",
                                  instanceOrigin: "original-helper", bootSessionID: "boot", rootStartTime: 123)
        let restored = try #require(f.service.instances(ofProfile: "knodo").last)
        #expect(restored.runUUID == "original-run" && restored.instanceOrigin == "original-helper")
        #expect(restored.bootSessionID == "boot" && restored.rootStartTime == 123)
    }

    @Test func rawRepeatedOperationsPreserveSourceActorAndRuntimeRevision() async throws {
        let f = try HelperLogFixture(register: true)
        try f.save(Fixtures.profile(revision: 2))
        let received = Date(timeIntervalSince1970: 1_800_000_001)
        let source = Date(timeIntervalSince1970: 1_800_000_000)
        let event = ESLine(globalSequence: 77, process: f.managed, executablePath: "/usr/bin/tool",
                           kind: .open(path: "/Users/me/work/file", write: false),
                           processStartTime: 123456, receivedAt: received, sourceAt: source, sourceEventID: "source-77")
        f.service.observe(line: event)
        f.service.observe(line: event)
        f.service.observe(line: ESLine(globalSequence: 78, process: f.managed, executablePath: "/usr/bin/tool",
                                      kind: .rename(from: "/Users/me/work/from", to: "/Users/me/work/to"),
                                      sourceEventID: "source-78"))
        f.service.observe(line: ESLine(globalSequence: 79, process: .init(pid: 999, version: 1), executablePath: nil,
                                      kind: .create(path: "/unmanaged")))
        try await f.logs.flush()
        let records = try await f.accesses()
        #expect(records.count == 4)
        let repeated = records.filter { $0.operation == "open" }
        #expect(repeated.count == 2 && Set(repeated.map(\.eventID)).count == 2)
        #expect(repeated.allSatisfy {
            $0.pid == f.managed.pid && $0.pidversion == f.managed.version && $0.processStartTime == 123456
                && $0.receivedAt == received && $0.sourceAt == source && $0.sourceSequence == 77
                && $0.profileRevision == 1 && $0.source == .eslogger && $0.outcome == .allowedObserved
                && $0.runUUID == "run-test" && $0.instanceOrigin == "helper-test"
        })
        let rename = records.filter { $0.operation == "rename" }.sorted { $0.sourceSubsequence! < $1.sourceSubsequence! }
        #expect(rename.map(\.target) == ["/Users/me/work/from", "/Users/me/work/to"])
        #expect(rename.map(\.sourceSubsequence) == [0, 1])
        #expect(rename.allSatisfy { $0.sourceEventID == "source-78" && $0.sourceSequence == 78 })
        guard case let .activity(activity) = f.service.handle(.activity(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app) else {
            Issue.record("activity unavailable"); return
        }
        #expect(activity.recent.count == 4)
        #expect(Set(activity.recent.compactMap(\.eventID)) == Set(records.map(\.eventID)))
        #expect(activity.recent.allSatisfy { $0.accessLogWriterID == "helper-log-writer" && $0.accessLogSequence != nil })
    }

    @Test func unknownOpenModeIsSavedWithoutManufacturingAReadSuggestion() async throws {
        let f = try HelperLogFixture(register: true)
        for (sequence, rawFlags) in [nil, UInt32(32768)].enumerated() {
            f.service.observe(line: ESLine(globalSequence: UInt64(sequence + 1), process: f.managed,
                executablePath: "/usr/bin/tool", kind: .openUnclassified(path: "/config"),
                openFlags: rawFlags))
        }
        try await f.logs.flush()
        let records = try await f.accesses()
        #expect(records.count == 2)
        #expect(records.allSatisfy {
            $0.operation == "open" && $0.target == "/config" && $0.outcome == .allowedObserved
                && $0.evidence == "eslogger_notify_open_mode_unknown"
        })
        #expect(Set(records.compactMap(\.openFlags)) == [32768])
        guard case let .activity(activity) = f.service.handle(.activity(profileID: "knodo"),
                                                              caller: Fixtures.appCaller, process: f.app) else {
            Issue.record("activity unavailable"); return
        }
        #expect(activity.recent.isEmpty)
        guard case let .status(status) = f.service.handle(.status, caller: Fixtures.appCaller, process: f.app) else {
            Issue.record("status unavailable"); return
        }
        #expect(status.profiles.first?.pendingCount == 0)
    }

    @Test func validatedRestoredRootAcceptsItsExactESBirthWithoutChangingRuntimeIdentity() async throws {
        let f = try HelperLogFixture()
        try f.save(Fixtures.profile(revision: 2))
        let born: UInt64 = 1_700_000_000_123_456
        let placeholder = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: born))
        f.service.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: placeholder,
            supervisedByLaunchd: true, runUUID: "preserved-run", instanceOrigin: "old-helper",
            bootSessionID: "same-boot", rootStartTime: born)
        _ = f.service.adoptDescendants(of: [], knownBirths: [placeholder: born], birth: { $0 == 20 ? born : nil })
        f.service.ingest(.gap)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil,
            kind: .open(path: "/restored-root", write: false), processStartTime: born))
        try await f.logs.flush()
        let access = try #require(try await f.accesses().first)
        #expect(access.pidversion == f.managed.version && access.processStartTime == born)
        #expect(access.profileRevision == 1 && access.runUUID == "preserved-run")
        #expect(access.instanceOrigin == "old-helper" && access.bootID == "same-boot")
        let snapshot = try #require(f.service.instances(ofProfile: "knodo").first)
        #expect(snapshot.liveProcesses == [f.managed] && snapshot.entry == f.managed)
        #expect(snapshot.rootProcess == f.managed && snapshot.rootStartTime == born)
        #expect(snapshot.trackingIncomplete && !snapshot.lifecycleConfirmed)
    }

    @Test(arguments: [nil, 1_700_000_000_123_457] as [UInt64?])
    func restoredIdentityRejectsMissingOrDifferentBirth(_ supplied: UInt64?) async throws {
        let f = try HelperLogFixture()
        let born: UInt64 = 1_700_000_000_123_456
        let placeholder = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: born))
        f.service.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: placeholder,
            supervisedByLaunchd: false, rootStartTime: born)
        _ = f.service.adoptDescendants(of: [], knownBirths: [placeholder: born], birth: { $0 == 20 ? born : nil })
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil,
            kind: .fork(child: .init(pid: 21, version: 5)), processStartTime: supplied))
        try await f.logs.flush()
        #expect(try await f.accesses().isEmpty)
        #expect(f.service.instances(ofProfile: "knodo").first?.liveProcesses == [placeholder])
    }

    @Test func restoredPlaceholderNeedsPlatformValidationEvenWhenVersionCoincides() async throws {
        let f = try HelperLogFixture()
        let born: UInt64 = 1_700_000_000_123_456
        f.service.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: f.managed,
            supervisedByLaunchd: false, rootStartTime: born)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil,
            kind: .open(path: "/unvalidated", write: false), processStartTime: born))
        let child = ProcessKey(pid: 21, version: 5)
        f.service.observe(line: .init(globalSequence: 2, process: f.managed, executablePath: nil,
            kind: .fork(child: child), processStartTime: born))
        f.service.observe(line: .init(globalSequence: 3, process: child, executablePath: nil,
            kind: .open(path: "/unvalidated-child", write: false)))
        try await f.logs.flush()
        #expect(try await f.accesses().isEmpty)
        #expect(f.service.instances(ofProfile: "knodo").first?.liveProcesses == [f.managed])
    }

    @Test func validatedRestoredDescendantKeepsForkAndExecLineage() async throws {
        let f = try HelperLogFixture()
        let rootBorn: UInt64 = 1_700_000_000_123_456
        let childBorn = rootBorn + 1_000
        let root = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: rootBorn))
        let child = ProcessKey(pid: 21, version: 7)
        let grandchild = ProcessKey(pid: 22, version: 8)
        let execImage = ProcessKey(pid: 21, version: 9)
        f.service.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: root,
            supervisedByLaunchd: false, runUUID: "restored-descendants", rootStartTime: rootBorn)
        let adopted = f.service.adoptDescendants(
            of: [.init(key: child, executablePath: "/child", parentPID: 20, startTime: childBorn)],
            knownBirths: [root: rootBorn], birth: { $0 == 20 ? rootBorn : $0 == 21 ? childBorn : nil })
        #expect(adopted.count == 1)
        f.service.observe(line: .init(globalSequence: 1, process: child, executablePath: nil,
            kind: .fork(child: grandchild), processStartTime: childBorn, relatedProcessStartTime: childBorn + 1_000))
        f.service.observe(line: .init(globalSequence: 2, process: child, executablePath: nil,
            kind: .exec(target: execImage, path: "/exec-image"), processStartTime: childBorn,
            relatedProcessStartTime: childBorn))
        f.service.observe(line: .init(globalSequence: 3, process: grandchild, executablePath: nil,
            kind: .open(path: "/grandchild", write: false)))
        f.service.observe(line: .init(globalSequence: 4, process: execImage, executablePath: nil,
            kind: .open(path: "/after-exec", write: false)))
        try await f.logs.flush()
        let accesses = try await f.accesses()
        #expect(accesses.count == 4 && accesses.allSatisfy { $0.runUUID == "restored-descendants" })
        let snapshot = try #require(f.service.instances(ofProfile: "knodo").first)
        #expect(snapshot.liveProcesses == [root, grandchild, execImage])
        #expect(snapshot.trackingIncomplete)
    }

    @Test(arguments: [nil, 1_700_000_000_124_456, 1_700_000_000_124_457] as [UInt64?])
    func bufferedForkDoesNotDuplicateAnAlreadyAdoptedChild(_ relatedBirth: UInt64?) throws {
        let f = try HelperLogFixture()
        let rootBorn: UInt64 = 1_700_000_000_123_456
        let childBorn = rootBorn + 1_000
        let root = ProcessKey(pid: 20, version: UInt32(truncatingIfNeeded: rootBorn))
        let childPlaceholder = ProcessKey(pid: 21, version: UInt32(truncatingIfNeeded: childBorn))
        let child = ProcessKey(pid: 21, version: 7)
        f.service.restoreInstance(id: 4, profileID: "knodo", revision: 1, root: root,
            supervisedByLaunchd: false, rootStartTime: rootBorn)
        _ = f.service.adoptDescendants(of: [.init(key: child, executablePath: "/child", parentPID: 20, startTime: childBorn)],
            knownBirths: [root: rootBorn], birth: { $0 == 20 ? rootBorn : $0 == 21 ? childBorn : nil })
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil,
            kind: .fork(child: child), processStartTime: rootBorn, relatedProcessStartTime: relatedBirth))
        let beforeChildEvent = try #require(f.service.instances(ofProfile: "knodo").first)
        #expect(beforeChildEvent.liveProcesses == [f.managed, relatedBirth == childBorn ? child : childPlaceholder])
        f.service.observe(line: .init(globalSequence: 2, process: child, executablePath: nil,
            kind: .exit, processStartTime: childBorn))
        #expect(f.service.instances(ofProfile: "knodo").first?.liveProcesses == [f.managed])
    }

    @Test func unclassifiedDenialIsDurableWithoutInventedIdentityOrSuggestion() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.observe(denial: SandboxDenial(process: "tool", pid: f.managed.pid, operation: "mach-lookup",
                                                target: "com.example.unsupported", sourceEventID: "denial-1"))
        f.service.observe(denial: SandboxDenial(process: "other", pid: 999, operation: "mach-lookup", target: "unmanaged"))
        try await f.logs.flush()
        let record = try #require(try await f.accesses().first)
        #expect(record.operation == "mach-lookup" && record.rawTarget == "com.example.unsupported")
        #expect(record.outcome == .denied && record.source == .sandboxLog)
        #expect(record.pid == f.managed.pid && record.pidversion == nil && record.processStartTime == nil)
        #expect(record.sourceAt == nil && record.sourceSequence == nil && record.attributionStatus == .pidOnly)
        #expect(record.sourceEventID == "denial-1")
        #expect(f.service.handle(.pendingItems(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app) == .pendingItems([]))
        #expect(try await f.accesses().count == 1)
    }

    @Test func execKeepsTheActorKeyBeforeTrackerTransition() async throws {
        let f = try HelperLogFixture(register: true)
        let target = ProcessKey(pid: f.managed.pid, version: f.managed.version + 1)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: "/bin/zsh",
                                     kind: .exec(target: target, path: "/usr/bin/tool"), processStartTime: 500))
        try await f.logs.flush()
        let record = try #require(try await f.accesses().first)
        #expect(record.pidversion == f.managed.version && record.executablePath == "/bin/zsh")
        #expect(record.target == "/usr/bin/tool")
        #expect(f.service.managedInstance(of: target) == 1)
        #expect(f.service.managedInstance(of: f.managed) == nil)
    }

    @Test func accessLogInterfacesAreAppOnlyAndRejectManagedAppSignatures() async throws {
        let f = try HelperLogFixture(register: true)
        let requests: [HelperRequest] = [
            .accessLogStatus(profileID: "knodo"), .queryAccessLog(.init(profileID: "knodo")),
            .exportAccessLogPage(query: .init(profileID: "knodo"), byteLimit: 4096),
            .clearAccessLog(profileID: "knodo", expectedGeneration: 1),
        ]
        for request in requests {
            #expect(await f.request(request, caller: Fixtures.cliCaller, process: .init(pid: 30, version: 1)) == .failure(code: "not_trusted"))
            #expect(await f.request(request, caller: Fixtures.launcherCaller, process: .init(pid: 40, version: 1)) == .failure(code: "not_trusted"))
            #expect(await f.request(request, caller: Fixtures.appCaller, process: f.managed) == .failure(code: "managed_caller"))
        }
        #expect(f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: false),
                                 caller: Fixtures.cliCaller, process: .init(pid: 30, version: 1)) == .failure(code: "not_trusted"))
        #expect(f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: false),
                                 caller: Fixtures.appCaller, process: f.managed) == .failure(code: "managed_caller"))
        #expect(await f.request(.queryAccessLog(.init(profileID: "../outside"))) == .failure(code: "invalid_profile"))
        #expect(await f.request(.accessLogStatus(profileID: "missing")) == .failure(code: "unknown_profile"))
        #expect(f.service.handle(.queryAccessLog(.init(profileID: "knodo")), caller: Fixtures.appCaller,
                                 process: f.app) == .failure(code: "access_log_async_required"))
    }

    @Test func loggingSettingIsIndependentAndDefaultEnabled() async throws {
        let f = try HelperLogFixture(register: true)
        #expect(f.service.accessLogEnabled("knodo"))
        #expect(f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: false),
                                 caller: Fixtures.appCaller, process: f.app) == .ok)
        #expect(!f.service.accessLogEnabled("knodo"))
        #expect(try f.profiles.latest("knodo") == Fixtures.profile())
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/old", write: false)))
        try await f.logs.flush()
        #expect(try await f.accesses().isEmpty)
        guard case let .accessLogStatus(status) = await f.request(.accessLogStatus(profileID: "knodo")) else {
            Issue.record("status unavailable"); return
        }
        #expect(status.loggingEnabled == false && status.enabledProfileIDs.isEmpty)
        let reloadedSettings = AccessLogSettingStore(root: "/store", files: f.files)
        #expect(!reloadedSettings.isEnabled("knodo"))
    }

    @Test func clearBarrierAlsoCutsOffDisabledAndQueuedRecentEvents() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/old", write: false)))
        _ = f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: false), caller: Fixtures.appCaller, process: f.app)
        f.service.observe(line: .init(globalSequence: 2, process: f.managed, executablePath: nil, kind: .open(path: "/disabled-old", write: false)))
        guard case let .accessLogCleared(profileID, result) = await f.request(.clearAccessLog(profileID: "knodo", expectedGeneration: 1)) else {
            Issue.record("clear unavailable"); return
        }
        f.service.observe(line: .init(globalSequence: 3, process: f.managed, executablePath: nil, kind: .open(path: "/disabled-new", write: false)))
        f.service.completeAccessLogClear(profileID: profileID, result: result)
        guard case let .activity(activity) = f.service.handle(.activity(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app) else {
            Issue.record("activity unavailable"); return
        }
        #expect(activity.recent.map(\.access) == [.read("/disabled-new")])
        #expect(activity.history.filter { $0.title == "已清空访问日志" }.count == 1)
        #expect(try await f.accesses().isEmpty)
        #expect(await f.request(.clearAccessLog(profileID: "knodo", expectedGeneration: 1)) == .failure(code: "access_log_generation_conflict"))
    }

    @Test func clearIngressBoundaryOnlyRunsAfterTrustAndProfileValidation() async throws {
        let f = try HelperLogFixture(register: true)
        var boundaryCalls = 0
        f.service.onAccessLogClearBoundary = {
            boundaryCalls += 1
            f.service.observe(line: .init(globalSequence: 10, process: f.managed, executablePath: nil,
                                          kind: .open(path: "/queued-before-clear", write: false)))
        }
        let clear = HelperRequest.clearAccessLog(profileID: "knodo", expectedGeneration: 1)
        #expect(await f.request(clear, caller: Fixtures.cliCaller, process: .init(pid: 30, version: 1)) == .failure(code: "not_trusted"))
        #expect(await f.request(clear, caller: Fixtures.appCaller, process: f.managed) == .failure(code: "managed_caller"))
        #expect(await f.request(.clearAccessLog(profileID: "missing", expectedGeneration: 1)) == .failure(code: "unknown_profile"))
        #expect(boundaryCalls == 0)
        guard case let .accessLogCleared(profileID, result) = await f.request(clear) else { Issue.record("clear unavailable"); return }
        #expect(boundaryCalls == 1)
        f.service.completeAccessLogClear(profileID: profileID, result: result)
        try await f.logs.flush()
        #expect(try await f.accesses().isEmpty)
        #expect(await f.request(.clearAccessLog(profileID: "knodo", expectedGeneration: 1)) == .failure(code: "access_log_generation_conflict"))
        #expect(boundaryCalls == 2)
        try await f.logs.flush()
        #expect(try await f.accesses().map(\.target) == ["/queued-before-clear"])
    }

    @Test func clearCutoffIsFrozenBeforeItsAsyncJobIsScheduled() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/old", write: false)))
        let operation = try #require(f.service.prepareAccessLogRequest(.clearAccessLog(profileID: "knodo", expectedGeneration: 1),
                                                                     caller: Fixtures.appCaller, process: f.app))
        f.service.observe(line: .init(globalSequence: 2, process: f.managed, executablePath: nil, kind: .open(path: "/after-boundary", write: false)))
        guard case let .accessLogCleared(profileID, result) = await operation() else { Issue.record("clear unavailable"); return }
        f.service.completeAccessLogClear(profileID: profileID, result: result)
        try await f.logs.flush()
        #expect(try await f.accesses().map(\.target) == ["/after-boundary"])
        guard case let .activity(activity) = f.service.handle(.activity(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app) else {
            Issue.record("activity unavailable"); return
        }
        #expect(activity.recent.map(\.access) == [.read("/after-boundary")])
    }

    @Test func persistenceDispositionIsFrozenWhenEachObservationArrives() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/queued", write: false)))
        _ = f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: false), caller: Fixtures.appCaller, process: f.app)
        f.service.observe(line: .init(globalSequence: 2, process: f.managed, executablePath: nil, kind: .open(path: "/memory-only", write: false)))
        _ = f.service.handle(.setAccessLogEnabled(profileID: "knodo", enabled: true), caller: Fixtures.appCaller, process: f.app)
        let rejected = try HelperLogFixture(register: true, budget: EventQueueBudget(maxBytes: 0, maxCount: 0))
        rejected.service.observe(line: .init(globalSequence: 3, process: rejected.managed, executablePath: nil, kind: .open(path: "/rejected", write: false)))
        func dispositions(_ fixture: HelperLogFixture) throws -> [String: String] {
            let response = fixture.service.handle(.activity(profileID: "knodo"), caller: Fixtures.appCaller, process: fixture.app)
            let data = try HelperWire.encode(response)
            let decoded = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
            let payload = try #require(decoded["activity"] as? [String: Any])
            let activity = try #require(payload["_0"] as? [String: Any])
            let recent = try #require(activity["recent"] as? [[String: Any]])
            return Dictionary(uniqueKeysWithValues: recent.compactMap {
                guard let id = $0["eventID"] as? String, let disposition = $0["accessLogDisposition"] as? String else { return nil }
                return (id, disposition)
            })
        }
        #expect(Set(try dispositions(f).values) == ["queued", "memory_only"])
        #expect(Set(try dispositions(rejected).values) == ["rejected"])
        let response = f.service.handle(.activity(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app)
        #expect(try HelperWire.decodeResponse(HelperWire.encode(response)) == response)
        guard case let .activity(activity) = response else { Issue.record("activity unavailable"); return }
        #expect(activity.recent.map(\.accessLogDisposition) == [.memoryOnly, .queued])
        // Adding optional receipt metadata must not make old observations unreadable.
        let old = Observation(instance: 1, access: .read("/legacy"), denied: false)
        let oldData = try JSONEncoder().encode(old)
        #expect(try JSONDecoder().decode(Observation.self, from: oldData).accessLogDisposition == nil)
        try await f.logs.flush()
    }

    @Test func sourceTimestampsRetainFractionalSecondsInPersistenceAndWire() async throws {
        let f = try HelperLogFixture(register: true)
        let sourceAt = Date(timeIntervalSince1970: 1_800_000_000.123456)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil,
                                     kind: .open(path: "/timestamp", write: false), receivedAt: sourceAt, sourceAt: sourceAt))
        try await f.logs.flush()
        let event = try #require(try await f.accesses().first)
        #expect(abs(try #require(event.sourceAt).timeIntervalSince1970 - sourceAt.timeIntervalSince1970) < 0.000002)
        #expect(abs(event.receivedAt.timeIntervalSince1970 - sourceAt.timeIntervalSince1970) < 0.000002)
        let response = await f.request(.queryAccessLog(.init(profileID: "knodo")))
        let decoded = try HelperWire.decodeResponse(HelperWire.encode(response))
        guard case let .accessLogPage(page) = decoded, let roundTripped = page.records.first(where: { $0.kind == .access }) else {
            Issue.record("wire query unavailable"); return
        }
        #expect(abs(try #require(roundTripped.sourceAt).timeIntervalSince1970 - sourceAt.timeIntervalSince1970) < 0.000002)
    }

    @Test func coverageReportsActualSubscriptionAndAttributionGaps() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.updateCollectorHealth(.init(problems: []))
        f.service.updateAccessLogCoverage(fileEventsSubscribed: false)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/before", write: false)))
        f.service.updateAccessLogCoverage(fileEventsSubscribed: true)
        f.service.ingest(.gap)
        f.service.recordAccessLogGap(reason: "input_overflow", droppedCount: 4)
        f.service.observe(line: .init(globalSequence: 2, process: f.managed, executablePath: nil, kind: .open(path: "/after", write: false)))
        try await f.logs.flush()
        let records = try await f.accesses()
        let before = try #require(records.first { $0.target == "/before" })
        let after = try #require(records.first { $0.target == "/after" })
        #expect(before.coverage.fileEventsSubscribed == false && before.coverage.collectorHealthy == true)
        #expect(after.coverage.fileEventsSubscribed == true && after.coverage.attributionComplete == false)
        #expect(after.attributionStatus == .incomplete && !after.coverage.successfulNetworkCovered)
        let all = try await f.logs.query(.init(profileID: "knodo"))
        #expect(all.records.contains { $0.kind == .gap && $0.gap?.reason == "input_overflow" && $0.gap?.droppedCount == 4 })
    }

    @Test func historyQueriesNeverRegeneratePendingItemsAndWireRoundTrips() async throws {
        let f = try HelperLogFixture(register: true)
        f.service.observe(line: .init(globalSequence: 1, process: f.managed, executablePath: nil, kind: .open(path: "/historical", write: false)))
        try await f.logs.flush()
        let fresh = f.newService()
        let request = HelperRequest.queryAccessLog(.init(profileID: "knodo"))
        #expect(try HelperWire.decodeRequest(HelperWire.encode(request)) == request)
        let operation = try #require(fresh.prepareAccessLogRequest(request, caller: Fixtures.appCaller, process: f.app))
        let response = await operation()
        #expect(try HelperWire.decodeResponse(HelperWire.encode(response)) == response)
        #expect(fresh.handle(.pendingItems(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app) == .pendingItems([]))
        guard case let .accessLogPage(page) = response else { Issue.record("query unavailable"); return }
        #expect(page.records.filter { $0.kind == .access }.count == 1)
        let requests: [HelperRequest] = [
            .accessLogStatus(profileID: nil), .exportAccessLogPage(query: .init(profileID: "knodo"), byteLimit: 4096),
            .clearAccessLog(profileID: "knodo", expectedGeneration: 1), .setAccessLogEnabled(profileID: "knodo", enabled: false),
        ]
        for request in requests { #expect(try HelperWire.decodeRequest(HelperWire.encode(request)) == request) }
    }

    @Test func unavailableStorageIsVisibleAndIsNotReportedAsDisabled() async throws {
        let f = try HelperLogFixture()
        let service = HelperService(store: f.profiles, environment: Fixtures.environment, catalog: .init([]), trust: Fixtures.trust,
                                    verifier: HelperLogVerifier(), settings: Fixtures.helperSettings, clock: { HelperLogFixture.now },
                                    makeID: { "approval" }, accessLogInitializationError: "protected_directory_unavailable")
        let operation = try #require(service.prepareAccessLogRequest(.accessLogStatus(profileID: "knodo"), caller: Fixtures.appCaller, process: f.app))
        guard case let .accessLogStatus(status) = await operation() else { Issue.record("status unavailable"); return }
        #expect(!status.isReady && status.loggingEnabled == true)
        #expect(status.errors == ["protected_directory_unavailable"])
    }

    @Test func duplicateDenialSummaryStaysOneReceivedReport() async throws {
        let f = try HelperLogFixture(register: true)
        let denial = try #require(SandboxLogParser.parse("3 duplicate reports for Sandbox: tool(20) deny(1) file-read-data /same"))
        #expect(denial.reportedDuplicateCount == 3 && denial.operation == "file-read-data")
        f.service.observe(denial: denial)
        try await f.logs.flush()
        let records = try await f.accesses()
        #expect(records.count == 1)
        #expect(records.first?.evidence == "kernel_sandbox_denial;duplicate_report_summary_count=3")
        #expect(records.first?.target == "/same")
    }
}

private final class HelperLogFixture {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    let app = ProcessKey(pid: 10, version: 1)
    let managed = ProcessKey(pid: 20, version: 4)
    let files = InMemoryFileStore()
    let profiles: ProfileStore
    let logs: AccessLogStore
    let history: ActivityStore
    var service: HelperService!

    init(register: Bool = false, budget: EventQueueBudget = .init()) throws {
        profiles = ProfileStore(root: "/store", files: files)
        history = ActivityStore(root: "/store", files: files)
        logs = AccessLogStore(fileSystem: HelperLogMemoryFS(), scheduler: HelperLogScheduler(),
                              clock: { Self.now }, makeID: { UUID().uuidString }, writerID: "helper-log-writer",
                              budget: budget)
        service = newService()
        try save(Fixtures.profile())
        if register {
            guard case .registered = service.handle(.registerInstance(profileID: "knodo", revision: 1),
                                                     caller: Fixtures.cliCaller, process: managed) else {
                throw AccessLogError.storageUnavailable("fixture registration failed")
            }
        }
    }

    func newService() -> HelperService {
        HelperService(store: profiles, environment: Fixtures.environment, catalog: .init([]), trust: Fixtures.trust,
                      verifier: HelperLogVerifier(), settings: Fixtures.helperSettings, clock: { Self.now },
                      makeID: { UUID().uuidString }, activity: history, accessLog: logs,
                      helperSessionID: "helper-test", makeRunID: { "run-test" })
    }

    func save(_ profile: Profile) throws {
        guard case let .pending(info) = service.handle(.proposeChange(profile: profile), caller: Fixtures.appCaller, process: app),
              service.handle(.approveChange(changeID: info.id, digest: info.digest, authorization: Data("ok".utf8)),
                             caller: Fixtures.appCaller, process: app) == .applied(revision: profile.revision) else {
            throw AccessLogError.storageUnavailable("fixture approval failed")
        }
    }

    func request(_ request: HelperRequest, caller: CallerIdentity = Fixtures.appCaller, process: ProcessKey? = nil) async -> HelperResponse {
        guard let operation = service.prepareAccessLogRequest(request, caller: caller, process: process ?? app) else {
            return .failure(code: "fixture_not_async")
        }
        return await operation()
    }

    func accesses() async throws -> [AccessLogRecord] {
        try await logs.query(.init(profileID: "knodo")).records.filter { $0.kind == .access }
    }
}

private struct HelperLogVerifier: AuthorizationVerifier {
    func verify(token: Data?, scope: String, summary: [String]) -> Bool { token == Data("ok".utf8) }
}

private final class HelperLogScheduler: AccessLogScheduling, @unchecked Sendable {
    private let writer = DispatchQueue(label: "helper-log-test-writer")
    private let reader = DispatchQueue(label: "helper-log-test-reader")
    func write(after delay: TimeInterval, _ work: @escaping @Sendable () -> Void) {
        if delay == 0 { writer.async(execute: work) }
    }
    func read(_ work: @escaping @Sendable () -> Void) { reader.async(execute: work) }
}

private final class HelperLogMemoryFS: AccessLogFileSystem, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: [String: Data]] = [:]
    func profiles() throws -> [String] { lock.withLock { Array(storage.keys) } }
    func files(profileID: String) throws -> [AccessLogFileInfo] {
        lock.withLock { (storage[profileID] ?? [:]).map { .init(name: $0.key, size: UInt64($0.value.count)) } }
    }
    func createProfile(_ profileID: String) throws { lock.withLock { if storage[profileID] == nil { storage[profileID] = [:] } } }
    func read(profileID: String, name: String, offset: UInt64, limit: Int) throws -> Data {
        lock.withLock {
            let data = storage[profileID]?[name] ?? Data()
            let lower = min(data.count, Int(offset))
            return data.subdata(in: lower..<min(data.count, lower + limit))
        }
    }
    func append(profileID: String, name: String, data: Data) throws { lock.withLock { storage[profileID, default: [:]][name, default: Data()].append(data) } }
    func replace(profileID: String, name: String, data: Data) throws { lock.withLock { storage[profileID, default: [:]][name] = data } }
    func truncate(profileID: String, name: String, size: UInt64) throws {
        lock.withLock {
            let shortened = storage[profileID]?[name]?.prefix(Int(size))
            storage[profileID]?[name] = shortened
        }
    }
    func rename(profileID: String, from: String, to: String) throws {
        lock.withLock {
            let data = storage[profileID]?.removeValue(forKey: from)
            storage[profileID]?[to] = data
        }
    }
    func remove(profileID: String, name: String) throws { _ = lock.withLock { storage[profileID]?.removeValue(forKey: name) } }
    func synchronize(profileID: String, name: String) throws {}
    func availableBytes() throws -> UInt64? { UInt64.max }
}
