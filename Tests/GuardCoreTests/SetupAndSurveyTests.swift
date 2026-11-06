import Foundation
import Testing
@testable import GuardCore

@Suite struct ProgramSetupTests {
    let machO = ProgramPathTests.machO
    var probe: FakeProgramProbe {
        FakeProgramProbe(
            files: [
                "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js": Data("#!/usr/bin/env node\nconsole.log(1)\n".utf8),
                "/opt/homebrew/Cellar/node/22.1.0/bin/node": machO,
                "/opt/homebrew/Cellar/codex/1.0/bin/codex": machO,
                "/Users/me/bin/tool": machO,
                "/Users/me/bin/run.sh": Data("#!/bin/zsh\necho\n".utf8),
                "/bin/zsh": machO,
                "/Users/me/bin/odd": Data("#!/usr/bin/env nosuch\n".utf8),
            ],
            links: [
                "/opt/homebrew/bin/claude": "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js",
                "/opt/homebrew/bin/node": "/opt/homebrew/Cellar/node/22.1.0/bin/node",
                "/opt/homebrew/bin/codex": "/opt/homebrew/Cellar/codex/1.0/bin/codex",
            ]
        )
    }

    @Test func npmScriptGetsInterpreterAndPackage() throws {
        let plan = try ProgramSetup.analyze("/opt/homebrew/bin/claude", home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe).get()
        #expect(plan.command == "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js")
        #expect(plan.program == nil)
        #expect(plan.exec == [plan.command, "/opt/homebrew/Cellar/node/22.1.0/bin/node", "/usr/bin/env"])
        #expect(plan.files.map(\.path) == ["/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code", "/opt/homebrew/Cellar/node/22.1.0"])
        #expect(plan.files.allSatisfy { $0.access == .readOnly })
        #expect(plan.reasons.count == 4)
    }

    @Test func machOInKegGetsItsKeg() throws {
        let plan = try ProgramSetup.analyze("/opt/homebrew/bin/codex", home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe).get()
        #expect(plan.program == "/opt/homebrew/Cellar/codex/1.0/bin/codex")
        #expect(plan.files.map(\.path) == ["/opt/homebrew/Cellar/codex/1.0"])
        let plain = try ProgramSetup.analyze("~/bin/tool", home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe).get()
        #expect(plain.files.isEmpty && plain.exec.isEmpty && plain.program == "/Users/me/bin/tool")
    }

    @Test func shellScriptOutsidePackageGetsItsOwnFile() throws {
        let plan = try ProgramSetup.analyze("/Users/me/bin/run.sh", home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe).get()
        #expect(plan.exec == ["/Users/me/bin/run.sh", "/bin/zsh"])
        #expect(plan.files == [FileGrant(path: "/Users/me/bin/run.sh", kind: .file, access: .readOnly)])
    }

    @Test func missingInterpreterIsReported() {
        let result = ProgramSetup.analyze("/Users/me/bin/odd", home: "/Users/me", homebrewPrefix: "/opt/homebrew", probe: probe)
        #expect(result == .failure(.script(interpreter: "nosuch")))
    }

    @Test func packageRootHandlesScopes() {
        #expect(ProgramSetup.packageRoot(of: "/a/node_modules/pkg/bin/x.js") == "/a/node_modules/pkg")
        #expect(ProgramSetup.packageRoot(of: "/a/node_modules/@s/pkg/x.js") == "/a/node_modules/@s/pkg")
        #expect(ProgramSetup.packageRoot(of: "/a/node_modules/x.js") == nil)
        #expect(ProgramSetup.packageRoot(of: "/usr/local/bin/x") == nil)
    }
}

@Suite struct InstallationSurveyTests {
    typealias F = Fixtures

    func knodo() -> Profile {
        var p = F.profile(extraRules: [#"(allow file-read* (regex #"^/x"))"#])
        p.launch = LaunchSettings(executable: "/Library/KnodoRestricted/entry.sh", arguments: [], workingDirectory: nil,
                                  originalLabel: "com.knodo.restricted-agent", restartOnCleanExit: true)
        p.programs = ["/Library/KnodoRestricted/release/knodo-agentd"]
        return p
    }

    let entries = [
        LaunchEntry(label: "com.knodo.restricted-agent", path: "/Library/LaunchAgents/com.knodo.restricted-agent.plist",
                    executable: "/Library/KnodoRestricted/entry.sh", arguments: []),
        LaunchEntry(label: "com.knodo.dev", path: "/Users/me/Library/LaunchAgents/com.knodo.dev.plist",
                    executable: "/bin/sh", arguments: ["-c", "x", "/Library/KnodoRestricted/release/knodo-agentd"]),
        // Similar name, different program: never claimed.
        LaunchEntry(label: "com.knodo.updater", path: "/Users/me/Library/LaunchAgents/com.knodo.updater.plist",
                    executable: "/Applications/Knodo.app/Contents/MacOS/updater", arguments: []),
    ]

    @Test func sortsEntriesByWhatTheyStart() {
        let status = ProfileStatusReport(profileID: "knodo", savedRevision: 1, mode: .enforce, revisionState: .applied(running: true),
                                         runningInstances: [3], pendingCount: 0, unmanagedProcesses: [77], untrackedInstances: [3])
        let survey = InstallationSurvey.survey(profiles: [knodo()], entries: entries, disabled: [DisabledLaunchEntry(label: "com.old", location: "/x", profileID: "knodo")],
                                               status: [status], resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        let findings = survey.first?.findings ?? []
        #expect(findings.contains(.originalNotReplaced(entries[0])))
        #expect(findings.contains(.otherLaunchEntry(entries[1])))
        #expect(!findings.contains(.otherLaunchEntry(entries[2])))
        #expect(findings.contains(.unmanagedCopies([77])))
        #expect(findings.contains(.untrackedCopies([3])))
        #expect(findings.contains { if case .unverifiedLegacyRules = $0 { return true } else { return false } })
        #expect(survey.first?.disabled.map(\.label) == ["com.old"])
        #expect(survey.first?.isOrganized == false)
    }

    @Test func originalStillPresentAfterTakeoverIsAConflict() {
        let status = ProfileStatusReport(profileID: "knodo", savedRevision: 1, mode: .enforce, revisionState: .applied(running: false),
                                         runningInstances: [], pendingCount: 0,
                                         launchAgent: LaunchAgentStatus(registered: true, running: true, runAtLogin: true, canRestoreOriginal: false))
        let survey = InstallationSurvey.survey(profiles: [knodo()], entries: [entries[0]], disabled: [], status: [status],
                                               resolver: AliasResolver.macOSDefault, caseInsensitive: true)
        #expect(survey.first?.findings.first == .otherLaunchEntry(entries[0]))
    }
}
