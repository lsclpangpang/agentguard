// swift-tools-version:6.0
import PackageDescription

let platformSettings: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "AgentGuard",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GuardCore", targets: ["GuardCore"]),
        .executable(name: "guard", targets: ["GuardCLI"]),
        .executable(name: "agentguard-launcher", targets: ["GuardLauncher"]),
        .executable(name: "agentguard-helper", targets: ["GuardHelper"]),
        .executable(name: "agentguard-collector", targets: ["GuardCollector"]),
        .executable(name: "AgentGuard", targets: ["AgentGuardApp"]),
    ],
    targets: [
        // Platform-independent decisions; fully unit tested on Linux and macOS.
        .target(name: "GuardCore"),
        // Thin macOS glue: sandbox, exec, XPC, code signing, Authorization Services.
        .target(name: "GuardPlatform", dependencies: ["GuardCore"], swiftSettings: platformSettings),
        .executableTarget(name: "GuardCLI", dependencies: ["GuardCore", "GuardPlatform"], swiftSettings: platformSettings),
        .executableTarget(name: "GuardLauncher", dependencies: ["GuardCore", "GuardPlatform"], swiftSettings: platformSettings),
        .executableTarget(name: "GuardHelper", dependencies: ["GuardCore", "GuardPlatform"], swiftSettings: platformSettings),
        // Privileged collector daemon: the only process holding Full Disk Access.
        .executableTarget(name: "GuardCollector", dependencies: ["GuardCore"], swiftSettings: platformSettings),
        .executableTarget(name: "AgentGuardApp", dependencies: ["GuardCore", "GuardPlatform"], swiftSettings: platformSettings),
        .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore"]),
        // Plain `import GuardCore`: catches APIs the app or CLI use that are not public.
        .testTarget(name: "GuardCoreAPITests", dependencies: ["GuardCore"]),
        .testTarget(name: "GuardPlatformTests", dependencies: ["GuardPlatform"], swiftSettings: platformSettings),
    ]
)
