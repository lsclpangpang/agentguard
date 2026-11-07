import Foundation

/// POSIX shell arguments for a command copied to Terminal. Unlike LaunchArguments (our own
/// argument parser), this must suppress shell substitutions, operators, globbing and empty-word loss.
public enum ShellCommand {
    public static func format(_ arguments: [String]) -> String {
        arguments.map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }.joined(separator: " ")
    }
}
