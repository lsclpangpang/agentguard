import Foundation

/// One line travelling from the collector daemon to the Helper.
///
/// The daemon runs from `/Library/PrivilegedHelperTools`, outside the app bundle, so the code
/// identity that Full Disk Access is granted to does not change when the app is rebuilt. Only these
/// payloads cross the boundary; parsing stays in the Helper.
public enum CollectorEvent: Equatable, Sendable {
    /// A line from `eslogger --format json`.
    case eslogger(String)
    /// A line from `log stream` carrying a sandbox denial.
    case sandbox(String)
    /// A line from `eslogger`'s stderr, for example a missing Full Disk Access grant.
    case error(String)
    /// Actual source subscriptions/health from a collector supporting status envelopes.
    case status(CollectorRuntimeStatus)
    /// A bounded diagnostic, never a raw machine-wide event backlog.
    case gap(CollectorInputGap)
}

public enum CollectorWire {
    struct Envelope: Codable {
        let k: String
        let v: String
    }

    public static func encode(_ event: CollectorEvent) -> String {
        let envelope: Envelope
        switch event {
        case let .eslogger(line): envelope = Envelope(k: "es", v: line)
        case let .sandbox(line): envelope = Envelope(k: "sb", v: line)
        case let .error(line): envelope = Envelope(k: "err", v: line)
        case let .status(status): envelope = Envelope(k: "status", v: json(status))
        case let .gap(gap): envelope = Envelope(k: "gap", v: json(gap))
        }
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(envelope), let text = String(data: data, encoding: .utf8) else {
            return #"{"k":"err","v":"collector wire encode failure"}"#
        }
        return text
    }

    public static func decode(_ line: String) -> CollectorEvent? {
        guard let data = line.data(using: .utf8),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data)
        else { return nil }
        switch envelope.k {
        case "es": return .eslogger(envelope.v)
        case "sb": return .sandbox(envelope.v)
        case "err": return .error(envelope.v)
        case "status":
            guard let value: CollectorRuntimeStatus = value(envelope.v) else { return nil }
            return .status(value)
        case "gap":
            guard let value: CollectorInputGap = value(envelope.v) else { return nil }
            return .gap(value)
        default: return nil
        }
    }

    private static func json<T: Encodable>(_ value: T) -> String {
        guard let data = try? JSONEncoder().encode(value) else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    private static func value<T: Decodable>(_ text: String) -> T? {
        try? JSONDecoder().decode(T.self, from: Data(text.utf8))
    }
}

/// Whether the privileged collector binary has to be (re)installed.
///
/// The installed copy is deliberately left alone when it differs from the bundled one: replacing it
/// changes the code identity the user granted Full Disk Access to, which is exactly the churn this
/// split exists to avoid. Shipping a new collector is therefore a deliberate manual step.
public enum CollectorInstallPlan: Equatable, Sendable {
    case install
    case keep
    case keepOutdated
}

public enum CollectorInstall {
    public static func plan(existing: Data?, bundled: Data?) -> CollectorInstallPlan {
        guard let existing else { return bundled == nil ? .keep : .install }
        guard let bundled else { return .keep }
        return existing == bundled ? .keep : .keepOutdated
    }
}
