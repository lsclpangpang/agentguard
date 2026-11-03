import Foundation

/// What the Helper learned about a connecting process from its audit token and code signature.
public struct CallerIdentity: Hashable, Sendable {
    public var uid: Int
    public var signingIdentifier: String?
    public var teamIdentifier: String?
    public var cdhash: String?
    /// Set when the caller process belongs to a managed run instance.
    public var managedInstance: Int?

    public init(uid: Int, signingIdentifier: String?, teamIdentifier: String?, cdhash: String?, managedInstance: Int?) {
        self.uid = uid
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.cdhash = cdhash
        self.managedInstance = managedInstance
    }
}

public enum CallerRole: String, Codable, Sendable {
    case app
    case cli
    case launcher
}

/// Expected code identity of one of our own binaries. Ad-hoc signed builds have no team, so they
/// are pinned by the cdhash of the binaries shipped in the same bundle as the Helper.
public struct CodeIdentity: Hashable, Sendable {
    public var signingIdentifier: String
    public var teamIdentifier: String?
    public var cdhashes: Set<String>

    public init(signingIdentifier: String, teamIdentifier: String?, cdhashes: Set<String>) {
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.cdhashes = Set(cdhashes.map { $0.lowercased() })
    }

    func matches(_ caller: CallerIdentity) -> Bool {
        guard caller.signingIdentifier == signingIdentifier else { return false }
        if let team = teamIdentifier { return caller.teamIdentifier == team }
        guard !cdhashes.isEmpty, let hash = caller.cdhash?.lowercased() else { return false }
        return cdhashes.contains(hash)
    }
}

public struct CallerTrustPolicy: Sendable {
    public var allowedUID: Int
    public var identities: [CallerRole: CodeIdentity]

    public init(allowedUID: Int, identities: [CallerRole: CodeIdentity]) {
        self.allowedUID = allowedUID
        self.identities = identities
    }

    /// 重读签名时某个程序可能正被重编、暂时读不到；这时沿用上一轮的结果，
    /// 而不是把这个角色从信任表里删掉，让正在处理的合法请求被判 not_trusted。
    public static func refreshed(_ previous: [CallerRole: CodeIdentity], with fresh: [CallerRole: CodeIdentity]) -> [CallerRole: CodeIdentity] {
        previous.merging(fresh) { _, new in new }
    }

    public func role(of caller: CallerIdentity) -> CallerRole? {
        guard caller.uid == allowedUID else { return nil }
        return identities.first { $0.value.matches(caller) }?.key
    }
}

/// Result of the system authorization prompt, already verified by the Helper and bound to one change.
public enum AuthorizationEvidence: Equatable, Sendable {
    case none
    case verified(changeID: String)
}

public struct PendingChange: Equatable, Sendable {
    public let id: String
    public let profileID: String
    public let baseRevision: Int
    public let diffDigest: String
    public let summaryLines: [String]
    public let requiresAuthorization: Bool
    public let createdAt: Date
    public let expiresAt: Date
}

public struct ApprovedChange: Equatable, Sendable, Codable {
    public let profileID: String
    public let baseRevision: Int
    public let newRevision: Int
    public let diffDigest: String

    public init(profileID: String, baseRevision: Int, newRevision: Int, diffDigest: String) {
        self.profileID = profileID
        self.baseRevision = baseRevision
        self.newRevision = newRevision
        self.diffDigest = diffDigest
    }

    enum CodingKeys: String, CodingKey {
        case profileID = "profile_id"
        case baseRevision = "base_revision"
        case newRevision = "new_revision"
        case diffDigest = "diff_digest"
    }
}

public enum ApprovalError: Error, Equatable, Sendable {
    case callerNotTrusted
    case callerIsManaged(instance: Int)
    case unknownChange
    case alreadyUsed
    case expired
    case digestMismatch
    case baseRevisionChanged(expected: Int, actual: Int)
    case authorizationMissing
    case authorizationRequired
}

/// Two-step change approval: the Helper proposes an exact diff, the user authorizes that exact
/// change, and the Helper applies it once against the revision it was computed from.
public struct ApprovalLedger {
    /// HelperService 重读签名后会改这里；它不另存副本，否则台账会一直用启动时那份信任表。
    var trust: CallerTrustPolicy
    private let lifetime: TimeInterval
    private let makeID: () -> String
    private var pending: [String: PendingChange] = [:]
    private var consumed: Set<String> = []

    public init(trust: CallerTrustPolicy, lifetime: TimeInterval = 300, makeID: @escaping () -> String) {
        self.trust = trust
        self.lifetime = lifetime
        self.makeID = makeID
    }

    public mutating func propose(profileID: String, baseRevision: Int, diff: PolicyDiff, caller: CallerIdentity, now: Date) throws -> PendingChange {
        try checkCaller(caller)
        let change = PendingChange(
            id: makeID(),
            profileID: profileID,
            baseRevision: baseRevision,
            diffDigest: diff.digest,
            summaryLines: diff.summaryLines,
            requiresAuthorization: diff.requiresAuthorization,
            createdAt: now,
            expiresAt: now.addingTimeInterval(lifetime)
        )
        pending[change.id] = change
        return change
    }

    public mutating func approve(
        changeID: String,
        presentedDigest: String,
        currentRevision: Int,
        caller: CallerIdentity,
        authorization: AuthorizationEvidence,
        now: Date
    ) throws -> ApprovedChange {
        try checkCaller(caller)
        guard !consumed.contains(changeID) else { throw ApprovalError.alreadyUsed }
        guard let change = pending.removeValue(forKey: changeID) else { throw ApprovalError.unknownChange }
        // Any attempt, successful or not, uses up the change; a retry needs a fresh proposal.
        consumed.insert(changeID)
        guard now <= change.expiresAt else { throw ApprovalError.expired }
        guard presentedDigest == change.diffDigest else { throw ApprovalError.digestMismatch }
        guard currentRevision == change.baseRevision else {
            throw ApprovalError.baseRevisionChanged(expected: change.baseRevision, actual: currentRevision)
        }
        if change.requiresAuthorization, authorization != .verified(changeID: changeID) {
            throw ApprovalError.authorizationMissing
        }
        return ApprovedChange(profileID: change.profileID, baseRevision: change.baseRevision, newRevision: change.baseRevision + 1, diffDigest: change.diffDigest)
    }

    /// Tightening changes need a trusted caller but no user authentication.
    public func applyTightening(profileID: String, baseRevision: Int, currentRevision: Int, diff: PolicyDiff, caller: CallerIdentity) throws -> ApprovedChange {
        try checkCaller(caller)
        guard !diff.requiresAuthorization else { throw ApprovalError.authorizationRequired }
        guard currentRevision == baseRevision else {
            throw ApprovalError.baseRevisionChanged(expected: baseRevision, actual: currentRevision)
        }
        return ApprovedChange(profileID: profileID, baseRevision: baseRevision, newRevision: baseRevision + 1, diffDigest: diff.digest)
    }

    private func checkCaller(_ caller: CallerIdentity) throws {
        if let instance = caller.managedInstance { throw ApprovalError.callerIsManaged(instance: instance) }
        guard trust.role(of: caller) == .app else { throw ApprovalError.callerNotTrusted }
    }
}
