import Foundation

public enum ArtifactResolver {

    /// Classify and normalise raw user input into an Artifact.
    public static func resolve(_ raw: String) -> Artifact {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower   = trimmed.lowercased()

        // File hashes — checked first (specific all-hex, fixed-length fingerprint)
        if let hashType = hashType(lower) {
            return Artifact(raw: trimmed, normalized: lower, type: hashType)
        }

        // Full URL (has a scheme)
        if let url = URL(string: trimmed), url.scheme != nil, url.host != nil {
            return Artifact(raw: trimmed, normalized: trimmed, type: .url)
        }

        // IPv4
        if isIPv4(trimmed) {
            return Artifact(raw: trimmed, normalized: trimmed, type: .ip)
        }

        // IPv6 (bare or bracket-wrapped)
        let bare = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if isIPv6(bare) {
            return Artifact(raw: trimmed, normalized: bare, type: .ip)
        }

        // Treat everything else as a domain (strip leading www.)
        let domain = lower.replacingOccurrences(of: "^www\\.", with: "", options: .regularExpression)
        return Artifact(raw: trimmed, normalized: domain, type: .domain)
    }

    // MARK: - Private helpers

    private static func hashType(_ s: String) -> ArtifactType? {
        guard s.allSatisfy(\.isHexDigit) else { return nil }
        switch s.count {
        case 32:  return .md5
        case 40:  return .sha1
        case 64:  return .sha256
        case 128: return .sha512
        default:  return nil
        }
    }

    private static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let n = Int(part) else { return false }
            return (0...255).contains(n)
        }
    }

    private static func isIPv6(_ s: String) -> Bool {
        var addr = in6_addr()
        return inet_pton(AF_INET6, s, &addr) == 1
    }
}
