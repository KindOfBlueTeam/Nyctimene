import Foundation
import AppKit

/// Manages /etc/hosts entries for blocking malicious domains.
/// Writes require a one-time admin prompt per action.
public enum HostsManager {

    private static let marker = "# Nyctimene"

    /// Add a domain to /etc/hosts (blocks all resolution).
    /// Returns true if the operation succeeded.
    @discardableResult
    public static func block(_ domain: String) -> Bool {
        let line = "0.0.0.0 \(domain)  \(marker)"
        // Escape single quotes in the line
        let escaped = line.replacingOccurrences(of: "'", with: "'\\''")
        let script = """
            do shell script "echo '\(escaped)' >> /etc/hosts && dscacheutil -flushcache" with administrator privileges
        """
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        return error == nil
    }

    /// Remove a domain from /etc/hosts.
    @discardableResult
    public static func unblock(_ domain: String) -> Bool {
        // Delete any line containing the domain that was added by Nyctimene
        let escaped = domain.replacingOccurrences(of: ".", with: "\\\\.")
        let script = """
            do shell script "sed -i '' '/0\\.0\\.0\\.0 \(escaped).*Nyctimene/d' /etc/hosts && dscacheutil -flushcache" with administrator privileges
        """
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        return error == nil
    }

    /// Returns all domains currently blocked by Nyctimene in /etc/hosts.
    public static func blockedDomains() -> [String] {
        guard let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8) else {
            return []
        }
        return content.components(separatedBy: "\n").compactMap { line in
            guard line.contains(marker) else { return nil }
            let parts = line.split(separator: " ")
            return parts.count >= 2 ? String(parts[1]) : nil
        }
    }

    /// True if the domain is already in the Nyctimene block list.
    public static func isBlocked(_ domain: String) -> Bool {
        blockedDomains().contains(domain)
    }
}
