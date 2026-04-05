import Foundation

public struct ConnectionEntry: Identifiable {
    public let id:          UUID   = UUID()
    public let remoteIP:    String
    public let process:     String
    public let remotePort:  Int?
}

public enum ConnectionScanner {

    /// Well-known CDN / platform domains whose IPs we skip without querying.
    public static let builtInAllowedSuffixes: Set<String> = [
        "apple.com", "icloud.com", "apple-dns.net", "aaplimg.com", "mzstatic.com",
        "cdn-apple.com", "apple-cloudkit.com",
        "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "youtube.com", "ytimg.com", "ggpht.com",
        "microsoft.com", "windows.net", "live.com", "azure.com", "msftconnecttest.com",
        "office.com", "office365.com", "microsoftonline.com",
        "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
        "akamaihd.net", "akamaiedge.net", "akamaitechnologies.com", "akamai.net",
        "amazonaws.com", "amazon.com", "awsstatic.com",
        "fastly.com", "fastly.net",
        "digicert.com", "letsencrypt.org", "ocsp.apple.com",
    ]

    public static func isDomainAllowed(_ domain: String) -> Bool {
        let d = domain.lowercased()
        return builtInAllowedSuffixes.contains { d == $0 || d.hasSuffix("." + $0) }
    }

    // MARK: - Scan

    /// Returns unique external IP endpoints visible in current network connections.
    public static func scan() async throws -> [ConnectionEntry] {
        let output = try await runProcess("/usr/sbin/lsof", args: ["-i", "-n", "-P"])
        return parseLsof(output)
    }

    private static func parseLsof(_ output: String) -> [ConnectionEntry] {
        var seen    = Set<String>()
        var entries = [ConnectionEntry]()

        for line in output.components(separatedBy: "\n").dropFirst() {
            guard line.contains("->") else { continue }

            let tokens = line.split(separator: " ", omittingEmptySubsequences: true)
            guard tokens.count >= 2 else { continue }
            let processName = String(tokens[0])

            guard let arrowRange = line.range(of: "->") else { continue }
            // NAME field may end with " (ESTABLISHED)" — take only the address part
            let afterArrow = String(line[arrowRange.upperBound...])
            let addrField  = afterArrow.components(separatedBy: " ").first ?? afterArrow

            let remoteIP: String
            let remotePort: Int?

            if addrField.hasPrefix("[") {
                // IPv6: [fe80::1]:443
                let inner = String(addrField.dropFirst())
                let parts = inner.components(separatedBy: "]:")
                remoteIP   = String(parts[0])
                remotePort = parts.count > 1 ? Int(parts[1]) : nil
            } else {
                // IPv4: 1.2.3.4:443
                guard let lastColon = addrField.lastIndex(of: ":") else { continue }
                remoteIP   = String(addrField[..<lastColon])
                remotePort = Int(addrField[addrField.index(after: lastColon)...])
            }

            guard !remoteIP.isEmpty,
                  remoteIP != "*",
                  !seen.contains(remoteIP),
                  !ReservedRanges.isReserved(remoteIP) else { continue }

            seen.insert(remoteIP)
            entries.append(ConnectionEntry(remoteIP: remoteIP, process: processName, remotePort: remotePort))
        }

        return entries
    }

    // MARK: - Helpers

    public static func runProcess(_ executable: String, args: [String]) async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: executable)
                p.arguments     = args
                let outPipe     = Pipe()
                p.standardOutput = outPipe
                p.standardError  = Pipe()
                do {
                    try p.launch()
                    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    cont.resume(returning: String(data: data, encoding: .utf8) ?? "")
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }
}
