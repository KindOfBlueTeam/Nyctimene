import AppKit
import Foundation

public enum PCAPScanner {

    private static let pidFile     = NSTemporaryDirectory() + "nyctimene_cap.pid"
    private static let captureFile = NSTemporaryDirectory() + "nyctimene_capture.pcap"

    // MARK: - Live Capture

    public static var isCapturing: Bool {
        FileManager.default.fileExists(atPath: pidFile)
    }

    /// Starts a tcpdump capture on all interfaces via admin AppleScript.
    public static func startCapture() throws {
        // Launch tcpdump in background, write PID so we can kill it later.
        let cmd = "tcpdump -i any -w '\(captureFile)' > /dev/null 2>&1 & echo $! > '\(pidFile)'"
        let script = "do shell script \"\(cmd)\" with administrator privileges"
        var err: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&err)
        if let err {
            let msg = (err[NSAppleScript.errorMessage] as? String) ?? "Failed to start capture"
            throw NSError(domain: "PCAPScanner", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: msg])
        }
    }

    /// Stops the running capture and returns the URL of the resulting PCAP file.
    @discardableResult
    public static func stopCapture() -> URL? {
        let cmd = "kill $(cat '\(pidFile)') 2>/dev/null; sleep 0.3; rm -f '\(pidFile)'"
        let script = "do shell script \"\(cmd)\" with administrator privileges"
        var err: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&err)
        let url = URL(fileURLWithPath: captureFile)
        return FileManager.default.fileExists(atPath: captureFile) ? url : nil
    }

    // MARK: - Artifact Extraction

    /// Extracts unique routable IPs and queried domain names from a PCAP file.
    public static func extractArtifacts(from fileURL: URL) async throws -> [String] {
        // Two tcpdump passes: one for all IPs, one to pull DNS query names
        async let rawOutput  = ConnectionScanner.runProcess("/usr/sbin/tcpdump",
                                   args: ["-r", fileURL.path, "-n", "-q"])
        async let dnsOutput  = ConnectionScanner.runProcess("/usr/sbin/tcpdump",
                                   args: ["-r", fileURL.path, "-n", "udp port 53 or tcp port 53"])

        let (raw, dns) = try await (rawOutput, dnsOutput)
        var artifacts = Set<String>()

        // Extract IPv4 src/dst from lines like "IP 1.2.3.4.port > 5.6.7.8.port:"
        let ipPat = try! NSRegularExpression(
            pattern: #"IP6? (\d{1,3}(?:\.\d{1,3}){3})\.\d+ > (\d{1,3}(?:\.\d{1,3}){3})\.\d+:"#)
        for m in ipPat.matches(in: raw, range: NSRange(raw.startIndex..., in: raw)) {
            for g in 1...2 {
                if let r = Range(m.range(at: g), in: raw) {
                    let ip = String(raw[r])
                    if !ReservedRanges.isReserved(ip) { artifacts.insert(ip) }
                }
            }
        }

        // Extract DNS query names from lines like "A? evil.com. "
        let dnsPat = try! NSRegularExpression(
            pattern: #"(?:A|AAAA|CNAME|MX|NS|PTR|TXT)\? ([a-zA-Z0-9][a-zA-Z0-9.\-]{2,}[a-zA-Z])\. "#)
        for m in dnsPat.matches(in: dns, range: NSRange(dns.startIndex..., in: dns)) {
            if let r = Range(m.range(at: 1), in: dns) {
                let domain = String(dns[r]).lowercased()
                if !ConnectionScanner.isDomainAllowed(domain) { artifacts.insert(domain) }
            }
        }

        return Array(artifacts).sorted()
    }
}
