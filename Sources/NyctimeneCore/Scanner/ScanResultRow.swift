import Foundation

/// A single row in the bulk-scan results table.
public struct ScanResultRow: Identifiable {
    public let id         = UUID()
    public let artifact:    Artifact
    public var process:     String?             // populated by ConnectionScanner
    public var isAnalyzed:  Bool = false

    public var vtResult:       VTProviderResult?
    public var otxResult:      OTXProviderResult?
    public var shodanResult:   ShodanProviderResult?
    public var urlScanResult:  URLScanProviderResult?
    public var ipInfoResult:   IPInfoProviderResult?

    public var overallRisk: RiskLevel {
        // Shodan is excluded — it surfaces exposure data (open ports / CVEs),
        // not confirmed malicious activity.
        [vtResult?.riskLevel, otxResult?.riskLevel, urlScanResult?.riskLevel]
            .compactMap { $0 }.max() ?? .unknown
    }

    public init(artifact: Artifact, process: String? = nil) {
        self.artifact = artifact
        self.process  = process
    }
}
