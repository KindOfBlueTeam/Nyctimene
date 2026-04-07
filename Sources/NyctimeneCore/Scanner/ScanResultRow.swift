import Foundation

/// A single row in the bulk-scan results table.
public struct ScanResultRow: Identifiable {
    public let id         = UUID()
    public let artifact:    Artifact
    public var process:     String?             // populated by ConnectionScanner
    public var isAnalyzed:  Bool = false
    public var isQuerying:  Bool = false

    public var vtResult:            VTProviderResult?
    public var otxResult:           OTXProviderResult?
    public var shodanResult:        ShodanProviderResult?
    public var urlScanResult:       URLScanProviderResult?
    public var ipInfoResult:        IPInfoProviderResult?
    public var malwareBazaarResult: MalwareBazaarResult?
    public var threatFoxResult:     ThreatFoxResult?
    public var urlhausResult:       URLhausResult?

    public var nycRiskScore: NycRiskScore {
        var signals: [NycRiskSignal] = []
        if let vt = vtResult {
            signals.append(NycRiskSignal(source: "VirusTotal",    riskLevel: vt.riskLevel))
        }
        if let mb = malwareBazaarResult {
            signals.append(NycRiskSignal(source: "MalwareBazaar", riskLevel: mb.riskLevel))
        }
        if let tf = threatFoxResult {
            signals.append(NycRiskSignal(source: "ThreatFox",     riskLevel: tf.riskLevel))
        }
        if let uh = urlhausResult {
            signals.append(NycRiskSignal(source: "URLhaus",        riskLevel: uh.riskLevel))
        }
        return NycRiskScore(signals: signals)
    }

    public var overallRisk: RiskLevel { nycRiskScore.level }

    public init(artifact: Artifact, process: String? = nil) {
        self.artifact = artifact
        self.process  = process
    }
}
