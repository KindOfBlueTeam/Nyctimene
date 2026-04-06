import Foundation

// MARK: - Artifact

public enum ArtifactType: String {
    case ip, domain, url
    case md5, sha1, sha256, sha512

    /// True for any hash variant.
    public var isHash: Bool {
        switch self {
        case .md5, .sha1, .sha256, .sha512: return true
        default: return false
        }
    }
}

public struct Artifact {
    public let raw: String          // original user input
    public let normalized: String   // cleaned value sent to APIs
    public let type: ArtifactType

    public init(raw: String, normalized: String, type: ArtifactType) {
        self.raw        = raw
        self.normalized = normalized
        self.type       = type
    }
}

// MARK: - Nyctimene Risk Score

/// A single provider's contribution to the Nyctimene Risk Score.
/// Add new cases here as additional scoring sources are integrated.
public struct NycRiskSignal {
    public let source:    String
    public let riskLevel: RiskLevel

    public init(source: String, riskLevel: RiskLevel) {
        self.source    = source
        self.riskLevel = riskLevel
    }
}

/// Aggregate risk score computed from one or more provider signals.
/// Only sources with confirmed malicious/suspicious activity should be added as signals;
/// contextual providers (Shodan, IPInfo, OTX) are displayed separately.
public struct NycRiskScore {
    /// All signals that contributed to this score.
    public let signals: [NycRiskSignal]

    /// Highest risk level across all signals; .unknown when no signals are present.
    public var level: RiskLevel {
        signals.map(\.riskLevel).max() ?? .unknown
    }

    /// Signals that flagged something (suspicious or higher).
    public var flagged: [NycRiskSignal] {
        signals.filter { $0.riskLevel >= .suspicious }
    }

    /// 0–10 composite score.
    /// Each malicious signal contributes 7 pts, each suspicious 3 pts. Clamped to 10.
    public var numericScore: Int {
        let pts = signals.reduce(0) { acc, s in
            switch s.riskLevel {
            case .malicious:  return acc + 7
            case .suspicious: return acc + 3
            default:          return acc
            }
        }
        return min(10, pts)
    }

    public init(signals: [NycRiskSignal]) {
        self.signals = signals
    }
}

// MARK: - Risk level

public enum RiskLevel: Int, Comparable {
    case unknown    = 0
    case clean      = 1
    case suspicious = 2
    case malicious  = 3

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.rawValue < rhs.rawValue }

    public var label: String {
        switch self {
        case .unknown:    return "Unknown"
        case .clean:      return "Clean"
        case .suspicious: return "Suspicious"
        case .malicious:  return "Malicious"
        }
    }
}

// MARK: - Per-provider results

public struct VTProviderResult {
    public let score: Int           // detections out of total engines
    public let total: Int
    public let reportURL: String
    public let riskLevel: RiskLevel
    // File-specific metadata (non-nil only for hash lookups)
    public let fileName: String?
    public let fileType: String?
    public let fileSize: Int?

    public init(score: Int, total: Int, reportURL: String,
                suspiciousThreshold: Int = 1, maliciousThreshold: Int = 3,
                fileName: String? = nil, fileType: String? = nil, fileSize: Int? = nil) {
        self.score     = score
        self.total     = total
        self.reportURL = reportURL
        if score == 0 {
            self.riskLevel = .clean
        } else if score < maliciousThreshold {
            self.riskLevel = .suspicious
        } else {
            self.riskLevel = .malicious
        }
        self.fileName  = fileName
        self.fileType  = fileType
        self.fileSize  = fileSize
    }
}

public struct OTXProviderResult {
    public let pulseCount: Int      // number of threat intelligence reports
    public let reportURL: String
    public let riskLevel: RiskLevel

    public init(pulseCount: Int, reportURL: String) {
        self.pulseCount = pulseCount
        self.reportURL  = reportURL
        self.riskLevel  = pulseCount == 0 ? .unknown : pulseCount < 3 ? .suspicious : .malicious
    }
}

public struct ShodanProviderResult {
    public let ports: [Int]
    public let vulns: [String]      // CVE IDs
    public let org: String
    public let country: String
    public let isp: String
    public let reportURL: String

    public var riskLevel: RiskLevel {
        if !vulns.isEmpty { return .malicious }
        return ports.isEmpty ? .clean : .suspicious
    }
}

public struct URLScanProviderResult {
    public let scanCount: Int
    public let maliciousCount: Int
    public let latestScore: Int?    // 0-100 urlscan score
    public let reportURL: String
    public let tags: [String]

    public var riskLevel: RiskLevel {
        if maliciousCount > 0                       { return .malicious }
        if let s = latestScore, s > 50              { return .suspicious }
        if scanCount == 0                           { return .unknown }
        return .clean
    }
}

public struct MalwareBazaarResult {
    public let found:         Bool
    public let sha256:        String?
    public let md5:           String?
    public let fileName:      String?
    public let fileType:      String?
    public let fileSize:      Int?
    public let malwareFamily: String?   // "signature" field — malware family name
    public let tags:          [String]
    public let firstSeen:     String?
    public let reportURL:     String

    /// Any hash present in MalwareBazaar is a confirmed malware sample.
    public var riskLevel: RiskLevel { found ? .malicious : .unknown }
}

public struct ThreatFoxResult {
    public let found:           Bool
    public let threatType:      String?   // "botnet_cc", "payload_delivery", etc.
    public let malwareFamily:   String?   // printable malware name
    public let confidenceLevel: Int       // 0–100 as reported by ThreatFox
    public let firstSeen:       String?
    public let lastSeen:        String?
    public let tags:            [String]
    public let reportURL:       String

    /// C2 infrastructure confirmed by ThreatFox; confidence drives suspicious vs malicious.
    public var riskLevel: RiskLevel {
        guard found else { return .unknown }
        return confidenceLevel >= 75 ? .malicious : .suspicious
    }
}

public struct URLhausResult {
    public let found:      Bool
    public let urlStatus:  String?   // "online" | "offline" | "unknown" (nil = host lookup)
    public let threat:     String?   // e.g. "malware_download"
    public let urlCount:   Int       // number of URLs seen for host lookups
    public let tags:       [String]
    public let reportURL:  String

    /// Active malware distribution (online) = malicious; historical/offline = suspicious.
    public var riskLevel: RiskLevel {
        guard found else { return .unknown }
        return urlStatus == "online" ? .malicious : .suspicious
    }
}

// MARK: - IPInfo result (ownership context, not a threat signal)

public struct IPInfoProviderResult {
    public let org:      String    // full org string, e.g. "AS714 Apple Inc."
    public let company:  String?   // company name only, e.g. "Apple Inc."
    public let asn:      String?   // ASN only, e.g. "AS714"
    public let country:  String
    public let city:     String
    public let reportURL: String

    /// IPInfo is purely contextual — it never contributes to overall risk scoring.
    public let riskLevel: RiskLevel = .unknown
}

// MARK: - Aggregate result

public struct LookupResult {
    public let artifact: Artifact
    public var vtResult:             VTProviderResult?
    public var otxResult:            OTXProviderResult?
    public var shodanResult:         ShodanProviderResult?
    public var urlScanResult:        URLScanProviderResult?
    public var domainInfo:           DomainInfo?
    public var ipInfoResult:         IPInfoProviderResult?
    public var malwareBazaarResult:  MalwareBazaarResult?
    public var threatFoxResult:      ThreatFoxResult?
    public var urlhausResult:        URLhausResult?

    /// Nyctimene Risk Score — scored sources only.
    /// OTX pulse counts, Shodan exposure, URLScan, and IPInfo are shown as context cards.
    /// Add new NycRiskSignal entries here as additional scoring sources are integrated.
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

    /// Convenience accessor — use nycRiskScore for the full signal breakdown.
    public var overallRisk: RiskLevel { nycRiskScore.level }

    public init(artifact: Artifact) {
        self.artifact = artifact
    }
}

// MARK: - Errors

public enum IntelError: Error, LocalizedError {
    case missingAPIKey(String)
    case httpError(Int)
    case decodingError
    case unsupportedArtifactType

    public var errorDescription: String? {
        switch self {
        case .missingAPIKey(let p): return "\(p) API key not configured"
        case .httpError(let c):     return "HTTP \(c)"
        case .decodingError:        return "Unexpected response format"
        case .unsupportedArtifactType: return "This provider doesn't support this artifact type"
        }
    }
}
