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
                fileName: String? = nil, fileType: String? = nil, fileSize: Int? = nil) {
        self.score     = score
        self.total     = total
        self.reportURL = reportURL
        self.riskLevel = score == 0 ? .clean : score < 3 ? .suspicious : .malicious
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
        self.riskLevel  = pulseCount == 0 ? .clean : pulseCount < 3 ? .suspicious : .malicious
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
        return .clean
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
    public var vtResult:      VTProviderResult?
    public var otxResult:     OTXProviderResult?
    public var shodanResult:  ShodanProviderResult?
    public var urlScanResult: URLScanProviderResult?
    public var domainInfo:    DomainInfo?
    public var ipInfoResult:  IPInfoProviderResult?

    public var overallRisk: RiskLevel {
        // Shodan is excluded: it reports exposure (open ports / CVEs), not confirmed
        // malicious activity. Including it inflated risk scores for benign hosts.
        [vtResult?.riskLevel,
         otxResult?.riskLevel,
         urlScanResult?.riskLevel]
            .compactMap { $0 }
            .max() ?? .unknown
    }

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
