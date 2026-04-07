import Foundation

public struct IOCFeed: Codable, Identifiable {
    public var id:        UUID
    public var name:      String
    public var urlString: String
    public init(name: String, urlString: String) {
        self.id = UUID(); self.name = name; self.urlString = urlString
    }

    /// Pre-populated feeds shown on first launch. Users can delete any of these.
    public static let defaults: [IOCFeed] = [
        IOCFeed(name: "GreyNoise",      urlString: "https://viz.greynoise.io/query/last_seen:1d%20classification:%22malicious%22"),
        IOCFeed(name: "URLhaus",        urlString: "https://urlhaus.abuse.ch/browse/"),
        IOCFeed(name: "ThreatFox",      urlString: "https://threatfox.abuse.ch/browse/"),
        IOCFeed(name: "MalwareBazaar",  urlString: "https://bazaar.abuse.ch/browse/"),
    ]
}

public struct ThreatLandscapeSource: Codable, Identifiable {
    public var id:        UUID
    public var name:      String
    public var urlString: String
    public init(name: String, urlString: String) {
        self.id = UUID(); self.name = name; self.urlString = urlString
    }

    public static let defaults: [ThreatLandscapeSource] = [
        ThreatLandscapeSource(name: "Wiz Threat Center",  urlString: "https://threats.wiz.io/all-incidents"),
        ThreatLandscapeSource(name: "OTX Dashboard",      urlString: "https://otx.alienvault.com/dashboard/new"),
        ThreatLandscapeSource(name: "GreyNoise",          urlString: "https://viz.greynoise.io/query/last_seen:1d%20classification:%22malicious%22"),
        ThreatLandscapeSource(name: "URLhaus",            urlString: "https://urlhaus.abuse.ch/browse/"),
        ThreatLandscapeSource(name: "ThreatFox",          urlString: "https://threatfox.abuse.ch/browse/"),
        ThreatLandscapeSource(name: "MalwareBazaar",      urlString: "https://bazaar.abuse.ch/browse/"),
    ]
}

// MARK: - Provider capability registry

public enum APIUsageTier: String, Codable, CaseIterable {
    case unlimited = "Unlimited"
    case high      = "High"
    case limited   = "Limited"
}

/// Canonical provider keys used across settings, lookup, and the radar chart.
public enum ProviderKey: String, CaseIterable {
    case virusTotal    = "VT"
    case otx           = "OTX"
    case shodan        = "Shodan"
    case urlScan       = "Scan"
    case ipInfo        = "IPInfo"
    case malwareBazaar = "MB"
    case threatFox     = "TFox"
    case urlhaus       = "UHaus"
    case isc           = "ISC"

    /// Artifact types this provider can process.
    public var supportedTypes: Set<ArtifactType> {
        switch self {
        case .virusTotal:    return [.ip, .domain, .url, .md5, .sha1, .sha256, .sha512]
        case .otx:           return [.ip, .domain, .url, .md5, .sha1, .sha256, .sha512]
        case .shodan:        return [.ip]
        case .urlScan:       return [.domain, .url]
        case .ipInfo:        return [.ip]
        case .malwareBazaar: return [.md5, .sha1, .sha256]
        case .threatFox:     return [.ip, .domain, .url, .md5, .sha1, .sha256, .sha512]
        case .urlhaus:       return [.ip, .domain, .url, .md5, .sha256]
        case .isc:           return [.ip]
        }
    }

    /// Whether this provider supports a given artifact type.
    public func supports(_ type: ArtifactType) -> Bool { supportedTypes.contains(type) }

    /// Human-readable display name.
    public var displayName: String {
        switch self {
        case .virusTotal:    return "VirusTotal"
        case .otx:           return "OTX AlienVault"
        case .shodan:        return "Shodan"
        case .urlScan:       return "URLScan.io"
        case .ipInfo:        return "IPInfo.io"
        case .malwareBazaar: return "MalwareBazaar"
        case .threatFox:     return "ThreatFox"
        case .urlhaus:       return "URLhaus"
        case .isc:           return "SANS ISC"
        }
    }

    /// Default usage tier for each provider.
    public var defaultTier: APIUsageTier {
        switch self {
        case .virusTotal: return .limited
        case .shodan:     return .limited
        case .urlScan:    return .high
        case .ipInfo:     return .high
        default:          return .unlimited
        }
    }

    /// Whether this provider requires an API key.
    public var requiresKey: Bool {
        switch self {
        case .isc: return false
        default:   return true
        }
    }
}

public struct AppSettings: Codable {
    public var virusTotalEnabled:    Bool
    public var otxEnabled:           Bool
    public var shodanEnabled:        Bool
    public var urlScanEnabled:       Bool
    public var ipInfoEnabled:        Bool
    public var abuseChEnabled:       Bool
    public var appearanceMode:       String   // "system" | "light" | "dark"
    public var transparencyEnabled:  Bool     // legacy — migrated to windowStyle
    public var windowStyle:          String   // "solid" | "frosted" | "glass-regular" | "glass-clear" | "glass-tinted"
    public var iocFeeds:             [IOCFeed]
    public var hasSeededDefaultFeeds: Bool
    public var threatLandscapeSources: [ThreatLandscapeSource]
    public var hasSeededDefaultTLSources: Bool
    /// Per-provider API usage tier (keyed by ProviderKey.rawValue)
    public var providerUsageTiers: [String: APIUsageTier]
    /// Minimum VT detection count to classify as Suspicious (default 1)
    public var vtSuspiciousThreshold: Int
    /// Minimum VT detection count to classify as Malicious (default 3); always > vtSuspiciousThreshold
    public var vtMaliciousThreshold:  Int

    /// Returns the usage tier for a provider, falling back to its default.
    public func usageTier(for key: ProviderKey) -> APIUsageTier {
        providerUsageTiers[key.rawValue] ?? key.defaultTier
    }

    public static var `default`: AppSettings {
        AppSettings(
            virusTotalEnabled:    true,
            otxEnabled:           true,
            shodanEnabled:        true,
            urlScanEnabled:       true,
            ipInfoEnabled:        true,
            abuseChEnabled:       true,
            appearanceMode:       "system",
            transparencyEnabled:  false,
            windowStyle:          "solid",
            iocFeeds:             [],
            hasSeededDefaultFeeds: false,
            threatLandscapeSources: [],
            hasSeededDefaultTLSources: false,
            providerUsageTiers: [:],
            vtSuspiciousThreshold: 1,
            vtMaliciousThreshold:  3
        )
    }

    // Custom decoder so existing settings files without threshold keys load cleanly.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        virusTotalEnabled    = try c.decode(Bool.self,   forKey: .virusTotalEnabled)
        otxEnabled           = try c.decode(Bool.self,   forKey: .otxEnabled)
        shodanEnabled        = try c.decode(Bool.self,   forKey: .shodanEnabled)
        urlScanEnabled       = try c.decode(Bool.self,   forKey: .urlScanEnabled)
        ipInfoEnabled        = try c.decodeIfPresent(Bool.self,   forKey: .ipInfoEnabled) ?? true
        abuseChEnabled       = try c.decodeIfPresent(Bool.self,   forKey: .abuseChEnabled) ?? true
        appearanceMode       = try c.decode(String.self, forKey: .appearanceMode)
        transparencyEnabled  = try c.decodeIfPresent(Bool.self,   forKey: .transparencyEnabled) ?? false
        windowStyle          = try c.decodeIfPresent(String.self, forKey: .windowStyle) ?? "solid"
        iocFeeds             = try c.decodeIfPresent([IOCFeed].self, forKey: .iocFeeds) ?? []
        hasSeededDefaultFeeds = try c.decodeIfPresent(Bool.self, forKey: .hasSeededDefaultFeeds) ?? false
        threatLandscapeSources = try c.decodeIfPresent([ThreatLandscapeSource].self, forKey: .threatLandscapeSources) ?? []
        hasSeededDefaultTLSources = try c.decodeIfPresent(Bool.self, forKey: .hasSeededDefaultTLSources) ?? false
        providerUsageTiers = try c.decodeIfPresent([String: APIUsageTier].self, forKey: .providerUsageTiers) ?? [:]
        vtSuspiciousThreshold = try c.decodeIfPresent(Int.self, forKey: .vtSuspiciousThreshold) ?? 1
        vtMaliciousThreshold  = try c.decodeIfPresent(Int.self, forKey: .vtMaliciousThreshold)  ?? 3
    }

    public init(virusTotalEnabled: Bool, otxEnabled: Bool, shodanEnabled: Bool,
                urlScanEnabled: Bool, ipInfoEnabled: Bool, abuseChEnabled: Bool,
                appearanceMode: String, transparencyEnabled: Bool = false,
                windowStyle: String = "solid",
                iocFeeds: [IOCFeed], hasSeededDefaultFeeds: Bool,
                threatLandscapeSources: [ThreatLandscapeSource] = [],
                hasSeededDefaultTLSources: Bool = false,
                providerUsageTiers: [String: APIUsageTier] = [:],
                vtSuspiciousThreshold: Int = 1, vtMaliciousThreshold: Int = 3) {
        self.virusTotalEnabled    = virusTotalEnabled
        self.otxEnabled           = otxEnabled
        self.shodanEnabled        = shodanEnabled
        self.urlScanEnabled       = urlScanEnabled
        self.ipInfoEnabled        = ipInfoEnabled
        self.abuseChEnabled       = abuseChEnabled
        self.appearanceMode       = appearanceMode
        self.transparencyEnabled  = transparencyEnabled
        self.windowStyle          = windowStyle
        self.iocFeeds             = iocFeeds
        self.hasSeededDefaultFeeds = hasSeededDefaultFeeds
        self.threatLandscapeSources = threatLandscapeSources
        self.hasSeededDefaultTLSources = hasSeededDefaultTLSources
        self.providerUsageTiers = providerUsageTiers
        self.vtSuspiciousThreshold = vtSuspiciousThreshold
        self.vtMaliciousThreshold  = vtMaliciousThreshold
    }
}

public class SettingsStore: ObservableObject {
    public static let shared = SettingsStore()

    @Published public var settings: AppSettings

    private let settingsURL: URL

    public init() {
        settingsURL = SettingsStore.configURL()
        var loaded = SettingsStore.load(from: settingsURL) ?? .default

        // Migrate legacy transparency toggle to windowStyle
        if loaded.transparencyEnabled && loaded.windowStyle == "solid" {
            loaded.windowStyle = "frosted"
            loaded.transparencyEnabled = false
        }

        // Seed the built-in IOC feeds once (legacy — kept for decoder compat)
        if !loaded.hasSeededDefaultFeeds {
            loaded.hasSeededDefaultFeeds = true
        }

        // Migrate any existing IOC feeds into Threat Landscape sources
        if !loaded.iocFeeds.isEmpty {
            let existingURLs = Set(loaded.threatLandscapeSources.map(\.urlString))
            for feed in loaded.iocFeeds where !existingURLs.contains(feed.urlString) {
                loaded.threatLandscapeSources.append(
                    ThreatLandscapeSource(name: feed.name, urlString: feed.urlString))
            }
            loaded.iocFeeds = []
        }

        // Seed the built-in Threat Landscape sources once
        if !loaded.hasSeededDefaultTLSources {
            loaded.threatLandscapeSources    = ThreatLandscapeSource.defaults
            loaded.hasSeededDefaultTLSources = true
        }

        settings = loaded
        save()
    }

    public func save() {
        try? FileManager.default.createDirectory(
            at: settingsURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if let data = try? JSONEncoder().encode(settings) {
            try? data.write(to: settingsURL, options: .atomic)
        }
    }

    private static func load(from url: URL) -> AppSettings? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(AppSettings.self, from: data)
    }

    // MARK: - Paths

    public static var basePath: String {
        let appSupport = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first!
        return appSupport.appendingPathComponent("Nyctimene").path
    }

    public static func configURL() -> URL {
        URL(fileURLWithPath: basePath + "/config/settings.json")
    }

    public static func dbURL() -> URL {
        URL(fileURLWithPath: basePath + "/data/nyctimene.db")
    }
}
