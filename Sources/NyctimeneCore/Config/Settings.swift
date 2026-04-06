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

public struct AppSettings: Codable {
    public var virusTotalEnabled:    Bool
    public var otxEnabled:           Bool
    public var shodanEnabled:        Bool
    public var urlScanEnabled:       Bool
    public var ipInfoEnabled:        Bool
    public var abuseChEnabled:       Bool
    public var appearanceMode:       String   // "system" | "light" | "dark"
    public var transparencyEnabled:  Bool
    public var iocFeeds:             [IOCFeed]
    public var hasSeededDefaultFeeds: Bool
    /// Minimum VT detection count to classify as Suspicious (default 1)
    public var vtSuspiciousThreshold: Int
    /// Minimum VT detection count to classify as Malicious (default 3); always > vtSuspiciousThreshold
    public var vtMaliciousThreshold:  Int

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
            iocFeeds:             [],
            hasSeededDefaultFeeds: false,
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
        transparencyEnabled  = try c.decode(Bool.self,   forKey: .transparencyEnabled)
        iocFeeds             = try c.decodeIfPresent([IOCFeed].self, forKey: .iocFeeds) ?? []
        hasSeededDefaultFeeds = try c.decodeIfPresent(Bool.self, forKey: .hasSeededDefaultFeeds) ?? false
        vtSuspiciousThreshold = try c.decodeIfPresent(Int.self, forKey: .vtSuspiciousThreshold) ?? 1
        vtMaliciousThreshold  = try c.decodeIfPresent(Int.self, forKey: .vtMaliciousThreshold)  ?? 3
    }

    public init(virusTotalEnabled: Bool, otxEnabled: Bool, shodanEnabled: Bool,
                urlScanEnabled: Bool, ipInfoEnabled: Bool, abuseChEnabled: Bool,
                appearanceMode: String, transparencyEnabled: Bool,
                iocFeeds: [IOCFeed], hasSeededDefaultFeeds: Bool,
                vtSuspiciousThreshold: Int = 1, vtMaliciousThreshold: Int = 3) {
        self.virusTotalEnabled    = virusTotalEnabled
        self.otxEnabled           = otxEnabled
        self.shodanEnabled        = shodanEnabled
        self.urlScanEnabled       = urlScanEnabled
        self.ipInfoEnabled        = ipInfoEnabled
        self.abuseChEnabled       = abuseChEnabled
        self.appearanceMode       = appearanceMode
        self.transparencyEnabled  = transparencyEnabled
        self.iocFeeds             = iocFeeds
        self.hasSeededDefaultFeeds = hasSeededDefaultFeeds
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

        // Seed the built-in IOC feeds once (not re-added if user removes them later)
        if !loaded.hasSeededDefaultFeeds {
            loaded.iocFeeds             = IOCFeed.defaults
            loaded.hasSeededDefaultFeeds = true
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
