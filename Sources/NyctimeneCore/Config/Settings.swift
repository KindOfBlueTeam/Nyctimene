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
        IOCFeed(name: "Bitdefender",   urlString: "https://github.com/bitdefender/malware-ioc"),
        IOCFeed(name: "GitHubInfoSec", urlString: "https://github.com/GithubInfosec/latest-malware-IoC"),
        IOCFeed(name: "Bert-JanP",     urlString: "https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds"),
    ]
}

public struct AppSettings: Codable {
    public var virusTotalEnabled:    Bool
    public var otxEnabled:           Bool
    public var shodanEnabled:        Bool
    public var urlScanEnabled:       Bool
    public var ipInfoEnabled:        Bool
    public var appearanceMode:       String   // "system" | "light" | "dark"
    public var transparencyEnabled:  Bool
    public var iocFeeds:             [IOCFeed]
    public var hasSeededDefaultFeeds: Bool

    public static var `default`: AppSettings {
        AppSettings(
            virusTotalEnabled:    true,
            otxEnabled:           true,
            shodanEnabled:        true,
            urlScanEnabled:       true,
            ipInfoEnabled:        true,
            appearanceMode:       "system",
            transparencyEnabled:  false,
            iocFeeds:             [],
            hasSeededDefaultFeeds: false
        )
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
