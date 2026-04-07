import Foundation

/// SANS Internet Storm Center / DShield API client.
/// Free, no API key required. Must set a custom User-Agent header.
/// https://isc.sans.edu/api/
public class ISCClient {
    public static let shared = ISCClient()

    private let base = "https://isc.sans.edu/api/ip"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> ISCProviderResult {
        guard artifact.type == .ip else {
            throw IntelError.unsupportedArtifactType
        }

        let url = URL(string: "\(base)/\(artifact.normalized)?json")!
        var req = URLRequest(url: url)
        req.setValue("Nyctimene DFIR Tool (github.com/KindOfBlueTeam/Nyctimene)", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }

        if http.statusCode == 429 {
            throw IntelError.httpError(429) // rate limited — caller can retry later
        }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ip   = json["ip"] as? [String: Any]
        else { throw IntelError.decodingError }

        let count     = ip["count"] as? Int
        let attacks   = ip["attacks"] as? Int
        let asNumber  = ip["as"] as? Int
        let asName    = ip["asname"] as? String
        let asCountry = ip["ascountry"] as? String
        let network   = ip["network"] as? String
        let comment   = ip["comment"] as? String
        let minDate   = ip["mindate"] as? String
        let maxDate   = ip["maxdate"] as? String

        // Threat feeds
        var feedNames: [String] = []
        if let feeds = ip["threatfeeds"] as? [String: Any] {
            feedNames = Array(feeds.keys).sorted()
        }

        let reportURL = "https://isc.sans.edu/ipinfo/\(artifact.normalized)"

        return ISCProviderResult(
            reports:    count,
            targets:    attacks,
            asNumber:   asNumber,
            asName:     asName,
            asCountry:  asCountry,
            network:    network,
            comment:    comment,
            firstSeen:  minDate,
            lastSeen:   maxDate,
            threatFeeds: feedNames,
            reportURL:  reportURL
        )
    }
}
