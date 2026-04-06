import Foundation

public class ThreatFoxClient {
    public static let shared = ThreatFoxClient()
    private let endpoint = URL(string: "https://threatfox-api.abuse.ch/api/v1/")!
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> ThreatFoxResult {
        guard let key = KeychainHelper.load(for: .abuseCh), !key.isEmpty else {
            throw IntelError.missingAPIKey("abuse.ch")
        }

        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(key, forHTTPHeaderField: "Auth-Key")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "query": "search_ioc",
            "search_term": artifact.normalized
        ])

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw IntelError.httpError((response as? HTTPURLResponse)?.statusCode ?? 0)
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IntelError.decodingError
        }

        let encoded = artifact.normalized
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? artifact.normalized
        let fallbackURL = "https://threatfox.abuse.ch/browse.php?search=\(encoded)"

        let status = json["query_status"] as? String ?? ""
        guard status == "ok",
              let entries = json["data"] as? [[String: Any]],
              let entry = entries.first
        else {
            return ThreatFoxResult(
                found: false, threatType: nil, malwareFamily: nil,
                confidenceLevel: 0, firstSeen: nil, lastSeen: nil,
                tags: [], reportURL: fallbackURL
            )
        }

        let iocID = entry["id"] as? String ?? ""
        let reportURL = iocID.isEmpty ? fallbackURL : "https://threatfox.abuse.ch/ioc/\(iocID)/"

        return ThreatFoxResult(
            found:           true,
            threatType:      entry["threat_type"]       as? String,
            malwareFamily:   entry["malware_printable"] as? String,
            confidenceLevel: entry["confidence_level"]  as? Int ?? 0,
            firstSeen:       entry["first_seen"]        as? String,
            lastSeen:        entry["last_seen"]         as? String,
            tags:            entry["tags"]              as? [String] ?? [],
            reportURL:       reportURL
        )
    }
}
