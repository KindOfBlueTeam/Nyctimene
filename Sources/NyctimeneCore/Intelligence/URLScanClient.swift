import Foundation

public class URLScanClient {
    public static let shared = URLScanClient()

    private let base = "https://urlscan.io/api/v1"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> URLScanProviderResult {
        guard let key = KeychainHelper.load(for: .urlScan), !key.isEmpty else {
            throw IntelError.missingAPIKey("URLScan.io")
        }
        let query: String
        switch artifact.type {
        case .domain: query = "domain:\(artifact.normalized)"
        case .ip:     query = "ip:\(artifact.normalized)"
        case .url:
            let host = URL(string: artifact.normalized)?.host ?? artifact.normalized
            query = "domain:\(host)"
        case .md5, .sha1, .sha256, .sha512:
            throw IntelError.unsupportedArtifactType
        }
        return try await search(query: query, key: key)
    }

    // MARK: - Private

    private func search(query: String, key: String) async throws -> URLScanProviderResult {
        let encoded = query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? query
        let url = URL(string: "\(base)/search/?q=\(encoded)&size=10")!
        let data = try await fetch(url, key: key)

        guard let json    = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = json["results"] as? [[String: Any]]
        else { throw IntelError.decodingError }

        var maliciousCount = 0
        var latestScore: Int?
        var allTags: Set<String> = []

        for result in results {
            if let verdicts = result["verdicts"] as? [String: Any] {
                if let overall = verdicts["overall"] as? [String: Any] {
                    if overall["malicious"] as? Bool == true { maliciousCount += 1 }
                    if let score = overall["score"] as? Int, latestScore == nil {
                        latestScore = score
                    }
                    if let tags = overall["tags"] as? [String] {
                        tags.forEach { allTags.insert($0) }
                    }
                }
            }
        }

        // Build a search URL the user can open
        let searchURL = "https://urlscan.io/search/#\(query)"

        return URLScanProviderResult(
            scanCount:      results.count,
            maliciousCount: maliciousCount,
            latestScore:    latestScore,
            reportURL:      searchURL,
            tags:           Array(allTags).sorted()
        )
    }

    private func fetch(_ url: URL, key: String) async throws -> Data {
        var req = URLRequest(url: url)
        req.setValue(key, forHTTPHeaderField: "API-Key")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }
        return data
    }
}
