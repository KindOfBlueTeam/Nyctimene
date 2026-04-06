import Foundation

public class URLhausClient {
    public static let shared = URLhausClient()
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> URLhausResult {
        switch artifact.type {
        case .url:             return try await lookupURL(artifact)
        case .ip, .domain:     return try await lookupHost(artifact)
        case .md5:             return try await lookupPayload(artifact, param: "md5_hash")
        case .sha256:          return try await lookupPayload(artifact, param: "sha256_hash")
        case .sha1, .sha512:   throw IntelError.unsupportedArtifactType
        }
    }

    // MARK: - URL lookup

    private func lookupURL(_ artifact: Artifact) async throws -> URLhausResult {
        let endpoint = URL(string: "https://urlhaus-api.abuse.ch/v2/url/")!
        let encoded  = artifact.normalized
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? artifact.normalized
        let body = "url=\(encoded)"

        let (data, _) = try await post(endpoint, body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IntelError.decodingError
        }

        let status = json["query_status"] as? String ?? ""
        let refURL = json["urlhaus_reference"] as? String
            ?? "https://urlhaus.abuse.ch/browse.php"
        guard status != "no_results" else {
            return URLhausResult(found: false, urlStatus: nil, threat: nil,
                                 urlCount: 0, tags: [], reportURL: refURL)
        }

        return URLhausResult(
            found:     true,
            urlStatus: json["url_status"] as? String,
            threat:    json["threat"]     as? String,
            urlCount:  1,
            tags:      json["tags"]       as? [String] ?? [],
            reportURL: refURL
        )
    }

    // MARK: - Host lookup (domain or IP)

    private func lookupHost(_ artifact: Artifact) async throws -> URLhausResult {
        let endpoint = URL(string: "https://urlhaus-api.abuse.ch/v2/host/")!
        let body = "host=\(artifact.normalized)"

        let (data, _) = try await post(endpoint, body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IntelError.decodingError
        }

        let status = json["query_status"] as? String ?? ""
        let refURL = json["urlhaus_reference"] as? String
            ?? "https://urlhaus.abuse.ch/browse.php"
        guard status != "no_results" else {
            return URLhausResult(found: false, urlStatus: nil, threat: nil,
                                 urlCount: 0, tags: [], reportURL: refURL)
        }

        // Determine if any URL is currently online
        let urls = json["urls"] as? [[String: Any]] ?? []
        let onlineCount = urls.filter { ($0["url_status"] as? String) == "online" }.count
        let urlStatus   = onlineCount > 0 ? "online" : "offline"
        let urlCount    = json["url_count"] as? Int ?? urls.count

        // Collect all distinct threat types
        let threats = urls.compactMap { $0["threat"] as? String }
        let threat  = threats.first

        return URLhausResult(
            found:     true,
            urlStatus: urlStatus,
            threat:    threat,
            urlCount:  urlCount,
            tags:      json["tags"] as? [String] ?? [],
            reportURL: refURL
        )
    }

    // MARK: - Payload lookup (hash)

    private func lookupPayload(_ artifact: Artifact, param: String) async throws -> URLhausResult {
        let endpoint = URL(string: "https://urlhaus-api.abuse.ch/v2/payload/")!
        let body = "\(param)=\(artifact.normalized)"

        let (data, _) = try await post(endpoint, body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw IntelError.decodingError
        }

        let status = json["query_status"] as? String ?? ""
        let refURL = (json["urlhaus_reference"] as? String)
            ?? "https://urlhaus.abuse.ch/browse.php"
        guard status != "no_results" else {
            return URLhausResult(found: false, urlStatus: nil, threat: nil,
                                 urlCount: 0, tags: [], reportURL: refURL)
        }

        let urls = json["urls"] as? [[String: Any]] ?? []
        let onlineCount = urls.filter { ($0["url_status"] as? String) == "online" }.count
        let urlStatus   = onlineCount > 0 ? "online" : "offline"
        let urlCount    = json["urls_count"] as? Int ?? urls.count

        return URLhausResult(
            found:     true,
            urlStatus: urlStatus,
            threat:    json["signature"] as? String,
            urlCount:  urlCount,
            tags:      [],
            reportURL: refURL
        )
    }

    // MARK: - Shared POST helper

    private func post(_ url: URL, body: String) async throws -> (Data, URLResponse) {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.httpBody = body.data(using: .utf8)
        return try await session.data(for: req)
    }
}
