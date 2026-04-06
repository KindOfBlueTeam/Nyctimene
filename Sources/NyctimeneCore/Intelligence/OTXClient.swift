import Foundation

public class OTXClient {
    public static let shared = OTXClient()

    private let base = "https://otx.alienvault.com/api/v1/indicators"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> OTXProviderResult {
        guard let key = KeychainHelper.load(for: .otx), !key.isEmpty else {
            throw IntelError.missingAPIKey("OTX AlienVault")
        }
        switch artifact.type {
        case .domain:                       return try await lookupDomain(artifact.normalized, key: key)
        case .ip:                           return try await lookupIP(artifact.normalized, key: key)
        case .url:                          return try await lookupURL(artifact.normalized, key: key)
        case .md5, .sha1, .sha256, .sha512: return try await lookupFile(artifact.normalized, key: key)
        }
    }

    // MARK: - Private

    private func lookupDomain(_ domain: String, key: String) async throws -> OTXProviderResult {
        // OTX distinguishes root domains (/domain/) from subdomains (/hostname/).
        // "evil.com" → 2 labels → /domain/;  "api.evil.com" → 3+ labels → /hostname/
        let isHostname = domain.split(separator: ".").count > 2
        let kind       = isHostname ? "hostname" : "domain"
        let url = URL(string: "\(base)/\(kind)/\(domain)/general")!
        let data = try await fetch(url, key: key)
        let reportURL = "https://otx.alienvault.com/indicator/\(kind)/\(domain)"
        return try parsePulses(data, reportURL: reportURL)
    }

    private func lookupIP(_ ip: String, key: String) async throws -> OTXProviderResult {
        let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip
        let url = URL(string: "\(base)/IPv4/\(encoded)/general")!
        let data = try await fetch(url, key: key)
        let reportURL = "https://otx.alienvault.com/indicator/ip/\(ip)"
        return try parsePulses(data, reportURL: reportURL)
    }

    private func lookupURL(_ rawURL: String, key: String) async throws -> OTXProviderResult {
        let encoded = rawURL.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? rawURL
        let url = URL(string: "\(base)/url/\(encoded)/general")!
        let data = try await fetch(url, key: key)
        let reportURL = "https://otx.alienvault.com/indicator/url/\(encoded)"
        return try parsePulses(data, reportURL: reportURL)
    }

    private func lookupFile(_ hash: String, key: String) async throws -> OTXProviderResult {
        let url       = URL(string: "\(base)/file/\(hash)/general")!
        let data      = try await fetch(url, key: key)
        let reportURL = "https://otx.alienvault.com/indicator/file/\(hash)"
        return try parsePulses(data, reportURL: reportURL)
    }

    private func parsePulses(_ data: Data, reportURL: String) throws -> OTXProviderResult {
        guard let json      = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pulseInfo = json["pulse_info"] as? [String: Any],
              let count     = pulseInfo["count"] as? Int
        else { throw IntelError.decodingError }
        return OTXProviderResult(pulseCount: count, reportURL: reportURL)
    }

    private func fetch(_ url: URL, key: String) async throws -> Data {
        var req = URLRequest(url: url)
        req.setValue(key, forHTTPHeaderField: "X-OTX-API-KEY")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }
        return data
    }
}
