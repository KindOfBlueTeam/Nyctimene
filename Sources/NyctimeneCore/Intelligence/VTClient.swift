import Foundation

public class VTClient {
    public static let shared = VTClient()

    private let base = "https://www.virustotal.com/api/v3"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    // MARK: - Public

    public func lookup(_ artifact: Artifact) async throws -> VTProviderResult {
        guard let key = KeychainHelper.load(for: .virusTotal), !key.isEmpty else {
            throw IntelError.missingAPIKey("VirusTotal")
        }
        switch artifact.type {
        case .domain:                       return try await lookupDomain(artifact.normalized, key: key)
        case .ip:                           return try await lookupIP(artifact.normalized, key: key)
        case .url:                          return try await lookupURL(artifact.normalized, key: key)
        case .md5, .sha1, .sha256, .sha512: return try await lookupFile(artifact.normalized, key: key)
        }
    }

    // MARK: - Private lookup methods

    private func lookupDomain(_ domain: String, key: String) async throws -> VTProviderResult {
        let url = URL(string: "\(base)/domains/\(domain)")!
        let data = try await fetch(url, key: key)
        return try parseAnalysis(data, reportURL: "https://www.virustotal.com/gui/domain/\(domain)")
    }

    private func lookupIP(_ ip: String, key: String) async throws -> VTProviderResult {
        let encoded = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip
        let url = URL(string: "\(base)/ip_addresses/\(encoded)")!
        let data = try await fetch(url, key: key)
        return try parseAnalysis(data, reportURL: "https://www.virustotal.com/gui/ip-address/\(ip)")
    }

    private func lookupURL(_ rawURL: String, key: String) async throws -> VTProviderResult {
        let b64 = Data(rawURL.utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let url = URL(string: "\(base)/urls/\(b64)")!
        let data = try await fetch(url, key: key)
        let encoded = Data(rawURL.utf8)
            .base64EncodedString()
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return try parseAnalysis(data, reportURL: "https://www.virustotal.com/gui/url/\(encoded)")
    }

    private func lookupFile(_ hash: String, key: String) async throws -> VTProviderResult {
        let url  = URL(string: "\(base)/files/\(hash)")!
        let data = try await fetch(url, key: key)

        guard let json  = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
              let stats = attrs["last_analysis_stats"] as? [String: Any]
        else { throw IntelError.decodingError }

        let malicious  = stats["malicious"]  as? Int ?? 0
        let suspicious = stats["suspicious"] as? Int ?? 0
        let total      = (stats.values.compactMap { $0 as? Int }).reduce(0, +)

        return VTProviderResult(
            score:    malicious + suspicious,
            total:    total,
            reportURL: "https://www.virustotal.com/gui/file/\(hash)",
            fileName: attrs["meaningful_name"] as? String,
            fileType: attrs["type_description"] as? String,
            fileSize: attrs["size"]             as? Int
        )
    }

    // MARK: - Shared parse / fetch

    private func parseAnalysis(_ data: Data, reportURL: String) throws -> VTProviderResult {
        guard let json  = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
              let stats = attrs["last_analysis_stats"] as? [String: Any]
        else { throw IntelError.decodingError }

        let malicious  = stats["malicious"]  as? Int ?? 0
        let suspicious = stats["suspicious"] as? Int ?? 0
        let total      = (stats.values.compactMap { $0 as? Int }).reduce(0, +)
        return VTProviderResult(score: malicious + suspicious, total: total, reportURL: reportURL)
    }

    private func fetch(_ url: URL, key: String) async throws -> Data {
        var req = URLRequest(url: url)
        req.setValue(key, forHTTPHeaderField: "x-apikey")
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }
        return data
    }
}
