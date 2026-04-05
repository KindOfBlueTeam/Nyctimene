import Foundation

public class IPInfoClient {
    public static let shared = IPInfoClient()

    private let base = "https://ipinfo.io"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    // MARK: - Public

    /// Only meaningful for IP artifacts. Returns nil silently for domains, URLs, and hashes.
    public func lookup(_ artifact: Artifact) async throws -> IPInfoProviderResult {
        guard artifact.type == .ip else { throw IntelError.unsupportedArtifactType }
        guard let key = KeychainHelper.load(for: .ipInfo), !key.isEmpty else {
            throw IntelError.missingAPIKey("IPInfo.io")
        }
        return try await lookupIP(artifact.normalized, key: key)
    }

    // MARK: - Private

    private func lookupIP(_ ip: String, key: String) async throws -> IPInfoProviderResult {
        let url = URL(string: "\(base)/\(ip)")!
        var req = URLRequest(url: url)
        req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw IntelError.decodingError }

        let org     = json["org"]     as? String ?? ""
        let country = json["country"] as? String ?? ""
        let city    = json["city"]    as? String ?? ""

        // ASN is the first token of the org string (e.g. "AS714 Apple Inc.")
        let orgParts = org.components(separatedBy: " ")
        let asn      = orgParts.first.flatMap { $0.hasPrefix("AS") ? $0 : nil }
        let orgName  = orgParts.count > 1 ? orgParts.dropFirst().joined(separator: " ") : nil

        // Some plans return a richer `company` object
        var companyName: String? = orgName
        if let companyDict = json["company"] as? [String: Any],
           let name = companyDict["name"] as? String {
            companyName = name
        }

        return IPInfoProviderResult(
            org:      org,
            company:  companyName,
            asn:      asn,
            country:  country,
            city:     city,
            reportURL: "https://ipinfo.io/\(ip)"
        )
    }
}
