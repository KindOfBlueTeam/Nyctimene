import Foundation

public class ShodanClient {
    public static let shared = ShodanClient()

    private let base = "https://api.shodan.io"
    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    public func lookup(_ artifact: Artifact) async throws -> ShodanProviderResult {
        guard let key = KeychainHelper.load(for: .shodan), !key.isEmpty else {
            throw IntelError.missingAPIKey("Shodan")
        }
        switch artifact.type {
        case .ip:
            return try await lookupIP(artifact.normalized, key: key)
        case .domain:
            // Resolve domain → IP via Shodan DNS, then look up the IP
            let ip = try await resolveToIP(artifact.normalized, key: key)
            return try await lookupIP(ip, key: key)
        case .url:
            guard let host = URL(string: artifact.normalized)?.host else {
                throw IntelError.unsupportedArtifactType
            }
            let ip = isIP(host) ? host : try await resolveToIP(host, key: key)
            return try await lookupIP(ip, key: key)
        case .md5, .sha1, .sha256, .sha512:
            throw IntelError.unsupportedArtifactType
        }
    }

    // MARK: - Private

    private func lookupIP(_ ip: String, key: String) async throws -> ShodanProviderResult {
        let url = URL(string: "\(base)/shodan/host/\(ip)?key=\(key)&minify=false")!
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else { throw IntelError.decodingError }
        guard http.statusCode == 200 else { throw IntelError.httpError(http.statusCode) }

        guard let json    = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw IntelError.decodingError }

        let ports   = json["ports"]   as? [Int]    ?? []
        let vulns   = (json["vulns"] as? [String: Any]).map { Array($0.keys) } ?? []
        let org     = json["org"]     as? String   ?? ""
        let country = json["country_name"] as? String ?? ""
        let isp     = json["isp"]     as? String   ?? ""

        return ShodanProviderResult(
            ports:     ports,
            vulns:     vulns.sorted(),
            org:       org,
            country:   country,
            isp:       isp,
            reportURL: "https://www.shodan.io/host/\(ip)"
        )
    }

    private func resolveToIP(_ host: String, key: String) async throws -> String {
        guard let url = URL(string: "\(base)/dns/resolve?hostnames=\(host)&key=\(key)") else {
            throw IntelError.decodingError
        }
        let (data, _) = try await session.data(from: url)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ip   = json[host] as? String
        else { throw IntelError.decodingError }
        return ip
    }

    private func isIP(_ s: String) -> Bool {
        var addr4 = in_addr(); var addr6 = in6_addr()
        return inet_pton(AF_INET, s, &addr4) == 1 || inet_pton(AF_INET6, s, &addr6) == 1
    }
}
