import Foundation

public struct RDAPClient {
    public static let shared = RDAPClient()
    private init() {}

    private let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private let isoFormatterNoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    public func lookup(_ artifact: Artifact) async throws -> DomainInfo? {
        guard artifact.type == .domain else { return nil }

        let urlString = "https://rdap.org/domain/\(artifact.normalized)"
        guard let url = URL(string: urlString) else { return nil }

        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return nil
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        // Status
        let status = (json["status"] as? [String]) ?? []

        // Events
        var registered: Date? = nil
        var expires: Date? = nil
        if let events = json["events"] as? [[String: Any]] {
            for event in events {
                guard let action = event["eventAction"] as? String,
                      let dateStr = event["eventDate"] as? String else { continue }
                let date = parseDate(dateStr)
                switch action {
                case "registration": registered = date
                case "expiration":   expires    = date
                default: break
                }
            }
        }

        // Registrar name from entities where roles contains "registrar"
        var registrar: String? = nil
        if let entities = json["entities"] as? [[String: Any]] {
            for entity in entities {
                guard let roles = entity["roles"] as? [String],
                      roles.contains("registrar") else { continue }
                // vcardArray is [[Any]] — heterogeneous
                if let vcardArray = entity["vcardArray"] as? [Any],
                   vcardArray.count >= 2,
                   let vcardFields = vcardArray[1] as? [[Any]] {
                    for field in vcardFields {
                        guard field.count >= 4,
                              let fieldName = field[0] as? String,
                              fieldName == "fn",
                              let value = field[3] as? String else { continue }
                        registrar = value
                        break
                    }
                }
                if registrar != nil { break }
            }
        }

        return DomainInfo(
            registrar:  registrar,
            registered: registered,
            expires:    expires,
            status:     status
        )
    }

    private func parseDate(_ str: String) -> Date? {
        isoFormatter.date(from: str) ?? isoFormatterNoFrac.date(from: str)
    }
}
