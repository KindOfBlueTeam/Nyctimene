import Foundation
import Security

/// Stores API keys for all threat intelligence providers in the macOS Keychain.
public enum KeychainHelper {
    private static let service = "com.nyctimene"

    public enum Provider: String, CaseIterable {
        case virusTotal = "virustotal_api_key"
        case otx        = "otx_api_key"
        case shodan     = "shodan_api_key"
        case urlScan    = "urlscan_api_key"
        case ipInfo     = "ipinfo_api_key"

        public var displayName: String {
            switch self {
            case .virusTotal: return "VirusTotal"
            case .otx:        return "OTX AlienVault"
            case .shodan:     return "Shodan"
            case .urlScan:    return "URLScan.io"
            case .ipInfo:     return "IPInfo.io"
            }
        }
    }

    @discardableResult
    public static func save(_ key: String, for provider: Provider) -> Bool {
        let data = Data(key.utf8)

        // Delete any existing item first.  Delete does not require ACL
        // authorization, so this works even if the old item has a restrictive ACL.
        let deleteQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: provider.rawValue,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Create an access object with an *empty* trusted-application list.
        // An empty array (distinct from nil) tells the Security framework to
        // grant access to every application without a confirmation dialog.
        // This prevents the "Allow/Deny" prompt that appears on each new build
        // because ad-hoc code signatures change with every recompile.
        var access: SecAccess?
        SecAccessCreate(
            "Nyctimene \(provider.displayName) API Key" as CFString,
            [] as CFArray,
            &access
        )

        var addQuery: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecAttrAccount:      provider.rawValue,
            kSecValueData:        data,
            kSecAttrAccessible:   kSecAttrAccessibleAfterFirstUnlock,
        ]
        if let access { addQuery[kSecAttrAccess] = access }

        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    public static func load(for provider: Provider) -> String? {
        let query: [CFString: Any] = [
            kSecClass:        kSecClassGenericPassword,
            kSecAttrService:  service,
            kSecAttrAccount:  provider.rawValue,
            kSecReturnData:   true,
            kSecMatchLimit:   kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func delete(for provider: Provider) {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: provider.rawValue
        ]
        SecItemDelete(query as CFDictionary)
    }
}
