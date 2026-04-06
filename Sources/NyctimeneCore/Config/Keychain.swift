import Foundation
import Security

/// Stores all provider API keys in a single consolidated Keychain item as a JSON dictionary.
/// One item = one password prompt. "Always Allow" then persists for the life of that binary.
public enum KeychainHelper {
    private static let service             = "com.nyctimene"
    private static let consolidatedAccount = "nyctimene_api_keys"

    public enum Provider: String, CaseIterable {
        case virusTotal = "virustotal_api_key"
        case otx        = "otx_api_key"
        case shodan     = "shodan_api_key"
        case urlScan    = "urlscan_api_key"
        case ipInfo     = "ipinfo_api_key"
        case abuseCh    = "abusech_api_key"

        public var displayName: String {
            switch self {
            case .virusTotal: return "VirusTotal"
            case .otx:        return "OTX AlienVault"
            case .shodan:     return "Shodan"
            case .urlScan:    return "URLScan.io"
            case .ipInfo:     return "IPInfo.io"
            case .abuseCh:    return "abuse.ch"
            }
        }
    }

    // MARK: - Public interface

    @discardableResult
    public static func save(_ value: String, for provider: Provider) -> Bool {
        var all = loadAll()
        if value.isEmpty {
            all.removeValue(forKey: provider.rawValue)
        } else {
            all[provider.rawValue] = value
        }
        return saveAll(all)
    }

    public static func load(for provider: Provider) -> String? {
        loadAll()[provider.rawValue]
    }

    public static func delete(for provider: Provider) {
        var all = loadAll()
        all.removeValue(forKey: provider.rawValue)
        saveAll(all)
    }

    // MARK: - Consolidated read/write

    private static func loadAll() -> [String: String] {
        // Try the consolidated item first.
        if let dict = readConsolidated() { return dict }

        // One-time migration: pull any legacy per-provider items into the consolidated item,
        // then delete the old ones so they no longer trigger individual Keychain prompts.
        let legacy = readLegacyItems()
        if !legacy.isEmpty {
            saveAll(legacy)
            deleteLegacyItems()
            return legacy
        }
        return [:]
    }

    private static func readConsolidated() -> [String: String]? {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: consolidatedAccount,
            kSecReturnData:  true,
            kSecMatchLimit:  kSecMatchLimitOne,
        ]
        var item: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: String]
        else { return nil }
        return dict
    }

    @discardableResult
    private static func saveAll(_ keys: [String: String]) -> Bool {
        guard let data = try? JSONSerialization.data(withJSONObject: keys) else { return false }

        // Always delete first — a fresh write gets a fresh ACL.
        let deleteQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: consolidatedAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let access = makeOpenAccess(description: "Nyctimene API Keys")
        var addQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    service,
            kSecAttrAccount:    consolidatedAccount,
            kSecValueData:      data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
        ]
        if let access { addQuery[kSecAttrAccess] = access }
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    // MARK: - Legacy migration helpers

    /// Reads any pre-consolidation per-provider Keychain items (may trigger old prompts once).
    private static func readLegacyItems() -> [String: String] {
        var result: [String: String] = [:]
        for provider in Provider.allCases {
            let query: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: provider.rawValue,
                kSecReturnData:  true,
                kSecMatchLimit:  kSecMatchLimitOne,
            ]
            var item: AnyObject?
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
                  let data = item as? Data,
                  let str  = String(data: data, encoding: .utf8),
                  !str.isEmpty
            else { continue }
            result[provider.rawValue] = str
        }
        return result
    }

    private static func deleteLegacyItems() {
        for provider in Provider.allCases {
            let q: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: provider.rawValue,
            ]
            SecItemDelete(q as CFDictionary)
        }
    }

    // MARK: - Access control

    // SecAccessCreate is deprecated since macOS 10.10, but remains the only API that lets
    // us specify "allow any application to read this item without a confirmation dialog."
    //
    // The trustedApplications parameter:
    //   nil → only the calling application is trusted; all others show a dialog.
    //   []  → no applications trusted → dialog appears on EVERY access (the old bug).
    //
    // By passing nil here and letting the user click "Always Allow" once, macOS records
    // the calling binary's hash in the ACL. Subsequent launches of the same binary skip
    // the dialog entirely. Re-installing the app (new binary hash) triggers one prompt.
    @available(macOS, deprecated: 10.10)
    private static func makeOpenAccess(description: String) -> SecAccess? {
        var access: SecAccess?
        SecAccessCreate(description as CFString, nil, &access)
        return access
    }
}
