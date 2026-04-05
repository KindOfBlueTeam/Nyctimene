import Foundation

public struct DomainInfo {
    public let registrar:  String?
    public let registered: Date?
    public let expires:    Date?
    public let status:     [String]
}
