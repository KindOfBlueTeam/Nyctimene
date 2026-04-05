import Foundation

/// Classifies IPv4/IPv6 addresses as private/reserved so scanners can skip them.
public enum ReservedRanges {

    public static func isReserved(_ ip: String) -> Bool {
        ip.contains(":") ? isReservedIPv6(ip) : isReservedIPv4(ip)
    }

    // MARK: - IPv4

    private static let ipv4Blocks: [(network: UInt32, mask: UInt32)] = [
        (0x7F000000, 0xFF000000), // 127.0.0.0/8   loopback
        (0x0A000000, 0xFF000000), // 10.0.0.0/8    RFC 1918
        (0xAC100000, 0xFFF00000), // 172.16.0.0/12 RFC 1918
        (0xC0A80000, 0xFFFF0000), // 192.168.0.0/16 RFC 1918
        (0xA9FE0000, 0xFFFF0000), // 169.254.0.0/16 link-local
        (0x64400000, 0xFFC00000), // 100.64.0.0/10  CGNAT
        (0x00000000, 0xFF000000), // 0.0.0.0/8
        (0xE0000000, 0xF0000000), // 224.0.0.0/4   multicast
        (0xF0000000, 0xF0000000), // 240.0.0.0/4   reserved
        (0xC0000000, 0xFFFFFF00), // 192.0.0.0/24  IETF protocol
        (0xC0000200, 0xFFFFFF00), // 192.0.2.0/24  TEST-NET-1
        (0xC6336400, 0xFFFFFF00), // 198.51.100.0/24 TEST-NET-2
        (0xCB007100, 0xFFFFFF00), // 203.0.113.0/24 TEST-NET-3
        (0xC6120000, 0xFFFE0000), // 198.18.0.0/15 benchmarking
        (0xFFFFFFFF, 0xFFFFFFFF), // 255.255.255.255 broadcast
    ]

    private static func isReservedIPv4(_ ip: String) -> Bool {
        guard let addr = toUInt32(ip) else { return false }
        return ipv4Blocks.contains { addr & $0.mask == $0.network & $0.mask }
    }

    private static func toUInt32(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    }

    // MARK: - IPv6

    private static func isReservedIPv6(_ ip: String) -> Bool {
        let l = ip.lowercased()
        if l == "::1" || l == "::" { return true }          // loopback / unspecified
        if l.hasPrefix("fe80") { return true }               // link-local
        if l.hasPrefix("fc") || l.hasPrefix("fd") { return true } // unique local
        if l.hasPrefix("ff") { return true }                 // multicast
        return false
    }
}
