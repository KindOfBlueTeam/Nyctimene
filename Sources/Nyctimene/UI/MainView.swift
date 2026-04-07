import SwiftUI
import NyctimeneCore

enum MainTab: String, CaseIterable, Identifiable {
    case lookup      = "Lookup"
    case connections = "Connections"
    case pcap        = "PCAP"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .lookup:      return "magnifyingglass.circle"
        case .connections: return "network.badge.shield.half.filled"
        case .pcap:        return "doc.text.magnifyingglass"
        }
    }
}

struct MainView: View {
    @State private var selectedTab: MainTab = .lookup
    @ObservedObject private var store = SettingsStore.shared

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            contentArea
        }
        .preferredColorScheme(resolvedColorScheme)
    }

    private var resolvedColorScheme: ColorScheme? {
        switch store.settings.appearanceMode {
        case "dark":  return .dark
        case "light": return .light
        default:      return nil
        }
    }

    // MARK: - Header / tab bar

    private var header: some View {
        HStack(spacing: 12) {
            // Square owl logo
            if let owl = Bundle.module.image(forResource: "Nyctimene_logo") {
                Image(nsImage: owl)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 60, height: 60)
            }

            // Text banner — screen blend removes solid black background
            if let banner = Bundle.module.image(forResource: "Nyctimene-banner") {
                Image(nsImage: banner)
                    .resizable()
                    .scaledToFit()
                    .frame(height: 52)
                    .blendMode(.screen)
            }

            Spacer()

            // Tab picker
            HStack(spacing: 2) {
                ForEach(MainTab.allCases) { tab in
                    tabButton(tab)
                }
            }
            .padding(3)
            .background(Color(NSColor.controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private func tabButton(_ tab: MainTab) -> some View {
        Button {
            selectedTab = tab
        } label: {
            Label(tab.rawValue, systemImage: tab.icon)
                .font(.subheadline)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(
                    selectedTab == tab
                        ? Color(NSColor.controlAccentColor).opacity(0.15)
                        : Color.clear,
                    in: RoundedRectangle(cornerRadius: 6)
                )
                .foregroundColor(selectedTab == tab ? .accentColor : .secondary)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Content

    // ZStack keeps ThreatLandscapeView (and its WKWebView) alive across tab switches.
    // Other tabs use conditional rendering since they don't hold expensive persistent state.
    private var contentArea: some View {
        ZStack {
            LookupView()
                .opacity(selectedTab == .lookup ? 1 : 0)
                .allowsHitTesting(selectedTab == .lookup)

            if selectedTab == .connections { ConnectionScanView() }
            if selectedTab == .pcap       { PCAPView() }
        }
    }
}
