import SwiftUI
import NyctimeneCore

enum MainTab: String, CaseIterable, Identifiable {
    case lookup      = "Lookup"
    case connections = "Connections"
    case pcap        = "PCAP"
    case feeds       = "IOC Feeds"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .lookup:      return "magnifyingglass.circle"
        case .connections: return "network.badge.shield.half.filled"
        case .pcap:        return "doc.text.magnifyingglass"
        case .feeds:       return "list.bullet.rectangle"
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
        .background(
            store.settings.transparencyEnabled ? Color.clear : Color(NSColor.windowBackgroundColor)
        )
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
        HStack(spacing: 0) {
            // Owl + app name
            HStack(spacing: 10) {
                if let img = NSImage(named: "owl") ?? Bundle.module.image(forResource: "owl") {
                    Image(nsImage: img)
                        .resizable().scaledToFill()
                        .frame(width: 26, height: 26)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
                Text("Nyctimene")
                    .font(.title3.bold())
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
        .padding(.top, 48)   // titlebar clearance
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

    @ViewBuilder
    private var contentArea: some View {
        switch selectedTab {
        case .lookup:      LookupView()
        case .connections: ConnectionScanView()
        case .pcap:        PCAPView()
        case .feeds:       IOCFeedsView()
        }
    }
}
