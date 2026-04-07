import SwiftUI
import NyctimeneCore

struct SettingsView: View {
    @StateObject private var store = SettingsStore.shared
    @State private var selectedTab: SettingsTab = .providers

    var body: some View {
        VStack(spacing: 0) {
            // Logo header — name is embedded in the image
            if let img = Bundle.module.image(forResource: "Nyctimene_text") {
                Image(nsImage: img)
                    .resizable()
                    .scaledToFit()
                    .frame(height: 110)
                    .padding(.top, 20)
                    .padding(.bottom, 12)
            }

            TabView(selection: $selectedTab) {
                ProvidersTab(settings: $store.settings, onSave: store.save)
                    .tabItem { Label("Providers", systemImage: "key.horizontal") }
                    .tag(SettingsTab.providers)

                ScoringTab(settings: $store.settings, onSave: store.save)
                    .tabItem { Label("Scoring", systemImage: "slider.horizontal.3") }
                    .tag(SettingsTab.scoring)

                AppearanceTab(settings: $store.settings, onSave: store.save)
                    .tabItem { Label("Appearance", systemImage: "paintbrush") }
                    .tag(SettingsTab.appearance)

                BlockListTab()
                    .tabItem { Label("Block List", systemImage: "hand.raised") }
                    .tag(SettingsTab.blockList)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .frame(width: 540, height: 520)
    }
}

enum SettingsTab: String, CaseIterable {
    case providers, scoring, appearance, blockList = "Block List"
}

// MARK: - Providers Tab

struct ProvidersTab: View {
    @Binding var settings: AppSettings
    let onSave: () -> Void

    var body: some View {
        Form {
            ForEach(KeychainHelper.Provider.allCases, id: \.self) { provider in
                ProviderRow(provider: provider, settings: $settings, onSave: onSave)
            }
        }
        .formStyle(.grouped)
    }
}

struct ProviderRow: View {
    let provider: KeychainHelper.Provider
    @Binding var settings: AppSettings
    let onSave: () -> Void

    @State private var keyInput:  String  = ""
    @State private var testStatus: String = ""
    @State private var isTesting = false

    var body: some View {
        Section {
            HStack {
                Toggle("", isOn: enabledBinding)
                    .labelsHidden()
                    .onChange(of: enabledFor(provider)) { _ in onSave() }
                VStack(alignment: .leading, spacing: 2) {
                    Text(provider.displayName).font(.headline)
                    if provider == .abuseCh {
                        Text("One key covers MalwareBazaar · ThreatFox · URLhaus")
                            .font(.caption).foregroundColor(.secondary)
                    }
                }
                Spacer()
            }

            SecureField("API Key", text: $keyInput)
                .textFieldStyle(.roundedBorder)
                .disabled(!enabledFor(provider))

            HStack {
                Button("Save") {
                    KeychainHelper.save(keyInput, for: provider)
                    testStatus = "Saved."
                }
                .disabled(keyInput.isEmpty)

                if !testStatus.isEmpty {
                    Text(testStatus).foregroundColor(.secondary).font(.caption)
                }

                Spacer()

                // API Usage tier picker
                if let pk = providerKey {
                    HStack(spacing: 4) {
                        Text("API Usage:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Picker("", selection: tierBinding(pk)) {
                            ForEach(APIUsageTier.allCases, id: \.self) { tier in
                                Text(tier.rawValue).tag(tier)
                            }
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 200)
                    }
                }
            }
        }
        .onAppear { keyInput = KeychainHelper.load(for: provider) ?? "" }
    }

    private var enabledBinding: Binding<Bool> {
        Binding(
            get: { enabledFor(provider) },
            set: { val in setEnabled(val, for: provider); onSave() }
        )
    }

    private func enabledFor(_ p: KeychainHelper.Provider) -> Bool {
        switch p {
        case .virusTotal: return settings.virusTotalEnabled
        case .otx:        return settings.otxEnabled
        case .shodan:     return settings.shodanEnabled
        case .urlScan:    return settings.urlScanEnabled
        case .ipInfo:     return settings.ipInfoEnabled
        case .abuseCh:    return settings.abuseChEnabled
        }
    }

    private func setEnabled(_ val: Bool, for p: KeychainHelper.Provider) {
        switch p {
        case .virusTotal: settings.virusTotalEnabled = val
        case .otx:        settings.otxEnabled        = val
        case .shodan:     settings.shodanEnabled     = val
        case .urlScan:    settings.urlScanEnabled    = val
        case .ipInfo:     settings.ipInfoEnabled     = val
        case .abuseCh:    settings.abuseChEnabled    = val
        }
    }

    /// Maps KeychainHelper.Provider to the canonical ProviderKey for tier storage.
    /// abuse.ch maps to nil here since it covers 3 providers with separate keys.
    private var providerKey: ProviderKey? {
        switch provider {
        case .virusTotal: return .virusTotal
        case .otx:        return .otx
        case .shodan:     return .shodan
        case .urlScan:    return .urlScan
        case .ipInfo:     return .ipInfo
        case .abuseCh:    return nil  // individual tiers set via the sub-providers
        }
    }

    private func tierBinding(_ pk: ProviderKey) -> Binding<APIUsageTier> {
        Binding(
            get: { settings.providerUsageTiers[pk.rawValue] ?? pk.defaultTier },
            set: { settings.providerUsageTiers[pk.rawValue] = $0; onSave() }
        )
    }
}

// MARK: - Scoring Tab

struct ScoringTab: View {
    @Binding var settings: AppSettings
    let onSave: () -> Void

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Suspicious at ≥ \(settings.vtSuspiciousThreshold) detection\(settings.vtSuspiciousThreshold == 1 ? "" : "s")")
                        .font(.subheadline)
                    Slider(
                        value: Binding(
                            get: { Double(settings.vtSuspiciousThreshold) },
                            set: { newVal in
                                let v = max(1, Int(newVal))
                                settings.vtSuspiciousThreshold = v
                                // Malicious must always be at least suspicious + 1
                                if settings.vtMaliciousThreshold <= v {
                                    settings.vtMaliciousThreshold = v + 1
                                }
                                onSave()
                            }
                        ),
                        in: 1...Double(settings.vtMaliciousThreshold - 1),
                        step: 1
                    )

                    Text("Malicious at ≥ \(settings.vtMaliciousThreshold) detections")
                        .font(.subheadline)
                        .padding(.top, 6)
                    Slider(
                        value: Binding(
                            get: { Double(settings.vtMaliciousThreshold) },
                            set: { newVal in
                                let v = max(settings.vtSuspiciousThreshold + 1, Int(newVal))
                                settings.vtMaliciousThreshold = v
                                onSave()
                            }
                        ),
                        in: Double(settings.vtSuspiciousThreshold + 1)...50,
                        step: 1
                    )
                }
                .padding(.vertical, 4)
            } header: {
                Label("VirusTotal Detection Thresholds", systemImage: "shield.lefthalf.filled")
            } footer: {
                Text("Any score below the Suspicious threshold is shown as Clean. Scores from \(settings.vtSuspiciousThreshold)–\(settings.vtMaliciousThreshold - 1) are Suspicious. \(settings.vtMaliciousThreshold)+ are Malicious.")
                    .foregroundColor(.secondary)
                    .font(.caption)
            }

            Section {
                HStack {
                    riskPill("Clean", color: .green)
                    Text("0 detections")
                    Spacer()
                }
                HStack {
                    riskPill("Suspicious", color: .orange)
                    Text("\(settings.vtSuspiciousThreshold)–\(settings.vtMaliciousThreshold - 1) detection\(settings.vtMaliciousThreshold - 1 == 1 ? "" : "s")")
                    Spacer()
                }
                HStack {
                    riskPill("Malicious", color: .red)
                    Text("≥ \(settings.vtMaliciousThreshold) detections")
                    Spacer()
                }
            } header: {
                Label("Current Classification", systemImage: "chart.bar")
            }
        }
        .formStyle(.grouped)
    }

    private func riskPill(_ label: String, color: Color) -> some View {
        Text(label)
            .font(.caption.bold())
            .foregroundColor(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color, in: Capsule())
    }
}

// MARK: - Appearance Tab

struct AppearanceTab: View {
    @Binding var settings: AppSettings
    let onSave: () -> Void

    var body: some View {
        Form {
            Section("Color Scheme") {
                Picker("Appearance", selection: $settings.appearanceMode) {
                    Text("System").tag("system")
                    Text("Light").tag("light")
                    Text("Dark").tag("dark")
                }
                .pickerStyle(.radioGroup)
                .onChange(of: settings.appearanceMode) { _ in
                    onSave()
                    NotificationCenter.default.post(name: WindowAppearance.reapplyNotification, object: nil)
                }
            }

            Section("Window Style") {
                Picker("Style", selection: $settings.windowStyle) {
                    Text("Solid").tag("solid")
                    Text("Frosted Vibrancy").tag("frosted")
                }
                .pickerStyle(.radioGroup)
                .onChange(of: settings.windowStyle) { _ in
                    onSave()
                    NotificationCenter.default.post(name: WindowAppearance.reapplyNotification, object: nil)
                }
                Text("Applies to all Nyctimene windows.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Block List Tab

struct BlockListTab: View {
    @State private var blocked:    [String] = []
    @State private var newDomain:  String   = ""
    @State private var statusMsg:  String   = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {

            // Description
            VStack(alignment: .leading, spacing: 6) {
                Label("How blocking works", systemImage: "info.circle")
                    .font(.caption.bold())
                    .foregroundColor(.secondary)
                Text("Blocked domains are written to /etc/hosts as 0.0.0.0, which prevents all DNS resolution on this Mac. Each change requires a one-time administrator password prompt. You can also block a domain from the Analyze tab after running a lookup.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 10)

            Divider()

            // Add domain row
            HStack(spacing: 8) {
                TextField("domain.example.com", text: $newDomain)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .onSubmit { addDomain() }
                Button("Block") { addDomain() }
                    .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)

            if !statusMsg.isEmpty {
                Text(statusMsg)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 6)
            }

            Divider()

            // List header
            HStack {
                Text("\(blocked.count) blocked domain\(blocked.count == 1 ? "" : "s")")
                    .font(.caption).foregroundColor(.secondary)
                Spacer()
                Button("Refresh") { load() }
                    .font(.caption)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)

            if blocked.isEmpty {
                Spacer()
                HStack {
                    Spacer()
                    Text("No domains blocked yet.")
                        .font(.callout).foregroundColor(.secondary)
                    Spacer()
                }
                Spacer()
            } else {
                List {
                    ForEach(blocked, id: \.self) { domain in
                        HStack {
                            Text(domain).font(.body.monospaced())
                            Spacer()
                            Button("Unblock") {
                                let ok = HostsManager.unblock(domain)
                                statusMsg = ok ? "Unblocked \(domain)." : "Failed to unblock \(domain) — check admin permissions."
                                load()
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.red)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .onAppear { load() }
    }

    private func addDomain() {
        let domain = newDomain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty else { return }
        guard !blocked.contains(domain) else {
            statusMsg = "\(domain) is already blocked."
            return
        }
        let ok = HostsManager.block(domain)
        statusMsg = ok ? "Blocked \(domain)." : "Failed to block \(domain) — check admin permissions."
        if ok { newDomain = "" }
        load()
    }

    private func load() {
        blocked = HostsManager.blockedDomains()
    }
}
