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
    case providers, appearance, blockList = "Block List"
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
                Text(provider.displayName).font(.headline)
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
        }
    }

    private func setEnabled(_ val: Bool, for p: KeychainHelper.Provider) {
        switch p {
        case .virusTotal: settings.virusTotalEnabled = val
        case .otx:        settings.otxEnabled        = val
        case .shodan:     settings.shodanEnabled     = val
        case .urlScan:    settings.urlScanEnabled    = val
        case .ipInfo:     settings.ipInfoEnabled     = val
        }
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
                    NotificationCenter.default.post(name: Notification.Name("com.nyctimene.reapplyBackground"), object: nil)
                }
            }

            Section("Window") {
                Toggle("Frosted glass (transparent) background", isOn: $settings.transparencyEnabled)
                    .onChange(of: settings.transparencyEnabled) { _ in
                        onSave()
                        NotificationCenter.default.post(name: Notification.Name("com.nyctimene.reapplyBackground"), object: nil)
                    }
                Text("When enabled, the lookup window blends with your desktop using macOS vibrancy.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Block List Tab

struct BlockListTab: View {
    @State private var blocked: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("\(blocked.count) blocked domains")
                    .font(.caption).foregroundColor(.secondary)
                Spacer()
                Button("Refresh") { load() }
            }
            .padding([.horizontal, .top])

            if blocked.isEmpty {
                Spacer()
                HStack {
                    Spacer()
                    Text("No domains blocked yet.\nUse the Analyze window to block a domain.")
                        .font(.callout).foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
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
                                HostsManager.unblock(domain)
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

    private func load() {
        blocked = HostsManager.blockedDomains()
    }
}
