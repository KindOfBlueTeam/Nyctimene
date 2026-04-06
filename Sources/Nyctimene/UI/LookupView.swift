import SwiftUI
import NyctimeneCore

struct LookupView: View {
    @State private var input         = ""
    @State private var isRunning     = false
    @State private var result: LookupResult?
    @State private var errorMsg: String?
    @State private var blockedDomains: Set<String> = []
    @State private var analysisTask: Task<Void, Never>?
    @State private var selectedSources: Set<String> = Set(Self.sourceOrder)

    // Investigation context
    @State private var caseName:  String = ""
    @State private var actorName: String = ""
    @State private var notes:     String = ""

    var body: some View {
        VStack(spacing: 0) {
            caseActorBar
            Divider()
            searchBar
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
            Divider()

            if let result {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        resultsView(result)
                            .padding(20)
                        notesSection
                            .padding(.horizontal, 20)
                            .padding(.bottom, 20)
                    }
                }
            } else if let errorMsg {
                Spacer()
                Text(errorMsg)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding()
                Spacer()
            } else {
                Spacer()
                emptyState
                Spacer()
            }
        }
        .onAppear { refreshBlockedList() }
    }

    // MARK: - Case / Actor bar

    private var caseActorBar: some View {
        HStack(spacing: 16) {
            HStack(spacing: 6) {
                Text("CASE")
                    .font(.caption.bold())
                    .foregroundColor(.secondary)
                    .frame(width: 40, alignment: .trailing)
                TextField("Case name", text: $caseName)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
            }
            HStack(spacing: 6) {
                Text("ACTOR")
                    .font(.caption.bold())
                    .foregroundColor(.secondary)
                    .frame(width: 44, alignment: .trailing)
                TextField("Threat actor", text: $actorName)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }

    // MARK: - Search bar

    private var searchBar: some View {
        HStack(spacing: 10) {
            TextField("Domain, IP, URL, or hash — e.g. evil.com, 1.2.3.4, https://evil.com/path, d41d8cd…", text: $input)
                .textFieldStyle(.roundedBorder)
                .onSubmit { if !isRunning { analyze() } }
                .disabled(isRunning)

            if isRunning {
                ProgressView().scaleEffect(0.7)
                Button("Stop") { stop() }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .keyboardShortcut(.escape, modifiers: [])
            } else {
                Button("Analyze") { analyze() }
                    .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
                    .keyboardShortcut(.return, modifiers: [])
            }
        }
    }

    // MARK: - Notes section

    private var notesSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("NOTES")
                .font(.caption.bold())
                .foregroundColor(.secondary)
            TextEditor(text: $notes)
                .font(.body)
                .frame(minHeight: 80, maxHeight: 160)
                .scrollContentBackground(.hidden)
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(NSColor.controlBackgroundColor))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(NSColor.separatorColor), lineWidth: 0.5)
                )
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "magnifyingglass.circle")
                .font(.system(size: 48))
                .foregroundColor(.secondary.opacity(0.4))
            Text("Enter a domain, IP address, or URL above to check it\nagainst VirusTotal, OTX AlienVault, Shodan, and URLScan.io")
                .font(.callout)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    // MARK: - Results

    private func resultsView(_ r: LookupResult, forScreenshot: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 16) {

            // ── LEFT: artifact header + provider cards ───────────────────
            VStack(alignment: .leading, spacing: 16) {
                // Artifact header
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .center) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.artifact.normalized)
                                .font(.title3.monospaced().bold())
                            Text(r.artifact.type.rawValue.uppercased())
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 8) {
                            riskBadge(r.overallRisk)
                            if !forScreenshot {
                                blockButton(r)
                                screenshotButton(r)
                            }
                        }
                    }
                    if let info = r.domainInfo   { domainInfoSection(info) }
                    if let ip   = r.ipInfoResult { ipInfoSection(ip) }
                }
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))

                // Provider cards — 2-column grid
                let cols = [GridItem(.flexible()), GridItem(.flexible())]
                LazyVGrid(columns: cols, spacing: 12) {
                    if let vt = r.vtResult            { vtCard(vt,  forScreenshot: forScreenshot) }
                    if let otx = r.otxResult          { otxCard(otx, forScreenshot: forScreenshot) }
                    if let sh = r.shodanResult        { shodanCard(sh, forScreenshot: forScreenshot) }
                    if let us = r.urlScanResult       { urlScanCard(us, forScreenshot: forScreenshot) }
                    if let mb = r.malwareBazaarResult { malwareBazaarCard(mb, forScreenshot: forScreenshot) }
                    if let tf = r.threatFoxResult     { threatFoxCard(tf, forScreenshot: forScreenshot) }
                    if let uh = r.urlhausResult       { urlhausCard(uh, forScreenshot: forScreenshot) }
                }
            }
            .frame(maxWidth: .infinity)

            // ── RIGHT: Risk Radar panel ───────────────────────────────────
            VStack(spacing: 12) {
                Text("RISK RADAR")
                    .font(.caption.bold())
                    .foregroundColor(.secondary)
                    .tracking(1)

                let allAxes  = radarAxes(for: r)
                // level > 1 means the source was actually queried and returned data;
                // N/A sources are excluded from the chart even if their checkbox is on
                let shown    = allAxes.filter { selectedSources.contains($0.label) && $0.level > 1 }
                let score    = radarScore(for: r)
                let risk     = r.overallRisk

                Group {
                    switch shown.count {
                    case 0:
                        VStack(spacing: 8) {
                            Image(systemName: "chart.xyaxis.line")
                                .font(.system(size: 36))
                                .foregroundColor(.secondary.opacity(0.3))
                            Text("Select at least one source")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    case 1:
                        SingleSourceRiskView(axis: shown[0])
                    case 2:
                        XYRiskView(axes: shown, score: score, riskLevel: risk)
                    default:
                        RadarChartView(axes: shown, score: score, riskLevel: risk)
                    }
                }
                .frame(width: 280, height: 280)

                // Source toggles
                Divider()
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(Self.sourceOrder, id: \.self) { key in
                        if let axis = allAxes.first(where: { $0.label == key }) {
                            let hasData = axis.level > 1
                            Toggle(isOn: sourceBinding(key)) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(levelDotColor(axis.level))
                                        .frame(width: 7, height: 7)
                                    Text(Self.sourceNames[key] ?? key)
                                        .font(.caption)
                                        .foregroundColor(hasData ? .primary : .secondary)
                                }
                            }
                            .toggleStyle(.checkbox)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                // Legend
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    ForEach([
                        (Color.secondary.opacity(0.5), "Not queried / N/A"),
                        (Color.green,  "Clean — no signal"),
                        (Color.yellow, "Low signal"),
                        (Color.orange, "Likely malicious"),
                        (Color.red,    "Confirmed malicious"),
                    ], id: \.1) { color, label in
                        HStack(spacing: 6) {
                            Circle().fill(color).frame(width: 7, height: 7)
                            Text(label).font(.caption2).foregroundColor(.secondary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(16)
            .frame(width: 340)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
        }
    }

    // MARK: - Source selection helpers

    static let sourceOrder = ["VT", "OTX", "Scan", "MB", "TFox", "UHaus"]
    static let sourceNames: [String: String] = [
        "VT":    "VirusTotal",
        "OTX":   "OTX AlienVault",
        "Scan":  "URLScan.io",
        "MB":    "MalwareBazaar",
        "TFox":  "ThreatFox",
        "UHaus": "URLhaus",
    ]

    private func sourceBinding(_ key: String) -> Binding<Bool> {
        Binding(
            get: { selectedSources.contains(key) },
            set: { if $0 { selectedSources.insert(key) } else { selectedSources.remove(key) } }
        )
    }

    private func levelDotColor(_ level: Int) -> Color {
        switch level {
        case 2:  return .green
        case 3:  return .yellow
        case 4:  return .orange
        case 5:  return .red
        default: return .secondary.opacity(0.4)
        }
    }

    // MARK: - Domain info section

    @ViewBuilder
    private func domainInfoSection(_ info: DomainInfo) -> some View {
        Divider()
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 16) {
                if let reg = info.registered {
                    Label("Registered: \(reg, formatter: mediumDateFormatter)", systemImage: "calendar")
                        .font(.caption).foregroundColor(.secondary)
                }
                if let exp = info.expires {
                    Label("Expires: \(exp, formatter: mediumDateFormatter)", systemImage: "calendar.badge.clock")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
            if let registrar = info.registrar {
                Label(registrar, systemImage: "building.2")
                    .font(.caption).foregroundColor(.secondary)
            }
            if !info.status.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(info.status, id: \.self) { s in
                            Text(s)
                                .font(.caption2)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
    }

    // MARK: - IPInfo section

    @ViewBuilder
    private func ipInfoSection(_ info: IPInfoProviderResult) -> some View {
        Divider()
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 16) {
                if let company = info.company {
                    Label(company, systemImage: "building.2")
                        .font(.caption).foregroundColor(.secondary)
                }
                if let asn = info.asn {
                    Label(asn, systemImage: "number")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
            HStack(spacing: 16) {
                if !info.country.isEmpty {
                    Label(info.country, systemImage: "flag")
                        .font(.caption).foregroundColor(.secondary)
                }
                if !info.city.isEmpty {
                    Label(info.city, systemImage: "mappin")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
        }
    }

    private var mediumDateFormatter: DateFormatter {
        let f = DateFormatter(); f.dateStyle = .medium; f.timeStyle = .none; return f
    }

    // MARK: - Provider cards

    private func vtCard(_ r: VTProviderResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "VirusTotal", icon: "shield.lefthalf.filled",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Detections", "\(r.score) / \(r.total) engines")
            if let name = r.fileName { statRow("File name", name) }
            if let type = r.fileType { statRow("File type", type) }
            if let size = r.fileSize {
                statRow("File size", ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
            }
        }
    }

    private func otxCard(_ r: OTXProviderResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "OTX AlienVault", icon: "antenna.radiowaves.left.and.right",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Threat Pulses", "\(r.pulseCount)")
        }
    }

    private func shodanCard(_ r: ShodanProviderResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "Shodan", icon: "network",
                     risk: r.riskLevel, reportURL: r.reportURL,
                     accentColor: .purple, forScreenshot: forScreenshot) {
            if !r.org.isEmpty     { statRow("Org",     r.org) }
            if !r.country.isEmpty { statRow("Country", r.country) }
            if !r.ports.isEmpty   { statRow("Ports",   r.ports.map(String.init).joined(separator: ", ")) }
            if !r.vulns.isEmpty   { statRow("CVEs",    r.vulns.joined(separator: ", ")) }
        }
    }

    private func urlScanCard(_ r: URLScanProviderResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "URLScan.io", icon: "doc.text.magnifyingglass",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Scans found", "\(r.scanCount)")
            statRow("Malicious",   "\(r.maliciousCount)")
            if let score = r.latestScore { statRow("Latest score", "\(score) / 100") }
            if !r.tags.isEmpty { statRow("Tags", r.tags.joined(separator: ", ")) }
        }
    }

    private func malwareBazaarCard(_ r: MalwareBazaarResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "MalwareBazaar", icon: "staroflife.fill",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Found", r.found ? "Yes" : "No")
            if let family = r.malwareFamily { statRow("Family",    family) }
            if let name   = r.fileName      { statRow("File name", name)   }
            if let type   = r.fileType      { statRow("File type", type)   }
            if let size   = r.fileSize {
                statRow("File size", ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
            }
            if let seen = r.firstSeen       { statRow("First seen", seen)  }
            if !r.tags.isEmpty              { statRow("Tags", r.tags.joined(separator: ", ")) }
        }
    }

    private func threatFoxCard(_ r: ThreatFoxResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "ThreatFox", icon: "ant.fill",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Found", r.found ? "Yes" : "No")
            if let family = r.malwareFamily { statRow("Malware",    family) }
            if let type   = r.threatType    { statRow("Threat type", type)  }
            if r.found { statRow("Confidence", "\(r.confidenceLevel)%") }
            if let seen = r.firstSeen       { statRow("First seen",  seen)  }
            if let last = r.lastSeen        { statRow("Last seen",   last)  }
            if !r.tags.isEmpty              { statRow("Tags", r.tags.joined(separator: ", ")) }
        }
    }

    private func urlhausCard(_ r: URLhausResult, forScreenshot: Bool = false) -> some View {
        providerCard(title: "URLhaus", icon: "link.badge.plus",
                     risk: r.riskLevel, reportURL: r.reportURL, forScreenshot: forScreenshot) {
            statRow("Found", r.found ? "Yes" : "No")
            if let status = r.urlStatus { statRow("Status",    status) }
            if let threat = r.threat    { statRow("Threat",    threat) }
            if r.found && r.urlCount > 0 { statRow("URL count", "\(r.urlCount)") }
            if !r.tags.isEmpty           { statRow("Tags", r.tags.joined(separator: ", ")) }
        }
    }

    private func providerCard(
        title: String, icon: String, risk: RiskLevel, reportURL: String,
        accentColor: Color? = nil,   // overrides riskColor when set (e.g. purple for Shodan)
        forScreenshot: Bool = false,
        @ViewBuilder content: () -> some View
    ) -> some View {
        let color = accentColor ?? riskColor(risk)
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: icon).foregroundColor(color)
                Text(title).font(.headline)
                Spacer()
                riskBadge(risk, color: color)
            }
            Divider()
            content()
            Spacer(minLength: 0)
            // ImageRenderer cannot render Link/Button — use plain text for screenshots
            if forScreenshot {
                Text(reportURL)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            } else {
                Link("View full report →", destination: URL(string: reportURL)!)
                    .font(.caption)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
    }

    private func statRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(label + ":")
                .font(.caption).foregroundColor(.secondary)
                .frame(width: 90, alignment: .leading)
            Text(value)
                .font(.caption.monospaced())
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Screenshot

    private func screenshotButton(_ r: LookupResult) -> some View {
        Button { saveScreenshot(r) } label: { Image(systemName: "camera") }
            .buttonStyle(.borderless)
            .help("Save screenshot of results")
    }

    private func saveScreenshot(_ r: LookupResult) {
        let snapCase  = caseName.trimmingCharacters(in: .whitespaces)
        let snapActor = actorName.trimmingCharacters(in: .whitespaces)
        let snapNotes = notes.trimmingCharacters(in: .whitespaces)

        let content = screenshotView(r, caseName: snapCase, actorName: snapActor, notes: snapNotes)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 2.0
        guard let image = renderer.nsImage else { return }

        let panel = NSSavePanel()
        panel.nameFieldStringValue = defangedFilename(r.artifact)
        panel.allowedContentTypes  = [.png]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }

        if let tiff   = image.tiffRepresentation,
           let bitmap = NSBitmapImageRep(data: tiff),
           let png    = bitmap.representation(using: .png, properties: [:]) {
            try? png.write(to: url)
        }
    }

    private func screenshotView(
        _ r: LookupResult,
        caseName: String, actorName: String, notes: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Investigation header
            if !caseName.isEmpty || !actorName.isEmpty {
                HStack(spacing: 24) {
                    if !caseName.isEmpty {
                        HStack(spacing: 4) {
                            Text("CASE:").font(.caption.bold()).foregroundColor(.secondary)
                            Text(caseName).font(.caption.bold())
                        }
                    }
                    if !actorName.isEmpty {
                        HStack(spacing: 4) {
                            Text("ACTOR:").font(.caption.bold()).foregroundColor(.secondary)
                            Text(actorName).font(.caption.bold())
                        }
                    }
                }
                .padding(.horizontal, 20)
            }

            resultsView(r, forScreenshot: true)

            // Notes
            if !notes.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("NOTES").font(.caption.bold()).foregroundColor(.secondary)
                    Text(notes)
                        .font(.body)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(Color(NSColor.controlBackgroundColor))
                        )
                }
                .padding(.horizontal, 20)
            }
        }
        .frame(width: 820)
        .padding(.vertical, 20)
        .background(Color(NSColor.windowBackgroundColor))
    }

    private func defangedFilename(_ artifact: Artifact) -> String {
        let date = String(ISO8601DateFormatter().string(from: Date()).prefix(10))

        var parts: [String] = []
        let trimmedCase  = caseName.trimmingCharacters(in: .whitespaces)
        let trimmedActor = actorName.trimmingCharacters(in: .whitespaces)
        if !trimmedCase.isEmpty  { parts.append(trimmedCase.replacingOccurrences(of: " ", with: "_")) }
        if !trimmedActor.isEmpty { parts.append(trimmedActor.replacingOccurrences(of: " ", with: "_")) }

        let defanged: String
        switch artifact.type {
        case .domain, .ip:
            defanged = artifact.normalized.replacingOccurrences(of: ".", with: "[.]")
        case .md5, .sha1, .sha256, .sha512:
            defanged = artifact.normalized  // hashes contain no special chars
        case .url:
            var s = artifact.normalized
            if s.hasPrefix("https://") { s = "hxxps[://]" + s.dropFirst("https://".count) }
            else if s.hasPrefix("http://") { s = "hxxp[://]" + s.dropFirst("http://".count) }
            else { s = s.replacingOccurrences(of: "://", with: "[://]") }
            defanged = s.replacingOccurrences(of: ".", with: "[.]")
        }
        parts.append(defanged)
        parts.append(date)

        return parts.joined(separator: "_")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .replacingOccurrences(of: "?", with: "_")
            .replacingOccurrences(of: "&", with: "_")
            + ".png"
    }

    // MARK: - Block button

    private func blockButton(_ r: LookupResult) -> some View {
        let domain = blockableDomain(r)
        guard let domain else { return AnyView(EmptyView()) }
        let blocked = blockedDomains.contains(domain)
        return AnyView(
            Button(blocked ? "Unblock" : "Block in /etc/hosts") {
                if blocked { HostsManager.unblock(domain) } else { HostsManager.block(domain) }
                refreshBlockedList()
            }
            .buttonStyle(.borderedProminent)
            .tint(blocked ? .secondary : .red)
        )
    }

    private func blockableDomain(_ r: LookupResult) -> String? {
        switch r.artifact.type {
        case .domain:                       return r.artifact.normalized
        case .ip, .md5, .sha1, .sha256, .sha512: return nil
        case .url:                          return URL(string: r.artifact.normalized)?.host
        }
    }

    // MARK: - Risk helpers

    private func riskBadge(_ level: RiskLevel, color: Color? = nil) -> some View {
        let c = color ?? riskColor(level)
        return Text(level.label.uppercased())
            .font(.caption2.bold())
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(Capsule().fill(c.opacity(0.2)))
            .foregroundColor(c)
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .unknown:    return .secondary
        case .clean:      return .green
        case .suspicious: return .orange
        case .malicious:  return .red
        }
    }

    // MARK: - Analyze / Stop

    private func stop() {
        analysisTask?.cancel()
        analysisTask = nil
        isRunning    = false
    }

    private func analyze() {
        let raw = input.trimmingCharacters(in: .whitespaces)
        guard !raw.isEmpty else { return }

        analysisTask?.cancel()
        isRunning = true
        result    = nil
        errorMsg  = nil

        let artifact = ArtifactResolver.resolve(raw)
        let settings = SettingsStore.shared.settings

        analysisTask = Task {
            var r = LookupResult(artifact: artifact)
            var errors: [String] = []

            await withTaskGroup(of: Void.self) { group in
                if settings.virusTotalEnabled {
                    group.addTask {
                        do    { r.vtResult = try await VTClient.shared.lookup(artifact) }
                        catch { errors.append("VT: \(error.localizedDescription)") }
                    }
                }
                if settings.otxEnabled {
                    group.addTask {
                        do    { r.otxResult = try await OTXClient.shared.lookup(artifact) }
                        catch { errors.append("OTX: \(error.localizedDescription)") }
                    }
                }
                if settings.shodanEnabled && !artifact.type.isHash {
                    group.addTask {
                        do    { r.shodanResult = try await ShodanClient.shared.lookup(artifact) }
                        catch { errors.append("Shodan: \(error.localizedDescription)") }
                    }
                }
                if settings.urlScanEnabled && !artifact.type.isHash {
                    group.addTask {
                        do    { r.urlScanResult = try await URLScanClient.shared.lookup(artifact) }
                        catch { errors.append("URLScan: \(error.localizedDescription)") }
                    }
                }
                if artifact.type == .domain {
                    group.addTask {
                        r.domainInfo = try? await RDAPClient.shared.lookup(artifact)
                    }
                }
                if settings.ipInfoEnabled && artifact.type == .ip {
                    group.addTask {
                        r.ipInfoResult = try? await IPInfoClient.shared.lookup(artifact)
                    }
                }
                if settings.abuseChEnabled {
                    if artifact.type.isHash && artifact.type != .sha512 {
                        group.addTask {
                            do    { r.malwareBazaarResult = try await MalwareBazaarClient.shared.lookup(artifact) }
                            catch { errors.append("MalwareBazaar: \(error.localizedDescription)") }
                        }
                    }
                    group.addTask {
                        do    { r.threatFoxResult = try await ThreatFoxClient.shared.lookup(artifact) }
                        catch { errors.append("ThreatFox: \(error.localizedDescription)") }
                    }
                    if artifact.type != .sha1 && artifact.type != .sha512 {
                        group.addTask {
                            do    { r.urlhausResult = try await URLhausClient.shared.lookup(artifact) }
                            catch { errors.append("URLhaus: \(error.localizedDescription)") }
                        }
                    }
                }
            }

            // Don't publish results if the user cancelled
            guard !Task.isCancelled else { return }

            await MainActor.run {
                if r.vtResult == nil && r.otxResult == nil && r.shodanResult == nil && r.urlScanResult == nil {
                    errorMsg = errors.joined(separator: "\n")
                } else {
                    self.result = r
                }
                isRunning    = false
                analysisTask = nil
            }
        }
    }

    private func refreshBlockedList() {
        blockedDomains = Set(HostsManager.blockedDomains())
    }

    // MARK: - Radar chart

    /// Builds the six radar axes from a completed LookupResult.
    private func radarAxes(for r: LookupResult) -> [RadarAxis] {
        let vt  = r.vtResult
        let otx = r.otxResult
        let us  = r.urlScanResult
        let mb  = r.malwareBazaarResult
        let tf  = r.threatFoxResult
        let uh  = r.urlhausResult
        return [
            RadarAxis(label: "VT",    level: vtLevel(vt),
                      rawDetail: vt.map { "\($0.score) / \($0.total) engines" }),
            RadarAxis(label: "OTX",   level: otxLevel(otx),
                      rawDetail: otx.map { "\($0.pulseCount) pulse\($0.pulseCount == 1 ? "" : "s")" }),
            RadarAxis(label: "Scan",  level: urlScanLevel(us),
                      rawDetail: us.map { "\($0.maliciousCount) malicious / \($0.scanCount) scans" }),
            RadarAxis(label: "MB",    level: mbLevel(mb),
                      rawDetail: mb.map { $0.found ? ($0.malwareFamily ?? "Found") : "Not found" }),
            RadarAxis(label: "TFox",  level: tfLevel(tf),
                      rawDetail: tf.map { $0.found ? "\($0.malwareFamily ?? $0.threatType ?? "Found") (\($0.confidenceLevel)%)" : "Not found" }),
            RadarAxis(label: "UHaus", level: uhLevel(uh),
                      rawDetail: uh.map { r in r.found ? (r.urlStatus ?? "Found") + (r.urlCount > 0 ? " · \(r.urlCount) URLs" : "") : "Not found" }),
        ]
    }

    /// Composite 1–100 score derived from the four scored sources only.
    /// Formula: normalized average × (applicable / total scored) × 99 + 1
    /// More sources confirming → higher ceiling. All clean → 1. All confirmed → 100.
    private func radarScore(for r: LookupResult) -> Int {
        let levels = [
            vtLevel(r.vtResult),
            mbLevel(r.malwareBazaarResult),
            tfLevel(r.threatFoxResult),
            uhLevel(r.urlhausResult),
        ]
        let applicable = levels.filter { $0 > 1 }   // exclude N/A
        guard !applicable.isEmpty else { return 1 }

        let N         = applicable.count
        let N_total   = 4                            // VT + MB + TF + UH
        let sum       = applicable.reduce(0, +)
        // Map: all at level 2 (clean) → 0.0 ; all at level 5 (confirmed) → 1.0
        let normalized  = Double(sum - 2 * N) / Double(3 * N)
        // Multiplier: more applicable sources = higher confidence ceiling
        let multiplier  = Double(N) / Double(N_total)
        return max(1, min(100, Int(normalized * multiplier * 99) + 1))
    }

    // MARK: - Level mappings (provider result → 1–5 scale)

    private func vtLevel(_ r: VTProviderResult?) -> Int {
        guard let r else { return 1 }
        if r.score == 0               { return 2 }
        if r.riskLevel == .suspicious { return 3 }
        return r.score >= 10 ? 5 : 4
    }

    private func mbLevel(_ r: MalwareBazaarResult?) -> Int {
        guard let r else { return 1 }
        return r.found ? 5 : 1          // not found = N/A, not clean
    }

    private func tfLevel(_ r: ThreatFoxResult?) -> Int {
        guard let r else { return 1 }
        if !r.found                    { return 1 }  // not found = N/A
        if r.confidenceLevel >= 75     { return 5 }
        if r.confidenceLevel >= 50     { return 4 }
        return 3
    }

    private func uhLevel(_ r: URLhausResult?) -> Int {
        guard let r else { return 1 }
        if !r.found                    { return 1 }  // not found = N/A
        if r.urlStatus == "online"     { return 5 }
        return r.urlCount > 3 ? 4 : 3
    }

    private func otxLevel(_ r: OTXProviderResult?) -> Int {
        guard let r else { return 1 }
        if r.pulseCount == 0           { return 1 }  // 0 pulses = N/A
        if r.pulseCount <= 2           { return 3 }
        if r.pulseCount <= 9           { return 4 }
        return 5
    }

    private func urlScanLevel(_ r: URLScanProviderResult?) -> Int {
        guard let r else { return 1 }
        if r.maliciousCount > 0                        { return 5 }
        if let s = r.latestScore, s > 50               { return 4 }
        if let s = r.latestScore, s > 20               { return 3 }
        if r.scanCount == 0                            { return 1 }  // 0 scans = N/A
        return 2
    }
}
