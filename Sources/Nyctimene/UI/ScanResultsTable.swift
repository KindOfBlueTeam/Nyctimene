import SwiftUI
import NyctimeneCore

// MARK: - Shared bulk-analysis engine

/// Runs multi-provider lookups for a list of artifacts, publishing results as they arrive.
@MainActor
final class BulkAnalysisModel: ObservableObject {
    @Published var rows:        [ScanResultRow] = []
    @Published var isAnalyzing: Bool            = false
    @Published var progress: (done: Int, total: Int) = (0, 0)

    var flaggedCount: Int { rows.filter { $0.overallRisk >= .suspicious }.count }

    /// Populate rows without running any analysis.
    func populate(artifacts: [(artifact: Artifact, process: String?)]) {
        rows = artifacts.map { ScanResultRow(artifact: $0.artifact, process: $0.process) }
    }

    /// Analyze all un-analyzed rows.
    func analyzeAll() async {
        let toAnalyze = rows.filter { !$0.isAnalyzed }
        guard !toAnalyze.isEmpty else { return }

        isAnalyzing = true
        progress    = (0, toAnalyze.count)

        // Mark rows as querying
        for row in toAnalyze {
            if let idx = rows.firstIndex(where: { $0.id == row.id }) {
                rows[idx].isQuerying = true
            }
        }

        await withTaskGroup(of: RowResult.self) { group in
            for row in toAnalyze {
                group.addTask { await Self.queryRow(row) }
            }
            for await result in group {
                applyResult(result)
            }
        }

        isAnalyzing = false
    }

    /// Analyze a single row by ID.
    func analyzeSingle(id: UUID) async {
        guard let row = rows.first(where: { $0.id == id }), !row.isAnalyzed else { return }

        if let idx = rows.firstIndex(where: { $0.id == id }) {
            rows[idx].isQuerying = true
        }

        isAnalyzing = true
        progress = (0, 1)

        let result = await Self.queryRow(row)
        applyResult(result)

        isAnalyzing = false
    }

    /// Legacy entry point used by PCAP tab — populates + analyzes in one call.
    func analyze(artifacts: [(artifact: Artifact, process: String?)]) async {
        populate(artifacts: artifacts)
        await analyzeAll()
    }

    // MARK: - Private

    private func applyResult(_ result: RowResult) {
        if let idx = rows.firstIndex(where: { $0.id == result.id }) {
            rows[idx].vtResult            = result.vt
            rows[idx].otxResult           = result.otx
            rows[idx].shodanResult        = result.shodan
            rows[idx].urlScanResult       = result.urlScan
            rows[idx].ipInfoResult        = result.ipInfo
            rows[idx].malwareBazaarResult = result.mb
            rows[idx].threatFoxResult     = result.tf
            rows[idx].urlhausResult       = result.uh
            rows[idx].isAnalyzed          = true
            rows[idx].isQuerying          = false
            progress.done += 1
        }
    }

    private static func queryRow(_ row: ScanResultRow) async -> RowResult {
        let settings = SettingsStore.shared.settings
        let artifact = row.artifact
        let vt     = settings.virusTotalEnabled ? (try? await VTClient.shared.lookup(artifact))     : nil
        let otx    = settings.otxEnabled        ? (try? await OTXClient.shared.lookup(artifact))    : nil
        let shodan = settings.shodanEnabled     ? (try? await ShodanClient.shared.lookup(artifact)) : nil
        let us     = settings.urlScanEnabled    ? (try? await URLScanClient.shared.lookup(artifact)) : nil
        let ipInfo = (settings.ipInfoEnabled && artifact.type == .ip)
                        ? (try? await IPInfoClient.shared.lookup(artifact)) : nil
        var mb: MalwareBazaarResult? = nil
        var tf: ThreatFoxResult?     = nil
        var uh: URLhausResult?       = nil
        if settings.abuseChEnabled {
            if artifact.type.isHash && artifact.type != .sha512 {
                mb = try? await MalwareBazaarClient.shared.lookup(artifact)
            }
            tf = try? await ThreatFoxClient.shared.lookup(artifact)
            if artifact.type != .sha1 && artifact.type != .sha512 {
                uh = try? await URLhausClient.shared.lookup(artifact)
            }
        }
        return RowResult(id: row.id, vt: vt, otx: otx, shodan: shodan,
                         urlScan: us, ipInfo: ipInfo, mb: mb, tf: tf, uh: uh)
    }

    private struct RowResult {
        let id: UUID
        let vt:      VTProviderResult?
        let otx:     OTXProviderResult?
        let shodan:  ShodanProviderResult?
        let urlScan: URLScanProviderResult?
        let ipInfo:  IPInfoProviderResult?
        let mb:      MalwareBazaarResult?
        let tf:      ThreatFoxResult?
        let uh:      URLhausResult?
    }
}

// MARK: - Results table

struct ScanResultsTable: View {
    let rows:        [ScanResultRow]
    let showProcess: Bool
    var riskyOnly:   Bool = false
    var onQueryRow:  ((UUID) -> Void)? = nil

    private var displayed: [ScanResultRow] {
        let filtered = riskyOnly ? rows.filter { $0.overallRisk >= .suspicious } : rows
        return filtered.sorted { $0.overallRisk > $1.overallRisk }
    }

    var body: some View {
        VStack(spacing: 0) {
            headerRow
            Divider()
            if displayed.isEmpty {
                Spacer()
                Text(riskyOnly ? "No suspicious or malicious artifacts found." : "No results yet.")
                    .foregroundColor(.secondary)
                    .font(.callout)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(displayed) { row in
                            dataRow(row)
                            Divider().opacity(0.5)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(spacing: 0) {
            colLabel("Artifact",     flex: true)
            if showProcess { colLabel("Process", width: 80) }
            colLabel("Risk",         width: 72)
            colLabel("VT",           width: 56)
            colLabel("OTX",          width: 50)
            colLabel("Shodan",       width: 56)
            colLabel("Scan",         width: 50)
            colLabel("MB",           width: 50)
            colLabel("TFox",         width: 50)
            colLabel("UHaus",        width: 50)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 5)
        .background(Color(NSColor.controlBackgroundColor))
        .font(.caption2.weight(.semibold))
        .foregroundColor(.secondary)
    }

    private func colLabel(_ title: String, flex: Bool = false, width: CGFloat? = nil) -> some View {
        Text(title.uppercased())
            .frame(maxWidth: flex ? .infinity : width, alignment: .leading)
    }

    // MARK: - Data row

    /// Returns the report URL of the highest-risk scored provider for this row.
    private func topReportURL(_ row: ScanResultRow) -> URL? {
        let candidates: [(RiskLevel, String?)] = [
            (row.vtResult?.riskLevel            ?? .unknown, row.vtResult?.reportURL),
            (row.malwareBazaarResult?.riskLevel ?? .unknown, row.malwareBazaarResult?.reportURL),
            (row.threatFoxResult?.riskLevel     ?? .unknown, row.threatFoxResult?.reportURL),
            (row.urlhausResult?.riskLevel       ?? .unknown, row.urlhausResult?.reportURL),
            // Contextual providers as fallback when scored sources are clean
            (row.otxResult?.riskLevel           ?? .unknown, row.otxResult?.reportURL),
            (row.urlScanResult?.riskLevel       ?? .unknown, row.urlScanResult?.reportURL),
            (row.shodanResult?.riskLevel        ?? .unknown, row.shodanResult?.reportURL),
        ]
        guard let urlStr = candidates
            .filter({ $0.0 > .unknown })
            .max(by: { $0.0 < $1.0 })?
            .1
        else { return nil }
        return URL(string: urlStr)
    }

    private func dataRow(_ row: ScanResultRow) -> some View {
        HStack(spacing: 0) {
            // Query pill + Artifact
            HStack(spacing: 6) {
                if let onQuery = onQueryRow, !row.isAnalyzed {
                    Button { onQuery(row.id) } label: {
                        Text("Query")
                            .font(.system(size: 9, weight: .semibold))
                            .padding(.horizontal, 7).padding(.vertical, 2)
                            .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                            .foregroundColor(.accentColor)
                    }
                    .buttonStyle(.plain)
                }

                VStack(alignment: .leading, spacing: 1) {
                    if let dest = topReportURL(row) {
                        Link(destination: dest) {
                            Text(row.artifact.normalized)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } else {
                        Text(row.artifact.normalized)
                        .font(.caption.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                // Type label + optional ownership hint from IPInfo
                HStack(spacing: 4) {
                    Text(row.artifact.type.rawValue.uppercased())
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    if let owner = row.ipInfoResult?.company ?? row.ipInfoResult?.org,
                       !owner.isEmpty {
                        Text("·")
                            .font(.caption2).foregroundColor(.secondary)
                        Text(owner)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
            }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Process (optional)
            if showProcess {
                Text(row.process ?? "")
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .foregroundColor(.secondary)
                    .frame(width: 80, alignment: .leading)
            }

            // Risk badge
            riskBadge(row.overallRisk)
                .frame(width: 72, alignment: .leading)

            // VirusTotal
            providerCell(
                main:    row.vtResult.map { "\($0.score)/\($0.total)" },
                url:     row.vtResult?.reportURL,
                risk:    row.vtResult?.riskLevel,
                pending: row.isQuerying && row.vtResult == nil,
                width:   56
            )

            // OTX
            providerCell(
                main:    row.otxResult.map { "\($0.pulseCount)p" },
                url:     row.otxResult?.reportURL,
                risk:    row.otxResult?.riskLevel,
                pending: row.isQuerying && row.otxResult == nil,
                width:   50
            )

            // Shodan — exposure context, purple
            providerCell(
                main:    row.shodanResult.map { $0.ports.isEmpty ? "—" : "\($0.ports.count)p" },
                url:     row.shodanResult?.reportURL,
                risk:    row.shodanResult?.riskLevel,
                color:   .purple,
                pending: row.isQuerying && row.shodanResult == nil,
                width:   56
            )

            // URLScan
            providerCell(
                main:    row.urlScanResult.map { "\($0.scanCount)s" },
                url:     row.urlScanResult?.reportURL,
                risk:    row.urlScanResult?.riskLevel,
                pending: row.isQuerying && row.urlScanResult == nil,
                width:   50
            )

            // MalwareBazaar
            providerCell(
                main:    row.malwareBazaarResult.map { $0.found ? "hit" : "—" },
                url:     row.malwareBazaarResult?.reportURL,
                risk:    row.malwareBazaarResult?.riskLevel,
                pending: row.isQuerying && row.malwareBazaarResult == nil && row.artifact.type.isHash && row.artifact.type != .sha512,
                width:   50
            )

            // ThreatFox
            providerCell(
                main:    row.threatFoxResult.map { $0.found ? "\($0.confidenceLevel)%" : "—" },
                url:     row.threatFoxResult?.reportURL,
                risk:    row.threatFoxResult?.riskLevel,
                pending: row.isQuerying && row.threatFoxResult == nil,
                width:   50
            )

            // URLhaus
            providerCell(
                main:    row.urlhausResult.map { $0.found ? ($0.urlStatus ?? "hit") : "—" },
                url:     row.urlhausResult?.reportURL,
                risk:    row.urlhausResult?.riskLevel,
                pending: row.isQuerying && row.urlhausResult == nil && row.artifact.type != .sha1 && row.artifact.type != .sha512,
                width:   50
            )
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(row.overallRisk >= .suspicious
            ? riskColor(row.overallRisk).opacity(0.05)
            : Color.clear)
    }

    // MARK: - Helpers

    private func providerCell(
        main:    String?,
        url:     String?,
        risk:    RiskLevel?,
        color:   Color? = nil,   // overrides riskColor when set (e.g. purple for Shodan)
        pending: Bool,
        width:   CGFloat
    ) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            if pending {
                ProgressView().scaleEffect(0.55).frame(height: 12)
            } else if let main {
                Text(main)
                    .font(.caption.monospaced())
                    .foregroundColor(color ?? risk.map(riskColor) ?? .secondary)
                    .lineLimit(1)
                if let url, let dest = URL(string: url) {
                    Link("report →", destination: dest)
                        .font(.caption2)
                }
            } else {
                Text("—").font(.caption).foregroundColor(.secondary)
            }
        }
        .frame(width: width, alignment: .leading)
    }

    private func riskBadge(_ level: RiskLevel) -> some View {
        Text(level.label.uppercased())
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(riskColor(level).opacity(0.2)))
            .foregroundColor(riskColor(level))
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .unknown:    return .secondary
        case .clean:      return .green
        case .suspicious: return .orange
        case .malicious:  return .red
        }
    }
}
