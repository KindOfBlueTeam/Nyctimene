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

    func analyze(artifacts: [(artifact: Artifact, process: String?)]) async {
        rows        = artifacts.map { ScanResultRow(artifact: $0.artifact, process: $0.process) }
        isAnalyzing = true
        progress    = (0, rows.count)

        let settings  = SettingsStore.shared.settings
        let snapshots = rows

        await withTaskGroup(of: RowResult.self) { group in
            for row in snapshots {
                let id       = row.id
                let artifact = row.artifact
                group.addTask {
                    let vt     = settings.virusTotalEnabled ? (try? await VTClient.shared.lookup(artifact))     : nil
                    let otx    = settings.otxEnabled        ? (try? await OTXClient.shared.lookup(artifact))    : nil
                    let shodan = settings.shodanEnabled     ? (try? await ShodanClient.shared.lookup(artifact)) : nil
                    let us     = settings.urlScanEnabled    ? (try? await URLScanClient.shared.lookup(artifact)) : nil
                    let ipInfo = (settings.ipInfoEnabled && artifact.type == .ip)
                                    ? (try? await IPInfoClient.shared.lookup(artifact)) : nil
                    var mb: MalwareBazaarResult? = nil
                    var tf: ThreatFoxResult?     = nil
                    var uh: URLhausResult?        = nil
                    if settings.abuseChEnabled {
                        if artifact.type.isHash && artifact.type != .sha512 {
                            mb = try? await MalwareBazaarClient.shared.lookup(artifact)
                        }
                        tf = try? await ThreatFoxClient.shared.lookup(artifact)
                        if artifact.type != .sha1 && artifact.type != .sha512 {
                            uh = try? await URLhausClient.shared.lookup(artifact)
                        }
                    }
                    return RowResult(id: id, vt: vt, otx: otx, shodan: shodan,
                                     urlScan: us, ipInfo: ipInfo, mb: mb, tf: tf, uh: uh)
                }
            }

            for await result in group {
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
                    progress.done += 1
                }
            }
        }

        isAnalyzing = false
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
            if showProcess { colLabel("Process", width: 100) }
            colLabel("Risk",         width: 80)
            colLabel("VirusTotal",   width: 88)
            colLabel("OTX",          width: 64)
            colLabel("Shodan",       width: 72)
            colLabel("URLScan",      width: 72)
            colLabel("MalBazaar",    width: 76)
            colLabel("ThreatFox",    width: 76)
            colLabel("URLhaus",      width: 68)
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
            // Artifact — linked to the highest-risk provider's report when available
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
            .frame(maxWidth: .infinity, alignment: .leading)

            // Process (optional)
            if showProcess {
                Text(row.process ?? "")
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .foregroundColor(.secondary)
                    .frame(width: 110, alignment: .leading)
            }

            // Risk badge
            riskBadge(row.overallRisk)
                .frame(width: 80, alignment: .leading)

            // VirusTotal
            providerCell(
                main:    row.vtResult.map { "\($0.score) / \($0.total)" },
                url:     row.vtResult?.reportURL,
                risk:    row.vtResult?.riskLevel,
                pending: !row.isAnalyzed && row.vtResult == nil,
                width:   88
            )

            // OTX
            providerCell(
                main:    row.otxResult.map { "\($0.pulseCount) pulse\($0.pulseCount == 1 ? "" : "s")" },
                url:     row.otxResult?.reportURL,
                risk:    row.otxResult?.riskLevel,
                pending: !row.isAnalyzed && row.otxResult == nil,
                width:   64
            )

            // Shodan — exposure context, purple
            providerCell(
                main:    row.shodanResult.map { $0.ports.isEmpty ? "no ports" : "\($0.ports.count) port\($0.ports.count == 1 ? "" : "s")" },
                url:     row.shodanResult?.reportURL,
                risk:    row.shodanResult?.riskLevel,
                color:   .purple,
                pending: !row.isAnalyzed && row.shodanResult == nil,
                width:   72
            )

            // URLScan
            providerCell(
                main:    row.urlScanResult.map { "\($0.scanCount) scan\($0.scanCount == 1 ? "" : "s")" },
                url:     row.urlScanResult?.reportURL,
                risk:    row.urlScanResult?.riskLevel,
                pending: !row.isAnalyzed && row.urlScanResult == nil,
                width:   72
            )

            // MalwareBazaar
            providerCell(
                main:    row.malwareBazaarResult.map { $0.found ? ($0.malwareFamily ?? "found") : "clean" },
                url:     row.malwareBazaarResult?.reportURL,
                risk:    row.malwareBazaarResult?.riskLevel,
                pending: !row.isAnalyzed && row.malwareBazaarResult == nil && row.artifact.type.isHash && row.artifact.type != .sha512,
                width:   76
            )

            // ThreatFox
            providerCell(
                main:    row.threatFoxResult.map { $0.found ? "\($0.confidenceLevel)% \($0.threatType ?? "")" : "clean" },
                url:     row.threatFoxResult?.reportURL,
                risk:    row.threatFoxResult?.riskLevel,
                pending: !row.isAnalyzed && row.threatFoxResult == nil,
                width:   76
            )

            // URLhaus
            providerCell(
                main:    row.urlhausResult.map { $0.found ? ($0.urlStatus ?? "found") + ($0.urlCount > 0 ? " (\($0.urlCount))" : "") : "clean" },
                url:     row.urlhausResult?.reportURL,
                risk:    row.urlhausResult?.riskLevel,
                pending: !row.isAnalyzed && row.urlhausResult == nil && row.artifact.type != .sha1 && row.artifact.type != .sha512,
                width:   68
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
