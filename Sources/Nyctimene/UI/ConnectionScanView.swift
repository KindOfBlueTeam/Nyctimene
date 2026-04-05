import SwiftUI
import NyctimeneCore

struct ConnectionScanView: View {
    @StateObject private var model    = BulkAnalysisModel()
    @State private var isScanning     = false
    @State private var scanError:      String?
    @State private var riskyOnly       = false
    @State private var connectionCount = 0

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()

            if model.rows.isEmpty && !isScanning {
                emptyState
            } else {
                ScanResultsTable(rows: model.rows, showProcess: true, riskyOnly: riskyOnly)
            }
        }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        HStack(spacing: 12) {
            Button {
                Task { await runScan() }
            } label: {
                Label(isScanning || model.isAnalyzing ? "Scanning…" : "Scan Now",
                      systemImage: "network.badge.shield.half.filled")
            }
            .disabled(isScanning || model.isAnalyzing)

            if model.isAnalyzing {
                ProgressView(value: Double(model.progress.done),
                             total: Double(max(model.progress.total, 1)))
                    .frame(width: 100)
                Text("\(model.progress.done) / \(model.progress.total)")
                    .font(.caption).foregroundColor(.secondary)
            }

            Spacer()

            if !model.rows.isEmpty {
                Text("\(connectionCount) external IPs · \(model.flaggedCount) flagged")
                    .font(.caption).foregroundColor(.secondary)

                Toggle("Risky only", isOn: $riskyOnly)
                    .toggleStyle(.checkbox)
                    .font(.caption)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 44))
                .foregroundColor(.secondary.opacity(0.4))
            Text("Click Scan Now to enumerate active network connections\nand check every external IP against your threat intel providers.")
                .font(.callout)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            if let err = scanError {
                Text(err).foregroundColor(.red).font(.caption)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Scan

    private func runScan() async {
        isScanning = true
        scanError  = nil

        do {
            let entries = try await ConnectionScanner.scan()
            connectionCount = entries.count

            let pairs: [(Artifact, String?)] = entries.map {
                (ArtifactResolver.resolve($0.remoteIP), $0.process)
            }
            isScanning = false
            await model.analyze(artifacts: pairs.map { (artifact: $0.0, process: $0.1) })
        } catch {
            scanError  = error.localizedDescription
            isScanning = false
        }
    }
}
