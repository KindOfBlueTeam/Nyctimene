import SwiftUI
import AppKit
import NyctimeneCore

struct PCAPView: View {
    @StateObject private var model   = BulkAnalysisModel()
    @State private var isCapturing   = false
    @State private var isLoading     = false
    @State private var captureError: String?
    @State private var loadedFile:   URL?
    @State private var riskyOnly     = false
    @State private var artifactCount = 0

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()

            if model.rows.isEmpty && !isLoading {
                emptyState
            } else {
                ScanResultsTable(rows: model.rows, showProcess: false, riskyOnly: riskyOnly)
            }
        }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        HStack(spacing: 10) {
            // Live capture controls
            if isCapturing {
                Button {
                    stopCapture()
                } label: {
                    Label("Stop & Analyze", systemImage: "stop.circle.fill")
                        .foregroundColor(.red)
                }
            } else {
                Button {
                    startCapture()
                } label: {
                    Label("Start Capture", systemImage: "record.circle")
                }
                .disabled(isLoading || model.isAnalyzing)
            }

            if isCapturing {
                ProgressView().scaleEffect(0.75)
                Text("Capturing traffic…")
                    .font(.caption).foregroundColor(.orange)
            }

            Divider().frame(height: 20)

            Button {
                pickFile()
            } label: {
                Label("Open PCAP…", systemImage: "doc.badge.plus")
            }
            .disabled(isCapturing || isLoading || model.isAnalyzing)

            if model.isAnalyzing {
                ProgressView(value: Double(model.progress.done),
                             total: Double(max(model.progress.total, 1)))
                    .frame(width: 90)
                Text("\(model.progress.done) / \(model.progress.total)")
                    .font(.caption).foregroundColor(.secondary)
            }

            Spacer()

            if !model.rows.isEmpty {
                Text("\(artifactCount) artifacts · \(model.flaggedCount) flagged")
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
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 44))
                .foregroundColor(.secondary.opacity(0.4))
            Text("Start a live capture or open an existing .pcap file.\nEvery routable IP and DNS query name will be checked against your providers.")
                .font(.callout)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            if let err = captureError {
                Text(err).foregroundColor(.red).font(.caption)
            }
            if let f = loadedFile {
                Text("Loaded: \(f.lastPathComponent)")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Capture

    private func startCapture() {
        captureError = nil
        do {
            try PCAPScanner.startCapture()
            isCapturing = true
        } catch {
            captureError = error.localizedDescription
        }
    }

    private func stopCapture() {
        isCapturing = false
        if let url = PCAPScanner.stopCapture() {
            loadedFile = url
            Task { await analyze(url: url) }
        } else {
            captureError = "Capture file not found."
        }
    }

    // MARK: - File picker

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.title            = "Select a PCAP file"
        panel.allowedContentTypes = []
        panel.allowsOtherFileTypes = true
        panel.canChooseDirectories = false
        panel.message          = "Choose a .pcap or .pcapng file to analyze"

        guard panel.runModal() == .OK, let url = panel.url else { return }
        loadedFile = url
        Task { await analyze(url: url) }
    }

    // MARK: - Analysis

    private func analyze(url: URL) async {
        isLoading    = true
        captureError = nil

        do {
            let strings   = try await PCAPScanner.extractArtifacts(from: url)
            artifactCount = strings.count
            let pairs     = strings.map { s -> (artifact: Artifact, process: String?) in
                (ArtifactResolver.resolve(s), nil)
            }
            isLoading = false
            await model.analyze(artifacts: pairs)
        } catch {
            captureError = error.localizedDescription
            isLoading    = false
        }
    }
}
