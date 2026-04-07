import SwiftUI
import WebKit
import NyctimeneCore

// MARK: - Main view

struct ThreatLandscapeView: View {
    @ObservedObject private var store = SettingsStore.shared
    @State private var selectedSourceID: UUID?
    @State private var editingSource: ThreatLandscapeSource?
    @State private var showAddSheet = false

    private var sources: [ThreatLandscapeSource] {
        store.settings.threatLandscapeSources
    }

    private var resolvedColorScheme: ColorScheme? {
        switch store.settings.appearanceMode {
        case "dark":  return .dark
        case "light": return .light
        default:      return nil
        }
    }

    var body: some View {
        HSplitView {
            sidebar
                .frame(minWidth: 160, idealWidth: 180, maxWidth: 220)
            mainContent
        }
        .preferredColorScheme(resolvedColorScheme)
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(spacing: 0) {
            List(selection: $selectedSourceID) {
                ForEach(sources) { source in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(selectedSourceID == source.id ? Color.accentColor : Color.secondary.opacity(0.4))
                            .frame(width: 6, height: 6)
                        Text(source.name)
                            .font(.caption)
                            .lineLimit(1)
                    }
                    .tag(source.id)
                    .contextMenu {
                        Button("Edit...") { editingSource = source }
                        Button("Remove") { removeSource(source.id) }
                    }
                }
            }
            .listStyle(.sidebar)

            Divider()
            HStack(spacing: 8) {
                Button { showAddSheet = true } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
                .help("Add source")

                Spacer()

                if selectedSourceID != nil {
                    Button { removeSource(selectedSourceID!) } label: {
                        Image(systemName: "minus")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove selected source")
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
        }
        .sheet(isPresented: $showAddSheet) {
            SourceEditorSheet(mode: .add) { name, url in
                var s = store.settings
                s.threatLandscapeSources.append(ThreatLandscapeSource(name: name, urlString: url))
                store.settings = s
                store.save()
            }
        }
        .sheet(item: $editingSource) { source in
            SourceEditorSheet(mode: .edit(source)) { name, url in
                if let idx = store.settings.threatLandscapeSources.firstIndex(where: { $0.id == source.id }) {
                    store.settings.threatLandscapeSources[idx].name = name
                    store.settings.threatLandscapeSources[idx].urlString = url
                    store.save()
                }
            }
        }
    }

    // MARK: - Main content

    @ViewBuilder
    private var mainContent: some View {
        if let id = selectedSourceID, let source = sources.first(where: { $0.id == id }) {
            WebBrowserView(urlString: source.urlString)
                .id(id) // force re-create when source changes
        } else {
            VStack(spacing: 12) {
                Image(systemName: "globe.americas")
                    .font(.system(size: 48))
                    .foregroundColor(.secondary.opacity(0.3))
                Text("Choose a source...")
                    .font(.title3)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - Helpers

    private func removeSource(_ id: UUID) {
        store.settings.threatLandscapeSources.removeAll { $0.id == id }
        if selectedSourceID == id { selectedSourceID = nil }
        store.save()
    }
}

// MARK: - Source editor sheet

private struct SourceEditorSheet: View {
    enum Mode {
        case add
        case edit(ThreatLandscapeSource)
    }

    let mode: Mode
    let onSave: (String, String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name:      String = ""
    @State private var urlString: String = ""

    var body: some View {
        VStack(spacing: 16) {
            Text(isEdit ? "Edit Source" : "Add Source")
                .font(.headline)

            TextField("Name", text: $name)
                .textFieldStyle(.roundedBorder)
            TextField("URL", text: $urlString)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(isEdit ? "Save" : "Add") {
                    let trimName = name.trimmingCharacters(in: .whitespaces)
                    let trimURL  = urlString.trimmingCharacters(in: .whitespaces)
                    guard !trimName.isEmpty, !trimURL.isEmpty else { return }
                    onSave(trimName, trimURL)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty ||
                          urlString.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 360)
        .onAppear {
            if case .edit(let src) = mode {
                name      = src.name
                urlString = src.urlString
            }
        }
    }

    private var isEdit: Bool {
        if case .edit = mode { return true }
        return false
    }
}

// MARK: - Web browser view (WKWebView + nav controls)

private struct WebBrowserView: View {
    let urlString: String
    @StateObject private var model = WebViewModel()

    var body: some View {
        VStack(spacing: 0) {
            // Navigation bar
            HStack(spacing: 8) {
                Button { model.goBack() } label: {
                    Image(systemName: "chevron.left")
                }
                .disabled(!model.canGoBack)
                .buttonStyle(.borderless)

                Button { model.goForward() } label: {
                    Image(systemName: "chevron.right")
                }
                .disabled(!model.canGoForward)
                .buttonStyle(.borderless)

                Button { model.reload() } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)

                Text(model.currentTitle ?? "")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)

                if model.isLoading {
                    ProgressView()
                        .scaleEffect(0.6)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Web content
            WebViewRepresentable(model: model)
        }
        .onAppear {
            model.load(urlString)
        }
    }
}

// MARK: - WebViewModel

private class WebViewModel: ObservableObject {
    @Published var canGoBack    = false
    @Published var canGoForward = false
    @Published var isLoading    = false
    @Published var currentTitle: String?

    let webView: WKWebView

    init() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()
        webView = WKWebView(frame: .zero, configuration: config)
        webView.allowsBackForwardNavigationGestures = true
    }

    func load(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        webView.load(URLRequest(url: url))
    }

    func goBack()    { webView.goBack() }
    func goForward() { webView.goForward() }
    func reload()    { webView.reload() }
}

// MARK: - NSViewRepresentable for WKWebView

private struct WebViewRepresentable: NSViewRepresentable {
    let model: WebViewModel

    func makeNSView(context: Context) -> WKWebView {
        model.webView.navigationDelegate = context.coordinator
        return model.webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    class Coordinator: NSObject, WKNavigationDelegate {
        let model: WebViewModel
        private var observations: [NSKeyValueObservation] = []

        init(model: WebViewModel) {
            self.model = model
            super.init()

            observations = [
                model.webView.observe(\.canGoBack)    { [weak model] wv, _ in
                    DispatchQueue.main.async { model?.canGoBack = wv.canGoBack }
                },
                model.webView.observe(\.canGoForward) { [weak model] wv, _ in
                    DispatchQueue.main.async { model?.canGoForward = wv.canGoForward }
                },
                model.webView.observe(\.isLoading)    { [weak model] wv, _ in
                    DispatchQueue.main.async { model?.isLoading = wv.isLoading }
                },
                model.webView.observe(\.title)        { [weak model] wv, _ in
                    DispatchQueue.main.async { model?.currentTitle = wv.title }
                },
            ]
        }
    }
}
