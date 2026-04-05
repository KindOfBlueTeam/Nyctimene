import SwiftUI
import NyctimeneCore

struct IOCFeedsView: View {
    @ObservedObject private var store = SettingsStore.shared

    @State private var showingAddForm = false
    @State private var newName  = ""
    @State private var newURL   = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Toolbar
            HStack {
                Text("IOC Feeds")
                    .font(.headline)
                Spacer()
                Button {
                    showingAddForm.toggle()
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)

            // Inline add form
            if showingAddForm {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Feed name", text: $newName)
                        .textFieldStyle(.roundedBorder)
                    TextField("Feed URL", text: $newURL)
                        .textFieldStyle(.roundedBorder)
                    HStack {
                        Button("Add") {
                            let trimmedName = newName.trimmingCharacters(in: .whitespaces)
                            let trimmedURL  = newURL.trimmingCharacters(in: .whitespaces)
                            guard !trimmedName.isEmpty, !trimmedURL.isEmpty else { return }
                            store.settings.iocFeeds.append(IOCFeed(name: trimmedName, urlString: trimmedURL))
                            store.save()
                            newName = ""
                            newURL  = ""
                            showingAddForm = false
                        }
                        .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty ||
                                  newURL.trimmingCharacters(in: .whitespaces).isEmpty)

                        Button("Cancel") {
                            newName = ""
                            newURL  = ""
                            showingAddForm = false
                        }
                        .buttonStyle(.borderless)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 12)
            }

            Divider()

            if store.settings.iocFeeds.isEmpty {
                Spacer()
                HStack {
                    Spacer()
                    Text("No IOC feeds yet. Add threat intelligence feed URLs to track here.")
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding()
                    Spacer()
                }
                Spacer()
            } else {
                List {
                    ForEach(store.settings.iocFeeds) { feed in
                        HStack(alignment: .center, spacing: 12) {
                            if let url = URL(string: feed.urlString) {
                                Link(destination: url) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(feed.name)
                                            .font(.body)
                                            .foregroundColor(.primary)
                                        Text(feed.urlString)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                            } else {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(feed.name)
                                        .font(.body)
                                    Text(feed.urlString)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()
                            Button {
                                store.settings.iocFeeds.removeAll { $0.id == feed.id }
                                store.save()
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                            }
                            .buttonStyle(.borderless)
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.inset)
            }
        }
    }
}
