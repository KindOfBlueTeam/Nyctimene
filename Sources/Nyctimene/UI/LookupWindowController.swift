import AppKit
import SwiftUI
import NyctimeneCore

class LookupWindowController: NSWindowController, NSWindowDelegate {

    // MARK: - Multi-window management

    static var openControllers: [LookupWindowController] = []

    static func open() {
        let controller = LookupWindowController()
        openControllers.append(controller)
        controller.show()
    }

    // MARK: - Hosting controller (created once, never recreated)

    private lazy var hostingController: NSHostingController<MainView> = {
        NSHostingController(rootView: MainView())
    }()

    // MARK: - Init

    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 960, height: 640),
            styleMask:   [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
            backing:     .buffered,
            defer:       false
        )
        window.title = "Nyctimene"
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 800, height: 500)
        window.center()

        super.init(window: window)
        window.delegate = self
        applyBackground()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleReapplyBackground),
            name: Notification.Name("com.nyctimene.reapplyBackground"),
            object: nil
        )
    }

    required init?(coder: NSCoder) { fatalError() }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        LookupWindowController.openControllers.removeAll { $0 === self }
    }

    // MARK: - Show

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
    }

    // MARK: - Background / transparency

    @objc private func handleReapplyBackground() {
        applyBackground()
    }

    func applyBackground() {
        guard let window else { return }
        let transparent = SettingsStore.shared.settings.transparencyEnabled

        if transparent {
            window.isOpaque = false
            window.backgroundColor = .clear

            let effect = NSVisualEffectView()
            effect.material      = .hudWindow
            effect.blendingMode  = .behindWindow
            effect.state         = .active
            effect.autoresizingMask = [.width, .height]

            hostingController.view.translatesAutoresizingMaskIntoConstraints = false
            effect.addSubview(hostingController.view)
            NSLayoutConstraint.activate([
                hostingController.view.leadingAnchor.constraint(equalTo: effect.leadingAnchor),
                hostingController.view.trailingAnchor.constraint(equalTo: effect.trailingAnchor),
                hostingController.view.topAnchor.constraint(equalTo: effect.topAnchor),
                hostingController.view.bottomAnchor.constraint(equalTo: effect.bottomAnchor)
            ])
            window.contentView = effect
        } else {
            window.isOpaque = true
            window.backgroundColor = nil
            window.contentViewController = hostingController
        }
    }
}
