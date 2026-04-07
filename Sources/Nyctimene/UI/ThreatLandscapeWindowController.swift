import AppKit
import SwiftUI

class ThreatLandscapeWindowController: NSWindowController, NSWindowDelegate {

    static let shared = ThreatLandscapeWindowController()

    private lazy var hostingController: NSHostingController<ThreatLandscapeView> = {
        NSHostingController(rootView: ThreatLandscapeView())
    }()

    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 700),
            styleMask:   [.titled, .closable, .resizable, .miniaturizable],
            backing:     .buffered,
            defer:       false
        )
        window.title = "Threat Landscape"
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 700, height: 400)
        window.center()

        super.init(window: window)
        window.delegate = self
        applyAppearance()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleReapply),
            name: WindowAppearance.reapplyNotification,
            object: nil
        )
    }

    required init?(coder: NSCoder) { fatalError() }

    deinit { NotificationCenter.default.removeObserver(self) }

    @objc private func handleReapply() { applyAppearance() }

    private func applyAppearance() {
        guard let window else { return }
        WindowAppearance.apply(to: window, hostingController: hostingController)
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
    }
}
