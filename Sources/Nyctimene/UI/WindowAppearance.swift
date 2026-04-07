import AppKit
import SwiftUI
import NyctimeneCore

/// Shared window appearance logic applied to all Nyctimene windows.
enum WindowAppearance {

    static let reapplyNotification = Notification.Name("com.nyctimene.reapplyBackground")

    /// Apply the current appearance settings to a window + its hosting controller.
    static func apply(to window: NSWindow, hostingController: NSViewController) {
        let settings = SettingsStore.shared.settings

        // Color scheme
        switch settings.appearanceMode {
        case "dark":  window.appearance = NSAppearance(named: .darkAqua)
        case "light": window.appearance = NSAppearance(named: .aqua)
        default:      window.appearance = nil
        }

        // Ensure the hosting controller is set
        if window.contentViewController !== hostingController {
            window.contentViewController = hostingController
        }

        // Remove any existing effect view
        removeEffectView(from: window)

        switch settings.windowStyle {
        case "frosted":
            window.isOpaque = false
            window.backgroundColor = .clear

            guard let contentView = window.contentView,
                  let themeFrame = contentView.superview else { return }

            let effect = NycVibrancyView()
            effect.material = .hudWindow
            effect.blendingMode = .behindWindow
            effect.state = .active
            effect.translatesAutoresizingMaskIntoConstraints = false

            themeFrame.addSubview(effect, positioned: .below, relativeTo: contentView)
            NSLayoutConstraint.activate([
                effect.leadingAnchor.constraint(equalTo: themeFrame.leadingAnchor),
                effect.trailingAnchor.constraint(equalTo: themeFrame.trailingAnchor),
                effect.topAnchor.constraint(equalTo: themeFrame.topAnchor),
                effect.bottomAnchor.constraint(equalTo: themeFrame.bottomAnchor),
            ])

            contentView.wantsLayer = true
            contentView.layer?.backgroundColor = .clear

        default: // "solid"
            window.isOpaque = true
            window.backgroundColor = nil
        }
    }

    private static func removeEffectView(from window: NSWindow) {
        guard let contentView = window.contentView,
              let themeFrame = contentView.superview else { return }
        for sub in themeFrame.subviews where sub is NycVibrancyView {
            sub.removeFromSuperview()
        }
    }
}

/// Tagged subclass so we can find and remove our vibrancy views.
private class NycVibrancyView: NSVisualEffectView {}
