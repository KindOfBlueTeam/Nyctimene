import AppKit
import NyctimeneCore

class MenuBarController {
    private var statusItem: NSStatusItem!

    func setup() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            if let img = Bundle.module.image(forResource: "Nyctimene_logo") {
                img.size = NSSize(width: 18, height: 18)
                img.isTemplate = false
                button.image = img
            } else {
                button.image = NSImage(systemSymbolName: "eyes", accessibilityDescription: "Nyctimene")
            }
        }

        let menu = NSMenu()

        let analyzeItem   = NSMenuItem(title: "Analyze...",           action: #selector(openLookup),     keyEquivalent: "")
        let landscapeItem = NSMenuItem(title: "Threat Landscape...", action: #selector(openLandscape),  keyEquivalent: "")
        let settingsItem  = NSMenuItem(title: "Settings...",         action: #selector(openSettings),   keyEquivalent: ",")
        let quitItem      = NSMenuItem(title: "Quit Nyctimene",     action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        analyzeItem.target   = self
        landscapeItem.target = self
        settingsItem.target  = self
        quitItem.target      = NSApp   // must target NSApp directly; targeting self greys it out

        menu.addItem(analyzeItem)
        menu.addItem(landscapeItem)
        menu.addItem(.separator())
        menu.addItem(settingsItem)
        menu.addItem(.separator())
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    @objc private func openLookup()     { LookupWindowController.open() }
    @objc private func openLandscape() { ThreatLandscapeWindowController.shared.show() }
    @objc private func openSettings()  { SettingsWindowController.shared.show() }
}
