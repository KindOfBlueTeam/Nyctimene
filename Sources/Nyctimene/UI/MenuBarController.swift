import AppKit
import NyctimeneCore

class MenuBarController {
    private var statusItem: NSStatusItem!

    func setup() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "eyes", accessibilityDescription: "Nyctimene")
        }

        let menu = NSMenu()

        let analyzeItem  = NSMenuItem(title: "Analyze...",     action: #selector(openLookup),    keyEquivalent: "")
        let settingsItem = NSMenuItem(title: "Settings...",    action: #selector(openSettings),  keyEquivalent: ",")
        let quitItem     = NSMenuItem(title: "Quit Nyctimene", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        analyzeItem.target  = self
        settingsItem.target = self
        quitItem.target     = NSApp   // must target NSApp directly; targeting self greys it out

        menu.addItem(analyzeItem)
        menu.addItem(.separator())
        menu.addItem(settingsItem)
        menu.addItem(.separator())
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    @objc private func openLookup()    { LookupWindowController.open() }
    @objc private func openSettings()  { SettingsWindowController.shared.show() }
}
