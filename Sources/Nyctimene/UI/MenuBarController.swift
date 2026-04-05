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
        menu.addItem(withTitle: "Analyze...",      action: #selector(openLookup),                  keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Settings...",     action: #selector(openSettings),                keyEquivalent: ",")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit Nyctimene",  action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        for item in menu.items { item.target = self }
        statusItem.menu = menu
    }

    @objc private func openLookup()    { LookupWindowController.open() }
    @objc private func openSettings()  { SettingsWindowController.shared.show() }
}
