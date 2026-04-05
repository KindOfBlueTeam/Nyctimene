import AppKit

// Menubar-only: no Dock icon, no app menu bar
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let delegate = AppDelegate()
app.delegate = delegate
app.run()
