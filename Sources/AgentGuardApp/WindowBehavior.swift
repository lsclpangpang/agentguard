#if os(macOS)
import AppKit
import SwiftUI

/// Hands the hosting NSWindow to `configure` once the view is attached, and again on every update.
struct WindowAccessor: NSViewRepresentable {
    let configure: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { if let window = view.window { configure(window) } }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { if let window = nsView.window { configure(window) } }
    }
}

enum MainWindowBehavior {
    static let pinnedKey = "pinMainWindow"

    /// A menu bar app has no Dock icon or Cmd-Tab entry, so its window is lost once it falls behind
    /// another app. Behave like a regular app while the main window is open.
    static func windowOpened() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    static func windowClosed() {
        NSApp.setActivationPolicy(.accessory)
    }

    static func apply(pinned: Bool, to window: NSWindow) {
        window.level = pinned ? .floating : .normal
        window.hidesOnDeactivate = false
        if pinned {
            window.collectionBehavior.insert(.fullScreenAuxiliary)
        } else {
            window.collectionBehavior.remove(.fullScreenAuxiliary)
        }
    }
}
#endif
