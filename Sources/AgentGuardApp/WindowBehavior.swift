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
    private static var closeObservers: [ObjectIdentifier: NSObjectProtocol] = [:]

    /// A menu bar app has no Dock icon or Cmd-Tab entry, so its window is lost once it falls behind
    /// another app. Behave like a regular app while the main window is open.
    static func windowOpened() {
        if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
    }

    /// Observe the actual close, not SwiftUI disappearance (which also occurs for sheet rebuilds).
    /// Exclude the closing window even if AppKit has not yet updated isVisible in this run loop.
    private static func observeClose(of window: NSWindow) {
        let id = ObjectIdentifier(window)
        guard closeObservers[id] == nil else { return }
        closeObservers[id] = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak window] _ in
            if let token = closeObservers.removeValue(forKey: id) { NotificationCenter.default.removeObserver(token) }
            DispatchQueue.main.async {
                let hasOtherWindow = NSApp.windows.contains {
                    $0 !== window && ($0.isVisible || $0.isMiniaturized) && $0.styleMask.contains(.titled) && !($0 is NSPanel) && $0.sheetParent == nil
                }
                if !hasOtherWindow && NSApp.activationPolicy() != .accessory { NSApp.setActivationPolicy(.accessory) }
            }
        }
    }

    /// `configure` runs from `updateNSView`, i.e. on every single SwiftUI update. Writing `level`
    /// and `collectionBehavior` unconditionally therefore made AppKit re-evaluate the titlebar and
    /// the content layout constantly, including mid-pass while a split view was being laid out.
    /// Only write what actually differs.
    static func apply(pinned: Bool, to window: NSWindow) {
        observeClose(of: window)
        let level: NSWindow.Level = pinned ? .floating : .normal
        if window.level != level { window.level = level }
        if window.hidesOnDeactivate { window.hidesOnDeactivate = false }
        if pinned {
            if !window.collectionBehavior.contains(.fullScreenAuxiliary) {
                window.collectionBehavior.insert(.fullScreenAuxiliary)
            }
        } else if window.collectionBehavior.contains(.fullScreenAuxiliary) {
            window.collectionBehavior.remove(.fullScreenAuxiliary)
        }
    }
}
#endif
