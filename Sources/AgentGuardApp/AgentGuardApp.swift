#if os(macOS)
import GuardCore
import SwiftUI

@main
struct AgentGuardApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView().environmentObject(model)
        } label: {
            MenuBarStatusIcon(symbol: menuBarSymbol)
        }
        .menuBarExtraStyle(.window)

        Window("AgentGuard", id: "main") {
            MainWindow()
                .environmentObject(model)
                .frame(minWidth: 900, minHeight: 620)
        }
        .windowToolbarStyle(.unified)
        .defaultSize(width: 1080, height: 720)
    }

    /// Menu bar icons are template images; the shape, not the color, carries the state.
    private var menuBarSymbol: String {
        switch model.overall.level {
        case .allGood: return "lock.shield"
        case .attention: return "exclamationmark.shield"
        case .problem: return "xmark.shield"
        }
    }
}

private struct MenuBarStatusIcon: View {
    let symbol: String
    @Environment(\.openWindow) private var openWindow
    @State private var opened = false

    var body: some View {
        Image(systemName: symbol)
            .onAppear {
                guard !opened, CommandLine.arguments.contains("--show-window") else { return }
                opened = true
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
    }
}
#else
@main
struct AgentGuardApp {
    static func main() {
        print("AgentGuard 只能在 macOS 上运行")
    }
}
#endif
