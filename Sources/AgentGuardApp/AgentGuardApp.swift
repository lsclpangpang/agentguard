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
            Image(systemName: menuBarSymbol)
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
#else
@main
struct AgentGuardApp {
    static func main() {
        print("AgentGuard 只能在 macOS 上运行")
    }
}
#endif
