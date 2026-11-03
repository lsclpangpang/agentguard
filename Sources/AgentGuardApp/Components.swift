#if os(macOS)
import AppKit
import GuardCore
import SwiftUI

/// A titled panel used for every section of the detail view.
struct Card<Content: View, Accessory: View>: View {
    let title: String
    let systemImage: String
    var subtitle: String?
    @ViewBuilder var accessory: () -> Accessory
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Label(title, systemImage: systemImage).font(.headline)
                Spacer()
                accessory()
            }
            if let subtitle {
                Text(subtitle).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(.quaternary))
    }
}

extension Card where Accessory == EmptyView {
    init(title: String, systemImage: String, subtitle: String? = nil, @ViewBuilder content: @escaping () -> Content) {
        self.init(title: title, systemImage: systemImage, subtitle: subtitle, accessory: { EmptyView() }, content: content)
    }
}

struct Chip: View {
    let text: String
    var systemImage: String?
    var tint: Color = .secondary

    var body: some View {
        HStack(spacing: 4) {
            if let systemImage { Image(systemName: systemImage).imageScale(.small) }
            Text(text)
        }
        .font(.caption.weight(.medium))
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .foregroundStyle(tint)
        .background(Capsule().fill(tint.opacity(0.14)))
    }
}

struct Notice: View {
    enum Kind {
        case info, warning, error

        var color: Color {
            switch self {
            case .info: return .blue
            case .warning: return .orange
            case .error: return .red
            }
        }

        var symbol: String {
            switch self {
            case .info: return "info.circle.fill"
            case .warning: return "exclamationmark.triangle.fill"
            case .error: return "xmark.octagon.fill"
            }
        }
    }

    let kind: Kind
    let text: String
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: kind.symbol).foregroundStyle(kind.color).font(.body)
            Text(text).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if let actionTitle, let action {
                Button(actionTitle, action: action).controlSize(.small)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(kind.color.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(kind.color.opacity(0.25)))
    }
}

/// Shows the last component prominently and the parent dimmed; the full path is selectable and in the tooltip.
struct PathLabel: View {
    let path: String

    var body: some View {
        let url = URL(fileURLWithPath: path)
        let parent = url.deletingLastPathComponent().path
        VStack(alignment: .leading, spacing: 1) {
            Text(url.lastPathComponent.isEmpty ? path : url.lastPathComponent).font(.body).lineLimit(1).truncationMode(.middle)
            Text(Self.abbreviate(parent)).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .help(path)
        .textSelection(.enabled)
    }

    static func abbreviate(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }
}

/// A round icon tile used in rows.
struct IconTile: View {
    let systemImage: String
    var tint: Color = .accentColor
    var size: CGFloat = 28

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: size * 0.48, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous).fill(tint.opacity(0.14)))
    }
}

enum Pasteboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

/// 变更确认：窗口内的 sheet。NSAlert 的 sheet/runModal 在菜单栏 App 上会挂到看不见的窗口，
/// 结果就是内容点不动、只有滚轮还活着。
struct ConfirmationSheet: View {
    let pending: PendingConfirmation
    let answer: (Bool) -> Void

    private var text: String { pending.lines.joined(separator: "\n") }

    private var needsScroll: Bool { pending.lines.count > 8 || text.count > 480 }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(pending.title).font(.headline)
            if needsScroll {
                Text("共 \(pending.lines.count) 行变更，滚动查看全部内容。")
                    .font(.callout).foregroundStyle(.secondary)
                ScrollView {
                    Text(text)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(height: 320)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary))
            } else if !text.isEmpty {
                Text(text).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("取消") { answer(false) }.keyboardShortcut(.cancelAction)
                Button("确认") { answer(true) }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 660)
    }
}
#endif
