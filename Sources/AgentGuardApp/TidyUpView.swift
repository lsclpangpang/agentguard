#if os(macOS)
import GuardCore
import SwiftUI

/// One pass over the installation: for each program, which startup routes and running copies are
/// managed, which are not, and what cannot be confirmed. Nothing changes without an explicit choice.
struct TidyUpSheet: View {
    @EnvironmentObject var model: AppModel
    @Binding var isPresented: Bool
    @State private var surveys: [ProgramSurvey]?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("整理现有安装").font(.title2.weight(.semibold))
            Text("按程序列出启动入口、正在运行的副本和旧规则。只有启动同一个程序文件的启动项才会列出；名称相似但启动其他程序的不会被处理。")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let surveys {
                        if surveys.isEmpty { Text("还没有受保护的程序。").foregroundStyle(.secondary) }
                        ForEach(surveys, id: \.profileID) { survey in programCard(survey) }
                    } else {
                        HStack { ProgressView().controlSize(.small); Text("正在检查…") }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 320, maxHeight: 460)
            HStack {
                Button("重新检查") { reload() }.disabled(busy)
                Spacer()
                Button("完成") { isPresented = false }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 640)
        .task { reload() }
    }

    private func reload() {
        Task {
            _ = await model.refreshReport(includePending: false)
            surveys = await model.survey()
        }
    }

    private func programCard(_ survey: ProgramSurvey) -> some View {
        Card(title: survey.profileID, systemImage: survey.isOrganized ? "checkmark.seal.fill" : "exclamationmark.triangle.fill") {
            VStack(alignment: .leading, spacing: 8) {
                Label(survey.managedLaunch ? "AgentGuard 启动入口：已设置" : "AgentGuard 启动入口：没有设置（在终端中用 guard run 运行）",
                      systemImage: "power").font(.callout)
                Label(survey.runningInstances.isEmpty ? "当前没有受管副本在运行" : "受管副本 #\(survey.runningInstances.map(String.init).joined(separator: "、#")) 正在运行",
                      systemImage: "bolt").font(.callout)
                if survey.isOrganized {
                    Text("没有发现其他启动入口、未受管的副本或无法核对的旧规则。").font(.callout).foregroundStyle(.secondary)
                }
                ForEach(Array(survey.findings.enumerated()), id: \.offset) { _, finding in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(finding.title).font(.callout.weight(.medium)).fixedSize(horizontal: false, vertical: true)
                        Text(finding.advice).font(.caption).foregroundStyle(.secondary)
                        if case let .otherLaunchEntry(entry) = finding {
                            Text(LaunchArguments.format([entry.executable] + entry.arguments)).font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled).lineLimit(2)
                            HStack {
                                Button("停用这个启动项…") {
                                    Task {
                                        busy = true
                                        if await model.disableLaunchItem(entry, for: survey.profileID) { reload() }
                                        busy = false
                                    }
                                }
                                .disabled(busy || !model.helperReachable)
                                Text("暂不处理时它会留在待处理清单里").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.08)))
                }
                if !survey.disabled.isEmpty {
                    Text("已停用的启动项（可以恢复）").font(.subheadline.weight(.medium)).padding(.top, 4)
                    ForEach(survey.disabled, id: \.label) { entry in
                        HStack {
                            Text("\(entry.label)  ·  原位置 \(entry.location)").font(.caption).textSelection(.enabled)
                            Spacer()
                            Button("恢复…") {
                                Task {
                                    busy = true
                                    if await model.restoreLaunchItem(entry) { reload() }
                                    busy = false
                                }
                            }
                            .controlSize(.small)
                            .disabled(busy || !model.helperReachable)
                        }
                    }
                }
            }
        }
    }
}
#endif
