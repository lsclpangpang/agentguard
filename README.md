# AgentGuard

个人自用的 macOS 权限管控工具：给命令行工具和 Agent 设定能读写哪些目录、能执行哪些程序、能连哪些本机端口，所有扩大权限的变更都要经本人系统认证。

> **状态：** 核心逻辑已有完整单元测试；macOS 集成部分（沙箱是否真正拦截、XPC、授权服务、eslogger）尚未在真机验证。见 [docs/M0-CHECKLIST.md](docs/M0-CHECKLIST.md)。

## 组成

| 组件 | 作用 | 运行身份 |
| --- | --- | --- |
| `AgentGuard.app` | 菜单栏 App：查看状态、审批权限变更、处理待定项、接管启动项 | 当前用户 |
| `guard` | `guard run <配置档> -- <命令>`：以已批准的配置档启动命令；`guard status` | 当前用户 |
| `agentguard-launcher` | 被接管的 LaunchAgent 用它进入沙箱后启动目标 | 当前用户 |
| `agentguard-helper` | 唯一的特权组件：保存修订、生成规则、校验调用方与系统认证、跟踪运行实例、采集行为 | root |

所有判断都在 `GuardCore` 中完成（不依赖系统接口，可在 Linux 上测试），`GuardPlatform` 和各可执行文件只负责调用 macOS 接口。

## 安全模型

- **默认拒绝**：强制和受限学习模式下，未列出的访问一律被沙箱拒绝；任何一步失败都保持停止，不退回无限制运行。
- **扩权要认证**：Helper 先生成精确差异，App 展示后用系统认证（每次一个新的授权，权利名绑定到这一次变更）；Helper 校验调用方 cdhash、uid、基础修订号后才写入。收紧权限不需要认证。
- **受管进程不能扩权**：规则固定拒绝连接 Helper 的 XPC 服务、拒绝写入配置与发行目录、App 包和 LaunchAgents 目录；即使绕过，Helper 也会拒绝来自受管进程树的请求。
- **撤销以旧实例退出为准**：只有使用旧修订的进程及其后代全部退出，才显示“已生效”。
- **观察不等于完整审计**：界面显示“已观测行为”和采集器缺口；没有记录只表示未观测到。

只保证**通过 AgentGuard 入口启动**的进程及其子进程受限；同一程序从其他入口启动时只能被发现和提醒。

## 开发

```sh
scripts/test.sh                 # 运行全部测试（Linux 或 macOS）
scripts/build-app.sh            # 在 macOS 上构建 build/AgentGuard.zip（ad-hoc 签名）
```

测试约定见 [docs/TESTING.md](docs/TESTING.md)。

## 发布

合并到 `main` 时，GitHub Actions 在 macOS 上运行测试、打包，并创建预发布版本 `v<VERSION>-build.<序号>`。`main` 受保护，只能通过 Pull Request 合并。

## 安装

1. 从 Releases 下载 `AgentGuard.zip`，解压后拖进“应用程序”，运行 `xattr -cr /Applications/AgentGuard.app`（未公证）。
2. 打开 App →“安装 Helper”，在“系统设置 > 通用 > 登录项 > 允许在后台”中允许 AgentGuard。
   第一次点“安装 Helper”时 macOS 会拒绝启动尚未允许的后台项目，这是正常流程；允许后 App 会自动连上。
3. 在“隐私与安全性 > 完全磁盘访问”中添加 `/Applications/AgentGuard.app/Contents/MacOS/agentguard-helper`（选择窗口里按 ⌘⇧G 输入路径），然后运行 `sudo launchctl kickstart -k system/com.lsclpangpang.agentguard.helper`。eslogger 由 Helper 启动，系统按 Helper 判断授权；不授权只能看到沙箱拒绝记录，看不到进程生命周期。
4. 新建配置档（默认“受限学习”），用 `guard run` 启动命令；在“待定项”里逐项批准后切换到“强制保护”。
