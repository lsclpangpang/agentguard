# M0：必须在真机上验证的假设

代码按以下假设实现，但都没有在 macOS 上运行过。每一项都要在真机上给出“成立 / 需降级 / 不成立”的结论，并据此修改代码或需求。

## 构建与签名

- [ ] `swift build` 在 macOS 上通过（Linux 上只编译了非 macOS 分支）。
- [x] ad-hoc 签名的 `SMAppService.daemon` 能注册并运行 Helper。（2026-11-03 真机确认：首次 `register()` 必然返回 `SMAppServiceErrorDomain` code 1，原因是 BTM 处置状态为 disallowed、smd 拒绝 bootstrap；条目已登记，状态变为 requiresApproval，在“登录项 > 允许在后台”允许后 smd 成功启动。另建无关的 ad-hoc 测试 App 复现同样行为，排除签名与 plist 问题。）
- [ ] Helper 按 `Contents/MacOS` 下各二进制计算的 cdhash，与 App、`guard`、启动器运行时的 cdhash 一致；`setCodeSigningRequirement` 用 `cdhash H"..."` 组合能放行这三者、拒绝其他程序。
- [ ] 通过 KVC 读取 `NSXPCConnection` 的 `auditToken` 可用，`val.5`/`val.7` 分别是 pid/pidversion。

## 系统认证

- [ ] Helper 写入的通配权利 `com.lsclpangpang.agentguard.`（结尾带点）能匹配 `com.lsclpangpang.agentguard.change.<id>`。
- [ ] App 用新的 AuthorizationRef 每次都会弹出认证；Helper 用外部形式复核同一权利能通过，`destroyRights` 后同一令牌不能再用。

## 沙箱规则（GuardCore 生成的 SBPL）

- [ ] `sandbox_init` 通过 `@_silgen_name` 调用可用，子进程继承规则。
- [ ] `(import "bsd.sb")` 作为基础规则可用，且足够让常见命令启动；否则调整 `AgentGuardConfig.baseRules`。
- [ ] 默认拒绝 + 读写目录：允许目录可读写，未授权目录不可读，符号链接越界被拒。
- [ ] 执行白名单：`(allow process-exec (literal ...))` 只放行列出的程序；通过符号链接（如 Homebrew 的 `bin/python3`）执行时匹配的是哪个路径。
- [ ] 读写父目录内的只读子路径：设计说明 10.2 的六种反例（直接写、删除、原子替换、改名、移动祖先、符号链接）。全部通过才把 `allowsNestedReadOnly` 设为 true。
- [ ] 网络：`localhost:<端口>` 规则对 IPv4 与 IPv6 回环都生效；拒绝端口须有监听器在运行才算验证。
- [ ] 末尾的 `(deny mach-lookup (global-name "com.lsclpangpang.agentguard.helper"))` 确实让受管进程连不上 Helper。

## 采集

- [ ] `eslogger --format json` 的字段名与 `ESLoggerParserTests` 中的样例一致（`global_seq_num`、`process.audit_token.pid/pidversion`、`event.fork.child`、`event.exec.target`、`open.fflag` 等）；用真实输出替换测试样例。
- [x] 由 Helper 启动 eslogger 时，“完全磁盘访问”要授予谁。（2026-11-03 真机确认：TCC 日志 `AUTHREQ_ATTRIBUTION: responsible={com.lsclpangpang.agentguard.helper} requesting={com.apple.eslogger}`，授权对象是 `agentguard-helper`，只给 `/usr/bin/eslogger` 授权无效。）
- [x] 授权对象搬出 App 包：采集器改成 `/Library/PrivilegedHelperTools/com.lsclpangpang.agentguard.collector` 独立守护进程，eslogger 是它的子进程，TCC 归因 `responsible_path=/Library/PrivilegedHelperTools/com.lsclpangpang.agentguard.collector`；App 重签不再让授权失效（2026-11-03 真机确认）。
- [ ] 采集器升级策略：替换 `/Library/PrivilegedHelperTools` 下的副本会让授权失效，需重新授权一次（当前实现只在该文件缺失时安装）。
- [ ] 全系统 fork/exec/exit 事件的 CPU 与内存开销；开启文件事件（学习模式）时的开销。
- [ ] 沙箱拒绝日志的实际格式与 `SandboxLogParserTests` 一致，`log stream` 谓词能收到。

## 模板路径

- [ ] Claude Code 实际写入的位置（`~/.claude` 下哪些子目录、`~/.claude.json`、`/private/tmp/claude-<uid>`）。
- [ ] Codex 实际写入的位置（`~/.codex` 下哪些子目录）。

## Knodo 迁移

- [ ] 用真实的 `/Library/KnodoRestricted/allowlist.json` 与 `policy.sb` 导入，核对“无法导入的规则”列表。
- [ ] 以 `/Library/KnodoRestricted/entry.sh` 作为启动程序是否能保留原有的私有配置与环境变量。
- [ ] 接管后原启动项 `com.knodo.restricted-agent` 被停止并备份；“恢复原启动项”能还原。
