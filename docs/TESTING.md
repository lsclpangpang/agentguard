# 测试约定

## 流程

每项功能先写测试，确认失败，再写实现让它通过。提交前 `scripts/test.sh` 必须全绿。

```sh
scripts/test.sh                      # 全部
scripts/test.sh --filter PolicyDiff  # 只跑某个套件
```

## 分层

| 层 | 内容 | 在哪里测 |
| --- | --- | --- |
| GuardCore | 路径规范化、规则编译与冲突检查、SBPL 生成、权限差异与扩权判定、两段式批准、调用方信任、修订存储、Knodo 导入、待定项生成、eslogger 与沙箱日志解析、运行实例归属、修订生效判定、采集健康、总体状态、Helper 请求处理 | Linux 与 macOS，`swift test` |
| GuardPlatform | PATH 查找、用户主目录 | Linux 与 macOS |
| macOS 集成 | 沙箱真实生效、执行白名单、嵌套目录反例、网络正反例、XPC 与授权服务、launchd 接管、eslogger 实际输出 | 只能在 Mac 上，见 M0-CHECKLIST.md |

GuardCore 不依赖任何第三方包，也不调用系统接口；时间、ID、文件存储、认证校验都通过参数注入，测试里用固定值或内存实现。

## SBPL 测试的含义

`SBPLRendererTests` 只验证生成的文本结构（规则顺序、转义、没有无条件 `process-exec`）。这些规则在 macOS 上是否真的按预期拦截，必须由 M0 的集成测试证明，单元测试通过不能代替。

## 设计说明验收用例对照

| 用例 | 单元测试覆盖 | 仍需 Mac 集成测试 |
| --- | --- | --- |
| A-01/A-02 受管进程不能扩权、不能连 Helper | HelperServiceTests：受管进程树中的调用方（即使签名正确）不能提议变更或再登记实例；SBPL 末尾固定拒绝 Helper 服务名 | 真实 XPC 连接被拒 |
| A-03 重放、过期、基础修订变化 | ApprovalLedgerTests | — |
| A-04 目标不以 root 运行 | — | 启动器与 guard run |
| A-05–A-07 保护状态 | OverallStatusTests | 未受管实例发现 |
| A-08 嵌套反例 | 默认拒绝"读写目录内的只读项" | 六种文件操作反例 |
| A-09 导入导出一致、模板顺序无关 | PolicyCompilerTests、ProfileCodingTests | — |
| A-10 执行白名单 | 生成按路径的 process-exec；可写区内可执行文件必须带哈希 | 真实拦截 |
| A-11 采集告警 | CollectorHealthTests | eslogger 适配器 |
| A-12–A-14 实例归属与撤销 | InstanceTrackerTests、RevisionStateTests | 真实 fork/exec/exit 事件 |
| A-15–A-17 迁移、自启、交互式 CLI | — | 全部 |
| A-18 网络正反例 | 规则顺序 | 真实连接 |
