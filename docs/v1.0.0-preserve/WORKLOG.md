# 1.0.0 保留 Wasm / IBC 工作记录

## 范围
SDK 0.55.0、CometBFT 0.40.0；保留 Wasm / IBC / ICA 的状态和运行；继承受限部署策略；主网共识保持 Ed25519。无资产清零要求。不包含自定义 pqcauth、主网发布、共识轮换。

## 来源
从正式 0.5.0 提交 8a4313d2b338eb5e5090dd5cdfe5b0f54203c426 新建 upgrade/v1.0.0-sdk055-preserve。复用 ae00da8、803be3b 两个 SDK 适配提交；go.mod/go.sum 冲突采用旧 SDK 候选再刷新安全依赖；.gitignore 合并两方条目。原工作区和模块下线分支未修改。

## 执行前测试清单（未运行不代表通过）
1. 依赖可解析、模块校验、Wasmd 本地补丁来源与哈希可复核。
2. 完整 Go 测试、vet、生产 Wasm 引擎构建。
3. Wasm / IBC 路由和状态保留，Nobody 与迁移限制测试，默认共识 Ed25519。
4. 隔离新链初始化、出块、合约执行和查询、重启、导出基础烟测。
5. 主网快照升级、多节点与真实跨链回归属于后续第 4 / 5 阶段，本轮不宣称完成。

## 实际过程
- 复用代码发现 Wasmd 0.70.3 / WasmVM 3.0.7 过时，不采用为交付依赖；先刷新到正式安全修复版本。
- 初次默认 goproxy.cn 下载停滞，停止本任务下载后改用 proxy.golang.org，Wasmd 下载成功。
- 第一次 tidy / test 尚处下载阶段时停止，未产生测试结果；固定 IBC 到 2026-09-29 的上游 main 提交 7b1838a13bc442393253b3b3d995e228a3995855 后重新执行，避免使用旧的 8 月适配快照。
- 执行层补丁：在 Wasmd 共用 create / instantiate / migrate 入口添加不可由节点配置关闭的应用策略；包含 Gov 权限调用。InitChain / 1.0.0 handler 将模块和已有代码实例化权限设为 Nobody。已有执行、查询、导入保留。
- Wasmd upstream-diff.patch 仅 4 个文件：2 个旧测试辅助适配、keeper 状态/检查及 option。完整文件 SHA-256 已生成。
- 复用了此前 Store v2 删除旧 params/group 的临时挂载修复；补充 19 -> 17 stores 的保存/重启测试，不删除 Wasm/IBC 数据。
- 远程资源读取：约 56 GiB 可用内存、88 GiB 可用磁盘。新目录 /root/vota-v1-preserve-20261004，测试容器限制 4 CPU / 12 GiB；未停止或清理原有环境。
- 远程 tests-01：编译与其余包通过，新增真实 VM 用例在智能查询处失败：测试 Context 未设置区块时间，被 Wasmd NewEnv 拒绝。修复测试上下文的时间/高度/chain-id，保留原失败日志后重测；未改动 VM 校验。
- 远程 tests-02：完整 go test ./... 通过，真实 VM 查询/11 单位提款、四类部署拒绝、19 -> 17 stores 保存及重启、SDK 原生 ML-DSA 账户回归通过。
- build-smoke-01 在执行 vet 前因源码归档排除了 evidence 目录而重定向失败；未构建、未烟测。增加先创建目录的独立 review 构建脚本，重新执行。
- 本机下载较慢，停止尚在下载的 tidy；使用远程成功 tidy 生成的 go.mod/go.sum，后续验证统一在远程 Linux 环境进行。
