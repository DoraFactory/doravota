# Wasmd 迁移到组织 fork

## 范围与执行前验证计划

2026-10-05：将本地 Wasmd 副本迁移到 `DoraFactory/wasmd`，固定提交引用；不改变当前 Wasm 限制、SDK/IBC 版本或主网节点。

1. 对照官方 v0.70.4 与此前本地副本，确认生产代码差异仅为原有兼容和部署限制。
2. 核对 fork 提交、Go 伪版本、go.sum 校验值，移除本地 Wasmd 副本及脚本中的旧路径。
3. 在 amaci-testnet-operator 隔离容器中重新运行完整应用 Go 测试、vet、依赖校验、Linux 构建及出块/重启/导出烟测。
4. 记录实际结果、失败与修复。既有真实主网快照/IBC 对端联调未完成的边界不变。

## 当前进度

已确认组织 fork 的 main 和 v0.70.4 均为官方提交 `70c6321f48bfff91dd581a40eeb706a2a24eaf7c`。新建 `doravota/sdk055-restricted` 分支，保留 main 和上游标签。

fork 保留完整上游历史和测试源文件；原有旧 SDK 测试辅助依旧排除，因此不能声称完整 wasmd 上游测试通过。本轮验证以 Dora Vota 实际依赖图和应用测试为准，不扩展到 wasmd 独立应用的 SDK 0.55 升级。

## 失败与修复

- 2026-10-05，首次远程 `go mod tidy` 失败：完整 fork 带回的 v2 迁移测试引用已经移除的 `x/params/keeper`。日志：`evidence/fork-migration/dependencies-01.log`。
- fork 提交 `035bca31` 将该测试改为使用迁移函数已有的只读 Subspace 接口和独立 KV 参数样本，保留四种参数组合及迁移后断言；生产迁移代码未改。
- 2026-10-06 继续：所有编译、测试和运行验证均在 `amaci-testnet-operator`，本地只编辑源码、操作 Git 和保存审查资料。远程约 82 GiB 可用磁盘、56 GiB 可用内存；使用 4 CPU / 12 GiB 容器，不停止现有服务。

## 实际结果

- fork 提交：`035bca31c3f57a3f5df665564c98d6bcbc2791cc`；Go 固定版本 `v0.70.5-0.20261005055950-035bca31c3f5`。这是 v0.70.4 基线上的伪版本，不是官方 v0.70.5 release。
- 远程 `go mod tidy`、`go mod verify` 及 fork 版本/校验值检查通过；除 fork 的两个 go.sum 条目外，其他依赖未变。见 `dependencies-02.log`。
- 在 Dora Vota 的 SDK 0.55 依赖图中，单独运行 fork 的 `x/wasm/migrations/v2` 测试通过，四种参数案例全部通过。见 `legacy-migration-test.log`。
- 远程完整应用 `go test -mod=readonly -p 4 ./... -count=1` 通过。包括真实 Wasm 查询和提款、普通/治理权限部署拒绝、状态保留、ML-DSA 账户交易回归。见 `application-tests.log`。
- 最终提交的 Linux 构建、vet、出块/重启/导出验证待执行；完成后追加记录。

## 代码与审查入口

- [组织 fork 分支](https://github.com/DoraFactory/wasmd/tree/doravota/sdk055-restricted)
- [与官方 v0.70.4 的差异](https://github.com/DoraFactory/wasmd/compare/v0.70.4...035bca31c3f57a3f5df665564c98d6bcbc2791cc)：仅 6 个文件变更，生产代码维持原部署策略；额外修正旧迁移测试及说明。
- 固定来源与模块哈希：[WASMD-FORK.json](WASMD-FORK.json)。`scripts/verify-wasmd-fork.py` 检查实际选择的依赖与记录一致；`go mod verify` 检查下载内容完整性。
- Dora Vota 删除 `third_party/wasmd-v055-compat`，保留另外两个历史类型兼容目录；运行和测试脚本不再使用被删除路径。
- 远程根目录：`amaci-testnet-operator:/root/vota-wasmd-fork-20261005/`；日期沿用首次执行目录名。日志在 `evidence/`，本地副本在本目录的 `evidence/fork-migration/`。
