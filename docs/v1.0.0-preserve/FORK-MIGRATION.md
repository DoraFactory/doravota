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
- 最终源码提交 `17d9b50b2e88c72cab4dce9a169df1d31cb78965` 的 Linux amd64 构建、vet、模块校验及 fork pin 校验通过。
- 最终二进制报告版本 1.0.0 / SDK 0.55.0 / WasmVM 3.0.8。隔离新链 Ed25519 共识出块至高度 3，重启后至高度 5，导出成功。见 `build-smoke-final.log` 和 `final-build/smoke-ed25519.json`。

## 代码与审查入口

- [组织 fork 分支](https://github.com/DoraFactory/wasmd/tree/doravota/sdk055-restricted)
- [与官方 v0.70.4 的差异](https://github.com/DoraFactory/wasmd/compare/v0.70.4...035bca31c3f57a3f5df665564c98d6bcbc2791cc)：仅 6 个文件变更，生产代码维持原部署策略；额外修正旧迁移测试及说明。
- 固定来源与模块哈希：[WASMD-FORK.json](WASMD-FORK.json)。`scripts/verify-wasmd-fork.py` 检查实际选择的依赖与记录一致；`go mod verify` 检查下载内容完整性。
- Dora Vota 删除 `third_party/wasmd-v055-compat`，保留另外两个历史类型兼容目录；运行和测试脚本不再使用被删除路径。
- 远程根目录：`amaci-testnet-operator:/root/vota-wasmd-fork-20261005/`；日期沿用首次执行目录名。日志在 `evidence/`，本地副本在本目录的 `evidence/fork-migration/`。

## 最终产物

| 内容 | 值 |
|---|---|
| Dora Vota 构建源码 | `17d9b50b2e88c72cab4dce9a169df1d31cb78965`，后续仅文档提交不改变该构建 |
| Wasmd 固定提交 | `035bca31c3f57a3f5df665564c98d6bcbc2791cc` |
| 远程源码归档 | `final-source.tar.gz`，SHA-256 `cb8a261526dd471b1e277d4ed474aba4f7c2f37dd4f8a60c179f9ddf0e4ba009` |
| 远程审查二进制 | `source-17d9b50/build/dorad` |
| 二进制 SHA-256 | `ce26dcff01bd37bf47134522e688d78940778f3524fc0e0e61215c59bb48c334` |
| 构建镜像 | `golang:1.26.5-bookworm`，digest `sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd` |

所有编译和测试都在远程 Linux amd64 容器完成；二进制动态链接 WasmVM，仅用于审查，不是静态验证人分发包。测试使用隔离新链和临时密钥，无主网改动。

重现命令（在上述远程源码目录及构建容器内）：

```sh
go test -mod=readonly -p 4 github.com/CosmWasm/wasmd/x/wasm/migrations/v2 -count=1 -v
go test -mod=readonly -p 4 ./... -count=1
COMMIT_SHA=17d9b50b2e88c72cab4dce9a169df1d31cb78965 bash scripts/build-preserve-review.sh
```

尚未覆盖：完整 wasmd 上游测试、wasmd 独立节点应用适配、真实主网快照迁移、多节点/IBC 对端联调和静态发行构建。此前相应验收要求继续有效。
