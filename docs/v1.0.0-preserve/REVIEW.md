# 1.0.0：SDK 0.55 + 保留 Wasm / IBC 审查记录

## 本轮范围
完成计划 1～3：确定范围、新分支、基础兼容性验证。不代表完成主网快照升级或可发布主网。

- 版本与治理升级名称：1.0.0。
- 保留 Wasm、IBC core、transfer、ICA 运行及原状态。资产清理不阻塞本次升级。
- 关闭新代码上传、Instantiate / Instantiate2、Migrate；已有合约执行、查询和提款路径保留。
- Wasm 模块参数和已有代码实例化权限在 InitChain / 升级时设为 Nobody。
- 共识参数不启用 ML-DSA；默认仍为 Ed25519。SDK 原生 ML-DSA 账户能力可测试，但自定义 x/pqcauth 未合入。
- 模块删除仅涉及 SDK 已移除的 params / group，沿用迁移前的空业务与引用检查；这与删除 Wasm / IBC 不同。

## 分支与来源
新分支：upgrade/v1.0.0-sdk055-preserve。
基线：正式 0.5.0，8a4313d2b338eb5e5090dd5cdfe5b0f54203c426。
复用 SDK 提交 ae00da8 / 803be3b，未从带 PQC 实验的工作区复制代码。
之前的 upgrade/v1.0.0-sdk055-retirement 保留，不作为本方案发布源。

## 固定依赖
| 组件 | 固定版本 / 提交 | 性质 |
|---|---|---|
| Cosmos SDK | 0.55.0 | 正式版 |
| CometBFT | 0.40.0 | 正式版 |
| Wasmd | 0.70.4 + third_party/wasmd-v055-compat | 本地最小兼容及部署限制补丁 |
| WasmVM | 3.0.8 | 官方修复版，禁止回退 3.0.7 |
| IBC-Go | v11.0.0-20260929073332-7b1838a13bc4 | 固定开发提交，不是正式兼容 release |
| Go | 1.26.5 | go.mod 固定 |

IBC 通过 replace 固定到 7b1838a13bc442393253b3b3d995e228a3995855，避免 Wasmd 的 v11.2.0 要求在 MVS 中覆盖该 SDK 0.55 提交。它的伪版本号低于 v11.2.0，不能仅凭数字推断提交先后。依赖来源和校验数据保存在 evidence/。

## 核心审查入口
- app/app.go：模块 wiring、SDK 迁移 handler、Wasm guard 永久启用。
- app/wasm_policy.go：Nobody 权限，不清空合约存储、不转移余额。
- app/upgrades/sdk055/preflight.go：提交计划/高度/版本/旧参数检查；仅 params/group 删除。
- third_party/wasmd-v055-compat/upstream-diff.patch：所有本地 Wasmd 变更。
- app/wasm_policy_test.go：真实 VM 执行、受限部署和余额退出回归。
- app/upgrades/sdk055/preflight_test.go：保留 stores / 在途包的存储回归。
- scripts/build-bridge-release.sh：沿用脚本文件名，内容已改为 1.0.0 与官方 WasmVM 3.0.8。

## 实际验证结果（2026-10-04）
- 最终代码提交：`f06b375f1477f25877cc32e9adedec3307bb437d`。后续提交仅整理审查文档，不改变下列构建源码。
- 远程完整 `go test -p 4 ./... -count=1` 通过，见 [最终测试记录](evidence/operator/tests-final.log)。此前 tests-01 / tests-02 是历史尝试，最终结论以 tests-final 为准。
- 真实 WasmVM：恢复有余额的 hackatom 合约，智能查询通过，release 将 11 个测试单位转给 beneficiary；代码、合约和导出保留。
- 普通及 Gov permission keeper 的 Store / Instantiate / Instantiate2 / Migrate 全部被拒绝。
- SDK 原生 ML-DSA 账户签名与重放拒绝回归通过；共识参数仍为 Ed25519。
- 存储层合成数据：19 -> 17 stores，Wasm / IBC / transfer / ICA 值保留且重启一致；不是实际跨链验收。
- 首次新增 VM 测试缺少 Context 时间而失败；修复测试上下文后通过。原始失败记录保留。
- Linux amd64 构建、`go vet -p 4 ./...`、`go mod verify` 均通过；本地 Wasmd 快照的 114 个文件哈希校验通过。
- 最终程序新链烟测通过：ML-DSA 账户生成 gentx，Ed25519 共识出块至高度 3，提交签名 64 字节；停止后重启至高度 5，状态导出成功。见 [烟测结果](evidence/operator/final-build/smoke-ed25519.json) 和 [构建烟测日志](evidence/operator/build-smoke-final.log)。
- 拒绝缺失保留 store 的数据库反例通过，避免误加载之前移除 Wasm/IBC 的候选数据库。

## Claude 审查资料和构建产物

工作区：`/Users/bun/.codex/worktrees/vota-v1-preserve-modules/doravota`。

远程机器：`amaci-testnet-operator`，本轮根目录：`/root/vota-v1-preserve-20261004/`。
最终审查文档及日志副本统一在远程 `review/docs/v1.0.0-preserve/`；源码归档里的文档是构建前版本，结果以本审查目录为准。审查包为根目录下的 `review-bundle.tar.gz`，同目录有 SHA-256 校验文件。

| 内容 | 位置 / 校验 |
|---|---|
| 最终代码归档 | `source-f06b375.tar.gz`，SHA-256 `0c2420411faf821042d97b29f0af46ce5d6f4951f006dd1ae3ac47471b06430a` |
| 最终源码目录 | `source-f06b375/` |
| 审查二进制 | `source-f06b375/build/dorad`，SHA-256 `f0455c469dfd544d8b833e9039f2a32906044f1a0fa0bb65805e6294413a3b91` |
| 测试尝试、失败和最终结果 | `evidence/`；本地镜像 [evidence/operator](evidence/operator/) |
| 版本、依赖、校验、出块记录 | `source-f06b375/docs/v1.0.0-preserve/evidence/`；本地镜像 [final-build](evidence/operator/final-build/) |
| 构建来源与环境 | [PROVENANCE.json](PROVENANCE.json) |
| 工作与修复记录 | [WORKLOG.md](WORKLOG.md) |

宿主机 Ubuntu 22.04.5 LTS / x86_64；构建和测试在 `golang:1.26.5-bookworm` 容器内完成，每次限制 4 CPU / 12 GiB。宿主机是 Ubuntu 不代表二进制已经通过宿主机直接部署验收。程序动态链接 WasmVM，需配套动态库；**仅供审查，不发给验证人**。

建议优先审查：
1. 与正式 0.5.0 的差异：`git diff 8a4313d2b338eb5e5090dd5cdfe5b0f54203c426 f06b375f1477f25877cc32e9adedec3307bb437d -- app go.mod scripts`。third_party 的体积主要是固定上游源码，Wasmd 本地差异单独见 upstream-diff.patch。
2. Wasm guard 是否覆盖所有共用部署入口；现有合约执行、回调和提款是否保留。当前真实 VM 用例证明普通提款可以运行，不保证每一个业务合约都不依赖实例化或迁移。
3. 0.5.0 升级预检、params/group 删除边界、Wasm/IBC 状态保留及失败时行为。
4. IBC-Go 固定开发提交与 Wasmd 本地兼容补丁的维护成本。基础兼容通过不等于对端协议验收通过。

## 重现入口
基础测试：`go test -p 4 ./... -count=1`。
固定源码之后：`COMMIT_SHA=<40位提交> bash scripts/build-preserve-review.sh`。
此脚本生成 Linux CGO 审查程序，使用模块内动态 WasmVM 库；不是验证人可直接分发的静态发行包。
本轮不声称完整上游 Wasmd 测试通过（本地 snapshot 不包含其 `_test.go`），也不声称开启了默认跳过的长链模拟测试。
发布脚本 / Dockerfile 已更新到公共依赖，但完整静态多架构发行流水线本轮未验收。


## 行为边界与后续必做
1. 执行层限制覆盖治理权限；仅改 Wasm 参数不能重新开放部署。重新开放需二进制升级。任何依赖新实例化/迁移的提款业务须单独核查。
2. Nobody 不是任意合约安全证明；已有合约及回调仍运行在 VM 中。
3. params/group 预检仍可能拒绝真实状态；尤其旧参数与权威模块参数不一致、group 历史/权限引用。主网快照演练要发现并处理，不能绕过。
4. 真实主网快照、多节点、Cosmovisor、同步/恢复、IBC 对端与 relayer、在途包及双向转账均属下一阶段。
5. 不依赖新高度强制切换共识算法；Osmosis 验签适配是后续 PQC 共识启用条件。
6. 不是已发布版本：不上传 GitHub / S3，不操作主网，不分发给验证人。
