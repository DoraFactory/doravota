# SDK 0.53：0.4.4 原代码保留复核

日期：2026-09-12。基线 tag `0.4.4`，工作区基于 `917c53b`。本记录是本地纠正，不是发布或主网放行。

## 边界

保留 0.4.4 原有实现，不以当前不用、过时或简洁为理由删除。仅接受锁定依赖的必要接口适配、真实迁移缺陷修复，以及用户已明确批准的配置：默认最低 gas price 10000000000peaka；新增治理 min_deposit_ratio / proposal_cancel_ratio 为 0，快速提案最低押金 110000000000000000000000peaka。旧链已有共识和治理参数原值迁移。此前未获授权的新增 proposal gas/bytes 兜底已移除。

## 已恢复

| 原有代码 | 纠正 |
| --- | --- |
| 0.4.4 upgrade handler | 从基线提取原函数体恢复；只有 context.Context + UnwrapSDKContext 的必要改动，没有空 handler 替代 |
| 0.4.4 import / store-loader | 恢复原导入和空 StoreUpgrades 分支；与 0.5.0 并存 |
| legacy params 治理 | SDK 0.53.6 仍提供 NewParamChangeProposalHandler / paramsclient.ProposalHandler，恢复执行路由及 param-change CLI |
| Ante 验证装配 | 恢复原 errorsmod.ErrLogic 包装、错误文字、装配数组和说明；保留 Wasmd 所需 GasRegister、TxContracts、类型适配与新增依赖非空检查 |
| Wasm capability 列表 | app/wasm.go 恢复为 0.4.4 原文件；不因新版引擎提供可选能力就自动扩大允许的新合约能力集合 |
| Group 配置 / 零高度导出计数器 | 恢复原结构，撤销无 SDK 依据的清理 |
| 历史升级 constants | 撤销无关换行差异 |
| Docker Ledger | Docker 显式启用原 ledger tag，恢复 linux-headers 和旧 GIT_COMMIT 参数兼容；普通 Linux release 原本不含 ledger，其默认不变 |

检查 0.4.4 跟踪文件均存在。这个检查只能证明没有整文件丢失；函数内部差异仍按下表复核，不能把文件存在当作行为完全相同。

## 保留的版本适配与证据

锁定版本：SDK 0.53.6、cosmossdk.io/x/upgrade 0.2.0、IBC-Go 10.5.0、Wasmd 0.61.14、WasmVM 3.0.7。

| 位置 | 保留原因 / 边界 |
| --- | --- |
| app/app.go imports、keeper、store service、ABCI lifecycle | 新版签名、包路径及 ABCI++ 接口；SDK 要求 upgrade/auth PreBlock 顺序，不用旧 BeginBlock 假替代 |
| capability / feeibc keeper、scoped / memory store | IBC-Go 10.5.0 CHANGELOG #7270/#7279/#8002 明确移除 capability / ICS-29；旧类型无法按原 API 接线。存储删除仍受先前约定的状态/余额/版本预检保护 |
| legacy software-upgrade / IBC proposal 的旧执行 handler | cosmossdk.io/x/upgrade 0.2.0 已不导出 NewSoftwareUpgradeProposalHandler；IBC-Go 10.5.0 CHANGELOG #6777 明确移除 NewClientProposalHandler。使用现有 MsgSoftwareUpgrade / MsgCancelUpgrade / MsgRecoverClient / MsgIBCSoftwareUpgrade 路径；不自行发明 legacy 执行兼容层。仍需检查升级边界是否有这类待执行旧提案 |
| GetMemKey / ScopedKeepers | 原本只服务已移除的 capability 内存状态；不是删除业务数据库访问接口 |
| app/encoding.go | SDK 签名接口要求地址 codec / proto resolver；保留 Dora 地址前缀 |
| app/export.go | keeper 改返回 error、地址接口及 collections 访问；保留导出/清零业务步骤 |
| app/module_basics.go、cmd/root.go | SDK 旧静态 CLI 转 AutoCLI，保留可用查询/交易入口；原 config.Cmd、GetAccountCmd、Comet RPC 函数不再按旧接口提供，不从旧 SDK 混入实现 |
| app/upgrades/v0_5_0/* | 新版本独立 handler；旧共识记录原值迁移、空 IAVL 读兼容和升级前预检是已复现的问题修复 |
| cmd/config.go / types/precision.go | sdk math 移包；18 位精度不变；版本标识及 gas price 是已批准变更 |
| cmd/genaccounts.go、testutil/network.go、cmd/main.go | 新返回值、DB / store 路径、移除的 server.ErrorCode 接口适配 |
| app/simulation_test.go | 新 ABCI / context / store API；保留原模拟，隔离 Wasm home/cache，导入显式使用导出共识参数 |
| Docker / release workflow / build script | Go、WasmVM 静态库及架构匹配、旧发布流程修复与候选校验；不取消原 Docker Ledger 能力 |
| go.mod / go.sum | 所选依赖及传递版本变化，不是删业务代码；来源见必要性审查 |

上游参考：[SDK 0.53.6 升级说明](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/UPGRADING.md)、[IBC-Go 10.5.0 CHANGELOG](https://github.com/cosmos/ibc-go/blob/v10.5.0/CHANGELOG.md)、[upgrade v0.2.0 PreBlocker](https://github.com/cosmos/cosmos-sdk/blob/x/upgrade/v0.2.0/x/upgrade/abci.go)。本次也直接核对了本机下载的上述精确依赖源码。

## 验证边界

验证结果追加于下方。旧 RC1 / 前轮本地测试的哈希不得套用本轮新文件。Linux Docker daemon 当前未运行，不能声称最终 Linux Ledger 镜像已完成构建；恢复 tag 和本地 Darwin 编译不等于硬件钱包签名成功。远程隔离网、生产链和 GitHub 均未变更。

### 本轮本地结果

- Go 1.24.7，Darwin/AMD64；`go test ./... -count=1` 通过。
- 三项显式模拟均通过，无 skip：Seed=42，10 blocks，BlockSize=5，Commit=true。
- 0.3.1/0.4.0/0.4.2/0.4.3/0.4.4 完成记录通过实际 SDK PreBlocker 检查，模块版本表未被重复迁移改写；未注册计划的反向样本正常拒绝。
- 0.4.4 handler 函数体去除 context 接口适配后，与基线文本一致；app/wasm.go 与基线逐字节一致。
- legacy params 路由回归及实际 CLI 的 param-change 入口可用。这里不声称旧 x/params 写入会自动更新已迁入各模块的新参数存储。
- 本地 `go build -tags ledger ./cmd/dorad` 通过；没有进行 Ledger 硬件签名或 Linux 镜像构建。
- `git diff --check` 与发布脚本语法检查通过。

本轮源码哈希与日志哈希：[证据清单](sdk-053-baseline-preservation-evidence-2026-09-12.json)。前轮测试曾因反向样本错误地将 handler 设为 nil 而失败：SDK HasHandler 检查的是 map key 是否存在，nil 不等于注销。已改为真实未注册计划样本后重跑通过，未为此改变生产代码。
