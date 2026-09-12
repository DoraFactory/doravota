# SDK 0.53 桥接分支：相对 0.4.4 的必要性与行为变更审查

审查日期：2026-09-12。基线：tag `0.4.4`（`1b0774785111d8a6e693cd155053c19a5a1d8bdc`）。被审版本：`sdk-053-bridge` 的 `917c53b650afdc592873e956b32e41fa720e97a5`。本次修正为该提交之后的本地工作区变更，尚未形成新的发布包或主网放行结论。

本次不是重新设计交易和治理机制。依据是对应版本的接口、迁移实现、原链接线、已复现的兼容问题，以及用户明确批准的政策调整。**上游示例中存在，不等于升级必须启用；不是 SDK 强制项，也不等于没有用途。**

## 结论与本次处理

1. 初始桥接提交混入了额外的提案筛选/拒绝策略和 IBC 可选功能。它们不能统一描述为“SDK 升级需要”。本次移除自定义 proposal 处理器、有限 gas/bytes 参数覆盖、观察参数补齐，以及 transfer/ICA callbacks 和 IBC v2 业务路由。
2. 保留 ABI/API 接线、累积模块迁移、旧共识记录读取、空 IAVL 读兼容和删除前校验。这些分别有上游要求或旧数据库/演练证据。
3. 恢复被漏掉的 `06-solomachine` 类型注册、客户端路由及模块注册；保留 `feeibc` 历史地址的 bank-send 阻止规则，避免移除模块后意外开放收款。
4. 保留用户确认的默认最低 gas price `10000000000peaka`。升级迁移中设置 `min_deposit_ratio=0`、`proposal_cancel_ratio=0`、快速提案押金 `110000 DORA`，保留旧治理字段。
5. 新的必要性边界不替代最终候选版的快照演练。IBC 接线和治理结果已经变化，旧 RC1 的 IBC/Wasm/重启结果不能直接算作本次代码通过。

## 版本依据

本分支实际使用：SDK `0.53.6`、CometBFT `0.38.21`、IBC-Go `10.5.0`、Wasmd `0.61.14`、WasmVM `3.0.7`、Go `1.24.7`。前四个执行依赖以及 WasmVM 与 Wasmd `v0.61.14/go.mod` 声明的一致；不是将 roadmap 后续的 SDK 0.55 / CometBFT 0.40 提前混进本次升级。

主要可复核依据（均固定版本）：

- [SDK v0.50.15 UPGRADING](https://github.com/cosmos/cosmos-sdk/blob/v0.50.15/UPGRADING.md)：覆盖跨越 0.47→0.50 的 ABCI、PreBlock、KVStoreService、AutoCLI 和模块拆包要求。
- [SDK v0.53.6 UPGRADE_GUIDE](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/UPGRADE_GUIDE.md)：auth PreBlock 为必需；protocolpool、epochs、unordered transactions 为可选。
- [SDK v0.53.6 BaseApp 构造](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/baseapp/baseapp.go)及[默认 proposal 实现](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/baseapp/abci_utils.go)。
- [SDK v0.53.6 gov 4→5 迁移](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/x/gov/migrations/v5/store.go)及[治理参数约束](https://github.com/cosmos/cosmos-sdk/blob/v0.53.6/x/gov/types/v1/params.go)。
- [IBC-Go v10.5.0 中的 v7→v8 迁移文档](https://github.com/cosmos/ibc-go/blob/v10.5.0/docs/versioned_docs/version-v10.1.x/05-migrations/11-v7-to-v8.md)和[v8.1→v10 文档](https://github.com/cosmos/ibc-go/blob/v10.5.0/docs/versioned_docs/version-v10.1.x/05-migrations/13-v8_1-to-v10.md)。目录名虽为 version-v10.1.x，读取的是 v10.5.0 tag 中的内容。
- [Wasmd v0.61.14 go.mod](https://github.com/CosmWasm/wasmd/blob/v0.61.14/go.mod)、[应用接线](https://github.com/CosmWasm/wasmd/blob/v0.61.14/app/app.go)、[ante 实现](https://github.com/CosmWasm/wasmd/blob/v0.61.14/app/ante.go)、[版本变更](https://github.com/CosmWasm/wasmd/blob/v0.61.14/CHANGELOG.md)。其 UPGRADING.md 仍大量使用旧版演示，不能仅凭那个演示判断 0.61 的全部要求。

## 是何时加入的

[逐文件提交来源 CSV](sdk-053-change-provenance-2026-09-12.csv)列出 `0.4.4..917c53b` 全部 376 个文件的新增/修改状态、首次桥接提交、最后提交和 Git 作者时间，跨目录改名使用 `git log --follow`。

376 个文件中：338 个为文档/演练证据，19 个为节点/CLI 文件，9 个为依赖或构建发布文件，8 个为测试，2 个为独立离线工具。文件数量或 30 万行增量不能等同于新增了同等规模的节点运行代码。CSV 是已提交历史清单；本次新增/删除见本文结论和工作区 diff。

| 提交 | Git 记录时间（UTC+8） | 内容与归属 |
|---|---|---|
| `6d03e3b` | 2026-08-13 19:00:55 | 初始桥接：依赖升级、应用/CLI 适配、proposal.go、callbacks/v2 接线、旧共识读取、初版空树兼容、默认 gas price 变化等 |
| `c980a75` | 2026-09-12 11:02:06 | 后续兼容修复、删除前保护、模拟/CLI 修复、离线工具、执行文档与 RC/CI 材料集中提交 |
| `c74cb37` / `e6e392e` / `c529f8d` | 2026-09-12 11:08–11:18 | 容器 VCS stamping、Linux 原生双架构校验、runner 输出目录权限修复 |
| `ea0e83f` | 2026-09-12 11:34:34 | RC1 验收证据及固定产物记录 |
| `917c53b` | 2026-09-12 12:06:33 | 目录/包名 `v0_5_0`、链上计划 `0.5.0` 及相应文档测试 |

Git 能证明内容在哪个提交出现；不能单凭 author 字段证明具体是哪位人员或哪个 AI 首次编写，也不能将提交时间说成精确的编辑时间。初始提交将必需适配和可选策略混在一起，没有逐项记录政策授权，这本身是审查可追溯性的不足。后续提供正面测试也不能倒推最初已有业务授权。

## 逐项必要性判断

| 文件/改动 | 相对 0.4.4 | 判断与依据 | 本次处理 |
|---|---|---|---|
| `go.mod` / `go.sum` 执行栈升级 | 修改 | 所选 Wasmd/SDK/IBC API 的匹配依赖；不能仅更新两个版本号 | 保留版本，不追加新模块、不盲目调整传递依赖 |
| `app/app.go` Keeper、StoreService、codec、模块签名 | 修改 | 0.50 起接口变更及对应 v10 Keeper 签名 | 保留 |
| `PreBlocker`、upgrade/auth 排序 | 新增 | 分别由 SDK 0.50 和 0.53 迁移要求明确规定 | 保留；修正误写成 v0.55 的注释 |
| `app/ante.go` GasRegister、TxContracts decorator | 新增适配 | 与 Wasmd 0.61 的 gas 上下文/交易内合约追踪配套 | 保留；未照搬示例的 circuit 模块 |
| `app/encoding.go` SigningOptions / 地址 codec | 修改 | 新版签名提取依赖显式地址 codec | 保留 |
| `root.go` 先设置 dora 前缀，再构造 registry | 修改 | 修复捕获默认 cosmos 前缀的问题 | 保留 |
| `app/module_basics.go` / AutoCLI | 新增 | 新 SDK 查询依赖 AutoCLI；静态 BasicManager 需提供 CLI 地址 codec | 保留；不是新增链上模块 |
| `root.go` ICA register 的 version flag 隔离 | 新增修复 | Comet 配置 version 与 ICA 协议 version 同名，已在 CLI 验收复现 | 保留 |
| `app/export.go`、genaccounts、main、testutil、precision | 修改 | 返回 error、context、store/math/DB 包路径、移除的 server.ErrorCode 等适配；10^18 精度未改 | 保留 |
| 移除 capability 和 fee middleware | 删除旧接线 | IBC v10 明确移除；capability 授权机制由新路由体系代替 | 保留迁移删除，但保留删除前 fee 状态/余额保护 |
| `legacy_consensus.go` | 新增 | 0.4.4 keeper 错接 upgrade store，真实记录在 `upgrade/Consensus` | 保留原值读取，不用 genesis 默认替换治理后的值 |
| `legacy_empty_iavl.go` | 新增 | 旧空 root 与 missing key 被 DB API 混同；新旧空树重启读兼容已有回归 | 保留；不制造缺失 root、不写状态 |
| `preflight.go` | 新增保护 | 在 StoreLoader 删除旧 store 前检查实际已提交状态及源 schema | 保留；增加已批准治理政策的兼容性检查 |
| `app/proposal.go` 自定义 Prepare/Process | 新增策略 | SDK 已提供默认实现；没有必须加 100M fallback、拒绝 zero gas/整块 ante 的要求 | 删除文件和原策略专属测试，改用实际 BaseApp 行为回归 |
| InitChainer / upgrade 的 finite gas/bytes 覆盖 | 新增政策 | `-1`、`0` 不能仅因非正就重写；正数未改不代表行为等价 | 删除；源共识参数原值迁移 |
| 从当前 context 补齐 consensus 字段 | 新增后备 | 已有完整旧记录且有校验；部分观察值不应再成为另一套参数来源 | 删除该后处理 |
| ICA controller Keeper 赋值及路由 | 新增可用行为/修复 | 0.4.4 构造了局部 controller Keeper 和栈，但未赋给 App 字段、未挂 controller 路由；不能说此前控制端功能完全相同 | 保留已修复的接线和前轮 ICA 验收范围，明确它是兼容修复而非所有链都必须添加的功能 |
| transfer / ICA callbacks middleware | 新增功能 | 上游提供按需使用；0.4.4 实际路由没有此合约回调功能；memo 解释及失败行为会改变 | 移除额外包装，保留直接 ICS-20/ICA 及原有 wasm IBC handler |
| IBC v2 transfer / wasm prefix routes | 新增功能 | v10 文档使用“增加 v2 支持时”这一条件，不是保留 v1 业务的强制项 | 取消业务路由；保留非 nil 空 router；不再向 Wasm 声明 `ibc2` capability |
| 06-solomachine 注册 | 原功能被漏删 | 0.4.4 有类型注册；v10 要显式注册客户端实现，否则 allowed_clients 保留也可能 route not found | 按 v10 接口恢复；不是新增客户端政策 |
| feeibc 历史模块地址 | 原限制被漏删 | 删除 maccPerms 后原地址不再 blocked，普通发送可能进入无法正常使用的旧地址 | 保留历史 auth 账户，恢复 bank-send blocked，未赋予新模块权限 |
| `min-gas-prices` 降至 1e10 peaka | 修改默认配置 | 非 SDK 强制；用户本轮确认与 validator 本地配置对齐 | 保留；不写入链上参数、不覆盖现有 app.toml |
| 新治理字段 | 上游迁移新增 + 明确政策 | 字段由 SDK gov 4→5 加入，值可由升级 handler 设置 | 只覆盖已授权的两个比例和 11 万 DORA；其他值见下表 |
| protocolpool / epochs / unordered tx / PQC / Sponsor | 无新增接入 | SDK 部分功能是可选，PQC 属后续阶段 | 继续不接入 |
| `scripts/build-bridge-release.sh` / CI / Docker | 新增或修改工具 | Go/WasmVM/静态链接必须匹配实际二进制；共享脚本减少两套构建命令漂移 | 保留；不作为链上逻辑运行 |
| `cmd/store-report`、`cmd/store-compare` | 新增独立程序 | 用于升级前后状态取证，不在 dorad 启动路径 | 保留，仅对停机副本使用；不是零风险在线查询工具 |
| 模拟测试、upgrade name 测试 | 新增/修改测试 | 修复共享 Wasm cache、非确定 seed/chain-id、CLI 注册及名称边界 | 保留；模拟导入现在显式传入导出的共识参数 |
| 历史 0.4.x constants.go 的文件尾换行 | 纯格式修改 | 不属于版本迁移需要 | 恢复基线内容，消除无意义的基线 diff |
| 已过时的 capability / GetMemKey / params 删除注释 | 遗留说明 | 与实际代码不符，增加误判 | 清理/修正；params 本次没有删除 |

此处原先记录的是较早的中间方案，已被同日的基线保留复核纠正：当前 `app/wasm.go` 已恢复为 0.4.4 原文件，并作为实际能力声明入口；没有自动扩展到新版 Wasmd 的可选能力集合。以 `sdk-053-baseline-preservation-2026-09-12.md` 和 `sdk-053-config-review-2026-09-12.md` 的最终工作区记录为准。

### msgpack replace 的依据

初始提交将 `github.com/shamaton/msgpack/v2` 替换到 `04a026e9ac24`。该提交是上游 [ext frame bounds validation 回补](https://github.com/shamaton/msgpack/commit/04a026e9ac24527f593a30258a98884768ec0e52)，修改截断 ext 帧在解码器中的边界校验，附有回归测试。`go mod why` 显示应用 → Wasmd → WasmVM types → msgpack 的真实依赖路径。

这不是 SDK 强制的接线项，但有具体的输入处理安全依据，因此保留，并在 go.mod 标注来源。不能因为是额外 replace 就去掉，也不能把保留它解释成整个依赖树已完成安全审计。

### 不应混淆的 proposal

删除的是 **ABCI 区块提议处理器** `app/proposal.go`，不是删除治理提案功能。治理继续由 SDK `x/gov` 处理。

原 0.4.4 的 BaseApp 默认 NoOp mempool 在 ProcessProposal 阶段接受区块提议，执行阶段仍验证交易。现在使用 SDK 0.53.6 的默认同类接线，不再自行增加 100M 上限。SDK 0.53 的 PrepareProposal 已经会解码并按声明 gas 筛选；这与 0.47 的默认实现仍存在上游行为差别，不能承诺每笔交易的打包顺序或 gas 消耗完全等同。

升级首块前新 consensus store 可能为空，SDK 默认 PrepareProposal 不会自行发明 100M cap。CometBFT 仍持有旧共识参数；升级在 PreBlock 中迁入旧参数后，BaseApp 会更新执行 context 和 block gas meter。是否实际完成首块、回放、重启，仍需在最终包的新快照演练中验证，单元测试不能替代。

## 治理参数：本次授权范围

| 参数 | 本次迁移后的来源/值 |
|---|---|
| `min_deposit_ratio` | `0.000000000000000000`；不再新增每次缴款比例门槛 |
| `proposal_cancel_ratio` | `0.000000000000000000`；取消扣费为 0，交易本身 gas 费用不因此免除 |
| `expedited_min_deposit` | `110000000000000000000000peaka` = 110,000 DORA × 10^18 |
| 普通 `min_deposit` | 完整保留旧值，不被快速押金替换 |
| `max_deposit_period` / `voting_period` | 保留旧值 |
| `quorum` / `threshold` / `veto_threshold` | 保留旧值 |
| `min_initial_deposit_ratio` | 保留旧值；与此次设为 0 的 min_deposit_ratio 是不同字段 |
| 三个旧 burn 参数 | 保留旧值 |
| `expedited_voting_period` | SDK 新字段默认 24 小时，本次未另行变更 |
| `expedited_threshold` | SDK 新字段默认 0.667，本次未另行变更 |
| `proposal_cancel_dest` | SDK 新字段默认空；取消比例为 0 时没有此项扣费可烧毁/转出 |

只在 `0.5.0` 升级 handler 的 RunMigrations 后写入批准值，不修改 SDK 全局默认常量。新建 genesis、已升级完成的旧演练数据库不会仅因换二进制就自动套用这些值。后续调整可以通过正常的治理参数更新流程进行。

SDK 校验要求快速押金高于普通押金、快速周期短于普通周期、快速阈值高于普通阈值。代码不会为了满足它们而降低旧普通押金、缩短旧投票期或修改旧阈值。删除前保护现读取旧 gov 参数，预检与已批准政策是否兼容；测试确认预检成功/失败都不写 DB。历史演练中的 60 秒普通投票期与一天快速投票期冲突，必须在演练准备阶段明确处理。**主网放行前必须针对 H−1 的真实参数重查；不能等到 H 才发现配置冲突。**

## 本次验证与边界

本次本地 Go 1.24.7 / darwin-amd64：

- `go test ./... -count=1`：通过。
- 显式启用 `TestAppStateDeterminism`、`TestAppImportExport`、`TestAppSimulationAfterImport`，Seed=42、10 blocks、BlockSize=5、Commit=true：三项通过，未将 skip 计为通过。
- 实际注册的 BaseApp Prepare/Process：目标 consensus store 为空、旧 gas=-1、gas=600M 三种情形；150M 交易不会再因 bridge 100M cap 被排除；600M 下正确限制声明 gas 总量。
- 实际 InitChain：-1、0、600M 的源参数原值保留；有效的验证人 genesis，没有改运行代码来迎合缺省测试数据。
- 实际 SDK gov `Migrate4to5` 后应用批准参数并重新读取：三个批准值准确，全部十个旧字段逐项一致，包括不同于默认值的 burn 配置。
- 110k 普通押金、60 秒普通投票期、0.75 普通通过阈值等冲突样本：明确报错，源对象未被改写。
- IBC 接线/能力测试：恢复 solo 路由；直接 transfer、ICA、wasm v1 路由保留；无 callbacks 包装、无 v2 业务端口/ibc2 capability；feeibc 地址继续 blocked。
- 原有 fee store、空 IAVL、共识缺失/损坏、源版本及只读预检回归继续通过；新增 gov 缺失/冲突的只读预检样本。
- 保留的 msgpack 回补：上游两个截断 ext 帧回归测试通过。

命令、结果摘要及修改后源码哈希见 [本地验证记录](sdk-053-necessity-review-evidence-2026-09-12.json)。

以上不等于本次新源码已经完成 Linux 两架构构建、最终包快照升级、全部旧 IBC 通道端到端、真实 Groth16 业务和 24 小时稳定性验收。正在运行的旧演练环境未被替换。下一份 RC 必须固定新 commit/哈希，不能覆盖旧 RC1 的身份。

## 仍需公开说明的差异和放行项

1. **Wasm 执行/gas 变化属于上游版本行为。** 保留共识 max_gas 不等于每次合约执行收费不变。旧新 gas register/VM 的计价尺度都有变更，不能只比较一个 multiplier 就推算业务贵了多少倍。真实处理/计票/结算/领取需按最终包在长期测试网验收。
2. **IBC 仍需重新演练。** 本次减少了可选包装，不能引用旧包装状态下的测试说新接线已经端到端通过。旧 channel-16 的 wasm IBC 路由仍保留；其业务未活跃不构成删除该路由的理由。
3. **0.4.4 历史 handler 已恢复（后续纠正）。** 初始桥接误删了原有注册；现已恢复原函数体、import 和空 StoreUpgrades 分支，只将 context 签名适配新 SDK。增加真实 SDK PreBlocker 回归，检查各历史计划的完成记录可被识别且不重复迁移。原始 0.4.4 快照的最终包切换仍须另行验收。
4. **Docker Ledger 编译配置已恢复（后续纠正）。** Docker 再次显式传入 ledger tag，并保留旧 GIT_COMMIT 构建参数；普通 Linux release 默认 tags 不变。需对最终 Linux 容器实际构建及冒烟；本地 Darwin ledger 编译不能代替 Linux 或硬件钱包签名验收。
5. **离线取证程序。** LevelDB 打开方式不是操作系统强制只读，必须对停机副本运行。未因它们“不是业务功能”就删除必要的状态比对能力。
6. **依赖审计边界。** 已核对执行依赖匹配、关键迁移及显式 replace；没有声称对所有第三方库每一行源码都完成漏洞审计。类似 `zkvm_runtime` 名称出现在传递依赖，不代表本链接入了 zkVM/PQC 共识模块。

后续主网放行应以本次政策边界下的新候选包为准，重新执行执行方案中的快照升级、状态比对、IBC/Wasm 业务、重启恢复和稳定性门槛。

## 后续纠正：保留 0.4.4 原有代码

用户再次明确：不以整理、过时或当前不用为由删除原有代码。历史 handler、legacy params 治理路由及 CLI、Wasm capability 原始列表、Ante 错误与装配结构、Docker Ledger 配置已恢复。具体项目和保留的必需适配见 [原代码保留复核](sdk-053-baseline-preservation-2026-09-12.md)。本文件前述本地测试及 JSON 是纠正前的历史证据；最终文件哈希与新验证结果须使用新的复核记录。
