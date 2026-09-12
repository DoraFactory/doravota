# sdk-053-bridge 升级安全审查

审查日期：2026-09-10。目标：判断从 0.4.4 升级该桥接版本的风险及放行条件。

## 结论

> 2026-09-10 主网补充核查：高度 17,236,364 的 feeibc store 经根证明验证为空，模块余额为零，F1 的现存手续费资金条件在该高度未触发；capability 有 21 条权限记录，包含 OPEN 的 ICS-721 合约通道。详见 [主网存储核查](mainnet-store-check-2026-09-10.md)。这不改变其余上线阻断项，也不替代升级前再次检查。

**当前不建议安排主网升级高度。** 当前版本有已复现的数据库兼容入口问题、未处理的条件性 IBC 手续费资金风险、过时的发布流水线，以及未通过的确定性模拟测试。它可以继续作为修复和隔离演练的基础，不能仅凭普通测试通过就作为生产升级候选。

这是一轮针对代码差异、升级路径、依赖接口和本地测试的工程安全审查，不是第三方安全认证，也不意味着已证明不存在其他漏洞。本轮没有取得并验证真实主网升级前快照、全部部署合约、IBC 通道/手续费清单、验证人机器配置或正式 Linux 发布产物；因此不对这些状态作安全保证。

## 审查基线

- 仓库：DoraFactory/doravota。
- release `0.4.4`：`1b0774785111d8a6e693cd155053c19a5a1d8bdc`。
- 分支 `sdk-053-bridge`：`6d03e3b7f80b485cbc2e10665657056e8613e5de`。
- 共同祖先就是上述 release；桥接代码相对它改变 25 个文件，增加 2528 行、删除 902 行。
- 本轮新增审计报告、测试日志和一项兼容性问题复现测试，未修改生产实现，未提交或推送。
- **链上升级计划名仍是 `sdk-v0.53-bridge`**。Git 分支名 `sdk-053-bridge` 不是链上计划名，Cosmovisor 目录必须与实际计划名一致。

## 最大变化是什么

这不是只改 Cosmos SDK 和 CometBFT 的版本号，而是跨多个主版本的执行栈和状态格式迁移。

| 部分 | 0.4.4 | 桥接版 | 实际影响 |
|---|---|---|---|
| Cosmos SDK | 0.47.17 | 0.53.6 | 模块存储、参数、交易入口和应用接线迁移 |
| CometBFT | 0.37.5 | 0.38.21 | ABCI++ 接口、提案验证和执行生命周期变化 |
| IBC-Go | 7.3.0 | 10.5.0 | 移除 capability、ICS-29 fee，修改 IBC/ICA 接线并启用新接口 |
| Wasmd | 0.43.0 | 0.61.14 | 合约执行集成、参数与存储迁移 |
| WasmVM | 1.5.1 | 3.0.7 | 原生库 ABI、缓存和执行环境变化 |
| Go | 1.19（模块声明） | 1.24.0（模块声明） | 构建工具链变化 |
| 状态数据库 | 旧 IAVL/数据库接口 | IAVL 1.x、cosmos-db | 旧空树根读取和重启兼容性需要专门处理 |

保留了 `dora` 地址前缀、18 位精度以及 `10^18` 验证人权重换算；没有在该桥接分支加入 PQC 账户、PQC 签名或 PQC 验证人共识。**它是后续 PQC 的基础设施准备阶段。**

## 发现与处理要求

### F1｜高｜删除 feeibc 存储前没有处理未结算手续费

证据：`app/app.go:1246` 的 StoreUpgrades 删除 `capability` 和 `feeibc`；旧版接入 ICS-29，桥接版去掉 fee keeper/module/账户权限。升级 handler（1157 行起）只做共识参数处理和 RunMigrations，没有看到手续费退款、保留映射或空存储前置检查。

旧 IBC-Go 7 的 `modules/apps/29-fee/keeper/escrow.go` 先把币转入模块账户，再将 packet、退款地址及分配数据写入 fee 存储。移除后通用 RunMigrations 不会替一个已经不在 ModuleManager 中的旧模块完成退款。

**触发条件：升级时仍有 ICS-29 费用托管记录或相关未结算业务。** 后果是当前状态中的费用归属/退款记录被删去，正常结算路径消失，余额可能滞留。不能把它表述成 bank 总供应量自动减少，也不能把手续费托管与 ICS-20 转账本金托管混为一谈。本轮尚未确认主网是否实际使用过 ICS-29。

当前规避：没有专门保障；上游要求移除旧模块，并不证明你们链上的旧费用已经清零。

放行条件：在 0.4.4 上完整导出 fee 状态、模块账户全部币种余额、关联未完成 packet；有余额/记录则先设计并演练确定性的结算或迁移。若证明未使用，也要保存可重复的零状态证据，并考虑失败即中止的检查。**旧 store 在加载阶段即被删除，因此不能简单在当前 handler 内追加读取已删除 store 的退款逻辑。** 必须调整迁移顺序/保留方案或先在旧版本完成结算。

### F2｜高｜空 IAVL 树兼容依赖本地 upgrade-info.json，已复现读取失败

证据：`app/upgrades/sdk_v053_bridge/legacy_empty_iavl.go:32` 起，文件不存在或计划名不是桥接名时直接返回原始 DB；兼容视图只在特定本地文件条件下开启。

新增测试 `TestAuditLegacyEmptyRootDependsOnLocalPlan` 使用真实 GoLevelDB、相同的高度 9 旧格式空树根验证：

- 桥接计划文件存在：可以加载。
- 文件缺失：`version does not exist`。
- 文件换成下一升级计划：`version does not exist`。

这是兼容层入口的可复现问题。它证明该状态样本对文件有依赖；没有把样本误称为已经复现了整条主网的升级后 halt。风险集中于恢复旧快照、遗漏本地文件、仍保留相关旧空树根时换计划或再次启动。若足够多验证人同时无法启动，会影响全链活性。

当前规避：空根兼容视图本身不改写数据，并验证升级边界空根，方向正确；但它的启用条件仍脆弱。

放行条件：让需要的兼容行为不依赖一个可被替换的临时计划文件，同时保留坏数据库拒绝加载的保护；加入升级后实际多次提交、停止重启、删除/替换计划文件、快照恢复、导出和不同数据库布局的集成测试。不能以删除 application.db、重置链或忽略哈希错误来绕过。

### F3｜高（发布阻断）｜发布流水线仍使用 WasmVM 1.5.1 和旧 Go 配置

证据：`.github/workflows/release.yml:36` 固定 Go 1.22，60 行指定 `WASMVM_VERSION=v1.5.1`，后续以 muslc/static_build 构建；但 go.mod 要求 Go 1.24 和 WasmVM v3.0.7。

原生库主版本不匹配可能直接导致链接失败；即使某个本地环境构建成功，也不能证明流水线将产生可用 Linux 二进制。Go 自动工具链下载可能缓解 Go 版本差异，但不能解决旧 Wasm 原生库问题。本轮未在 Linux 执行该 release 工作流，因此不编造具体链接错误。

当前规避：没有同步到该分支的发布配置。现有 SHA256 步骤只描述产物完整性，不能证明 ABI 正确。`ldd ... || echo statically linked` 也无法区分所有失败原因。

放行条件：固定匹配的 Go、WasmVM 和构建镜像/工具链，校验下载成功及原生库哈希；真正运行 Linux AMD64/ARM64 产物的启动、重启及旧合约执行测试，并让验证人使用同一已验证产物。发布 tag 规则只匹配数字版本，不能假定使用分支名作为 tag 就会触发发布。

### F4｜中｜ICA controller 重复包装

证据：`app/app.go:593–594` 连续两次 `NewIBCMiddlewareWithAuth`，内层没有真实 auth 应用，外层又把内层作为 auth 应用。IBC-Go 10 的官方迁移示例改为单次 `NewIBCMiddleware(keeper)`。

上游 middleware 在 `IsMiddlewareEnabled` 为真时会转调下层 callback，所以这个结构会使部分 keeper 回调重复执行。实际是否造成错误取决于链上 middleware 标记、通道状态及回调；本轮**没有证明所有 ICA 握手都会失败**，也没有证明这是全链 halt。

当前规避：没有覆盖重复调用的测试。

处理：按实际鉴权模型改成单个 controller 层；回归测试现有 ICA 账户、重新注册、握手、ack、timeout、关闭通道和 callbacks。必须同时检查旧状态 middleware 标记，不能只测试新 genesis。

### F5｜中（验证缺口）｜启用确定性模拟后因 Wasm 缓存锁中断

普通 `go test ./...` 通过，但三个模拟测试默认受 Enabled 标志控制，会跳过。主动运行确定性测试：

```sh
go test ./app -run '^TestAppStateDeterminism$' -Enabled=true -NumBlocks=10 -BlockSize=5 -Commit=true -count=1 -timeout=180s
```

结果：首轮模拟走到高度 11，后续应用实例创建时报 `could not lock exclusive.lock. Is a different VM running in the same directory already?`。测试多个实例共享默认 node home，WasmVM 3 的独占目录锁使测试无法完成重复比较。

这是测试设施问题及缺失证据，**不是已经证明相同区块产生不同 AppHash**。当前不能说确定性回归通过。

处理：为每个实例隔离 home/cache，正确关闭资源，保持相同输入、chain ID、时间和 seed 进行可比的多次执行；修复后重新运行确定性、导入导出和模拟套件。再增加真实旧快照迁移后的多节点 AppHash 对比。

### F6｜中（政策变化/回归风险）｜新增提案校验与有限区块预算

证据：`app/proposal.go`。PrepareProposal/ProcessProposal 新增 ante 验证、交易 gas 非零要求、总 gas/字节预算与溢出保护。缺失或非正 MaxGas 转成 100,000,000，缺失或非正 MaxBytes 转成 21 MiB；明确为正的原参数保留。

它限制了无上限区块资源消耗，但也改变了过去无限预算链的实际吞吐，以及某些交易被纳入提案的条件。大型合约操作、同账户连续交易、依赖前面业务状态变化的交易、过期授权、无效签名和 gas 边界需要真实交易回放。新代码不只是编译适配。

已看到的保护：长度/总 gas 限制、uint64 溢出检查、非法交易拒绝、签名/序列号/费用 ante 校验。SDK 默认最低手续费检查限制在 CheckTx，本轮没有发现仅因为节点 min-gas-prices 不同便确定导致 ProcessProposal 分歧的证据。

缺失：本分支原 proposal_test.go 仅测试共识参数补齐，没有对以上提案输入做完整回归。当前默认 min-gas-prices 还从 100000000000peaka 降到 10000000000peaka，属于新配置的费用政策变化；已有 app.toml 不因此自动重写。

### F7｜高（上线验证阻断）｜缺少真实源状态及升级后业务一致性证明

handler 接受 fromVM 并执行累计 RunMigrations，但没有看到对预期 0.4.4 module version map 的严格前置校验。共识参数使用专用旧记录、x/params 后备及观察参数补齐，损坏记录会返回错误，属于有益保护；源状态确实缺失与意外不兼容仍须在生产快照上辨别。

SDK、IBC、Wasmd 的累计迁移注册并不等同于每一个历史链上对象已经被验证。本轮未检查生产余额、委托、合约、通道与参数清单，不能批准“所有状态不会丢失”。

放行条件：固定快照高度和校验和，验证 module version map，导出所有核心状态的业务清单。升级后检查账户余额/总供应、模块余额、staking pools/委托/解委托、验证人权重及签名信息、distribution、gov、authz、feegrant、IBC clients/channels/packet/托管本金、Wasm bytecode/contract state/pinned code 与真实业务交易。

不要要求迁移前后 AppHash 相同：存储格式变化可以合法改变哈希。应要求不同新节点在同一高度、同一输入下哈希一致，并逐项验证业务不变量和预期迁移差异。

## 本轮测试证据

| 检查 | 结果 | 能证明的范围 |
|---|---|---|
| `go test ./app/... ./cmd/dorad/... ./types/... -count=1` | 通过 | 选定包编译及默认开启测试 |
| `go test ./... -count=1` | 通过 | 整个分支包编译及默认开启测试；不是完整模拟验证 |
| 新增本地计划文件依赖复现测试 | 通过，复现缺失/替换文件时加载失败 | F2 的 GoLevelDB 旧空树样本 |
| 显式启用确定性模拟 | 失败，Wasm cache exclusive.lock | 首轮执行成功，重复比较未完成 |
| 主网快照升级、多节点停机恢复 | 本轮未执行 | 仍是上线阻断项 |
| Linux 正式发布产物与部署合约兼容 | 本轮未执行 | 仍需 CI 与实际产物验证 |

日志：同目录 `sdk-053-bridge-tests.log`、`sdk-053-bridge-simulation.log`。本轮没有做全依赖 CVE 扫描、原生 WasmVM 源码审计、长时间 fuzz 或独立第三方审计，不能将本报告解释为这些检查已通过。

## 升级时最可能遇到什么

1. 制作发布包时先被旧原生库/构建环境卡住。
2. 到升级高度因源参数、模块迁移或数据库兼容问题停止；升级日志成功也还要验证后续块。
3. 恢复出块后部分旧合约、跨链通道、ICA 或 relayer/客户端接口不兼容；链继续出块不等于业务正常。
4. 首次升级成功，但后续重启/换机/恢复快照才暴露本地文件、缓存或数据库问题。
5. 资源峰值超过节点承受能力，迁移时间过长造成验证人启动时间不一致。

这些是基于变更面的排查优先级，不是有生产样本统计支持的故障概率排序。

## 按什么顺序放行

1. 先处理 F1–F5；固定共识预算和手续费政策；补齐源 module version map/参数检查及提案边界测试。
2. 修复 release 构建，固定候选 commit、工具链、原生库和可下载产物哈希。
3. 用真实主网快照在隔离网络演练 0.4.4 → 桥接版，保留旧数据库完整备份；使用隔离测试验证人密钥，绝不让主网签名密钥同时在线签名。
4. 同一升级高度测试至少多个验证人：跨过升级高度、连续出块、逐高度 AppHash 一致、代表性真实业务、恶意/边界交易、掉线再加入、两次重启、快照恢复、资源峰值。包含不同 min-gas-prices 和实际部署架构组合。
5. 逐项核对升级前后业务清单。对 intentionally deleted stores/参数变化给出允许差异，其他差异必须解释。
6. 再演练失败恢复。记录升级前已签名高度、数据库提交高度和 Comet 状态，制定一致的停机/恢复方案；达到放行标准后才提出主网升级高度。

## 回滚边界

升级停机本身可以是计划行为，**无法恢复出块**才是需要处置的问题。迁移错误返回、启动失败与已经提交新状态是不同阶段。

不要在新版本已经提交状态后直接换回 0.4.4 读取同一个数据库，也不要假定迁移失败就一定没有任何磁盘改动。恢复必须匹配 application/Comet 数据与签名状态；不能通过回退 priv_validator_state 或让两台机器共用私钥继续签名来“解决”。实际主网恢复策略须由验证人协调并在隔离环境预演，保留足够日志与快照用于核对。

## 上游参考

- [IBC-Go 10 迁移指南（固定 v10.5.0）](https://github.com/cosmos/ibc-go/blob/v10.5.0/docs/docs/05-migrations/13-v8_1-to-v10.md)：移除 fee/capability、ICA middleware 接线。
- [旧版 ICS-29 费用托管实现](https://github.com/cosmos/ibc-go/blob/v7.3.0/modules/apps/29-fee/keeper/escrow.go)：费用余额和 packet 退款映射之间的关系。
- [IBC-Go 10 ICA middleware](https://github.com/cosmos/ibc-go/blob/v10.5.0/modules/apps/27-interchain-accounts/controller/ibc_middleware.go)：条件性下层回调。
- [Wasmd 0.61.14 Wasm keeper](https://github.com/CosmWasm/wasmd/blob/v0.61.14/x/wasm/keeper/keeper_cgo.go)：原生 VM 与缓存初始化。

这些实现均对照本地固定版本 module cache 阅读；网页不是用未固定主分支替代目标依赖。
