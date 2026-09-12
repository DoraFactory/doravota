# SDK 0.53 分支复核与配置变更清单

日期：2026-09-12。基线为 `0.4.4`（`1b0774785111d8a6e693cd155053c19a5a1d8bdc`），审查对象为 `sdk-053-bridge`、HEAD `917c53b` 加当前本地修改。不是只审 HEAD，也不是对历史 RC 包重新出具放行结论。

## 结论和修改边界

本轮没有发现需要重新设计交易提议、治理或 IBC 业务机制的理由。此前恢复的旧 handler、Wasm 能力声明和原有参数保留逻辑继续保留。仍有配置兼容及依赖安全事项需要处理，不能称为“全部无问题，可直接上主网”。

本轮唯一生产代码修改：在 `cmd/dorad/cmd/root.go` 的真实节点构造路径补上 SDK 原生 `baseapp.SetQueryGasLimit`。新版已有配置和命令行选项，但 Vota 手动组装 BaseApp options 时漏接，导致运营者配置查询限额也不生效。默认 `0` 不变；没有修改交易 gas、共识参数或业务规则。新增回归测试通过真实 appCreator、初始化和提交区块后读取查询 context，验证有限值与不限额默认值。

其余新增内容是本复核文档、配置差异和测试证据；没有替换其他依赖版本，没有操作远端测试网、主网、GitHub 或发布包。

继续适用的边界：

- 保留 0.4.4 原有代码；不能因为旧、不常用、格式不统一而删改。
- 允许所锁定 SDK/IBC/Wasmd 的必要接口与迁移适配，以及有具体证据的安全/兼容修复。
- 可选功能不因出现在上游示例中就自动启用。本分支未接入 protocolpool、epochs、unordered transactions、PQC、IBC callbacks 或 IBC v2 业务路由。
- 保留用户已批准的最低 gas price，以及三个新增治理字段的指定值；已有链上参数按源链记录迁移。
- `app/proposal.go` 是桥接阶段新加的文件，0.4.4 没有它；此前删除它是撤销额外策略，不是删除 0.4.4 业务代码。

## 本轮发现与仍需处理的事项

| 编号 | 优先级 / 状态 | 发现、影响与处理边界 |
|---|---|---|
| R1 | P2，已修复 | `query-gas-limit` 未接入真实启动路径。运营者设置后仍无限额；现只补一条 SDK 接口调用。测试见下文。 |
| R2 | P2，运维迁移项 | SDK 不再读取独立的 `grpc-web.address` / `grpc-web.enable-unsafe-cors`。gRPC-Web 由 API listener 提供，需 `api.enable`、`grpc.enable`、`grpc-web.enable`；地址与 CORS 采用 `api` 配置。继续只代理旧 `9091` 会失效。不能承诺所有旧 TOML 字段原样生效；不自行补一套旧 HTTP 服务。 |
| R3 | P2，发布前必须统一 | `VERSION` 仍为 `v0.5.0-rc.1`，但 CHANGELOG 的 RC1 节写旧计划 `sdk-v0.53-bridge`，新计划 `0.5.0` 在 Unreleased 节。release workflow 按 tag 抽取单节，直接用当前代码再次发布 rc.1 会附上错误的计划说明。应在冻结候选版时统一 tag、对应 release notes、计划名和产物哈希；不能沿用历史 RC1 的验收哈希。没有擅自换 RC 编号或重写历史记录。 |
| R4 | 发布前安全门槛，尚未关闭 | 当前 Go 1.24.7 和 gRPC 1.79.1 等依赖命中公开安全公告。gRPC 官方公告包含 HTTP/2 Rapid Reset 防护绕过；不是只有未启用的 xDS 问题。应对最终 Linux 包按实际入口核实并采用最小兼容补丁/受支持工具链，重新构建与演练。本轮没有进行无差别依赖升级，也未证明攻击可造成共识 halt。 |
| R5 | 参数验收门槛，不是擅自修正旧值 | 11 万 DORA 快速押金必须高于普通最低押金；快速投票期 1 天必须短于普通投票期；快速阈值 0.667 必须高于普通阈值。不符合时当前预检会拒绝迁移，不会偷偷降低旧参数来凑合法。必须在安排升级前对目标链固定高度做预检；不能等到 H 才发现。 |
| R6 | 上游行为变化 / 业务检查 | 旧 `x/params` 治理路由虽保留，但写旧 subspace 不会自动更新已迁入各模块的新 Params store。参数变更应按该模块 `MsgUpdateParams`。旧 software-upgrade / IBC legacy proposal 的执行接口也已被上游移除，需检查 H 前后仍在途的此类治理提案。不能把 CLI 入口存在说成全部旧语义都保持。 |

没有本轮新证据支持“SDK 升级必须加一个应用层交易池”“必须把 block.max_gas 改成 1 亿”或“必须开放新的合约 capability”。这些都不能作为默认修复加入。

### 依赖安全扫描的证据边界

使用 `govulncheck v1.1.4`，扫描当前依赖的 package 信息，并扫描前一轮本地 Darwin/AMD64 二进制（与本轮只差查询配置接线，依赖相同）。二进制扫描有 **49 个公告的符号匹配候选**，不等于 49 个可利用漏洞，更不是 49 个链 halt 漏洞。候选及上游链接完整保存在 [dependency-scan-triage.json](sdk-053-config-review-evidence-2026-09-12/dependency-scan-triage.json)。

- `GO-2026-6061`：当前 gRPC 1.79.1 在官方 `<1.82.1` 范围内；HTTP/2 transport 也命中二进制。公开 gRPC 节点的资源耗尽风险需要优先处理。公告中的 xDS 条件不能套用到未使用 xDS 的 Vota 服务。[上游公告](https://github.com/grpc/grpc-go/security/advisories/GHSA-hrxh-6v49-42gf)
- `GO-2026-4762`：gRPC 的另一公告修复版本为 1.79.3，但依赖“按路径 deny、默认 allow”等认证条件；没有证据就不能声称链上账户权限可被绕过。仅升级到 1.79.3 也不能因此关闭上一条较新的公告。[上游公告](https://github.com/grpc/grpc-go/security/advisories/GHSA-p77j-4mvh-x3m3)
- Go 1.24.7 命中多个标准库公告，例如 `GO-2025-4011` 的 ASN.1 输入内存耗尽（该单条在 1.24.8 修复）；这不是建议仅升到 1.24.8 就算全部解决。必须综合当前公告和执行兼容性选择工具链。[Go 官方记录](https://pkg.go.dev/vuln/GO-2025-4011)
- msgpack 的 fixext 越界公告仍被数据库的开放版本范围匹配，但本分支已固定上游 `04a026e9ac24` 的边界检查回补。应逐项对照修复，不能把扫描命中自动解释成“回补无效”，也不能删除该安全 replace。
- 扫描不是完整可达性审计；还需逐条区分 CLI 下载/导出、公开 RPC、P2P、Wasm 执行以及未使用的功能。当前 Linux 发布包尚未用本轮源码重建，不能沿用 Darwin 扫描作为最终 Linux 结论。

## 版本配置

| 项目 | 0.4.4 | 本分支 |
|---|---|---|
| Cosmos SDK | 0.47.17 | 0.53.6 |
| CometBFT | 0.37.5 | 0.38.21 |
| IBC-Go | 7.3.0 | 10.5.0 |
| Wasmd | 0.43.0 | 0.61.14 |
| WasmVM | 1.5.1 | 3.0.7 |
| 链上升级计划 | 历史计划保留 | 新增 `0.5.0`，无 `v` 前缀 |
| 候选版本文件 | 无此 RC 文件 | `VERSION=v0.5.0-rc.1`；发布说明需按 R3 统一 |

这不是 SDK 0.55 / CometBFT 0.40，也没有提前添加 PQC 交易类型。

## 链上参数：逐项复核表

### 新增的治理参数

SDK gov 4→5 迁移新增六个字段。本分支在 SDK 迁移之后只覆盖用户批准的前三项。

| 参数 | SDK 新链默认 / 自动迁移初值 | 本分支升级结束后的值 | 意义及授权 |
|---|---|---|---|
| `min_deposit_ratio` | 0.01 | **0** | 用户批准；不新增每次缴纳押金的比例门槛。普通总押金门槛仍保留。 |
| `proposal_cancel_ratio` | 0.5 | **0** | 用户批准；取消提案的押金扣除比例为零，正常交易 gas 费用仍存在。 |
| `expedited_min_deposit` | 50,000,000 最小单位币 | **110000000000000000000000 peaka = 110,000 DORA** | 用户批准；仅快速提案，不改普通提案最低押金。 |
| `expedited_voting_period` | 86400 秒 | **1 天** | 上游默认，未额外覆盖；请复核是否接受，并确认短于现有普通投票期。 |
| `expedited_threshold` | 0.667 | **0.667（66.7%）** | 上游默认，未额外覆盖；须高于现有普通通过阈值。 |
| `proposal_cancel_dest` | 空字符串 | **空字符串** | 上游默认，未指定新地址。当前扣费比例为 0；将来若提高比例，空地址对应的扣除部分由 SDK burn。 |

**重要：此表的指定值是“执行 0.5.0 升级后”，不是新建 genesis 的默认值。** 当前 `dorad init` 仍使用 SDK 模块默认 genesis；它没有执行升级 handler，因此新链不会自动得到上述三个已批准迁移值。长期测试网若通过旧版升级，会执行 handler；若从新版空 genesis 新建，必须独立审查 genesis，不能混为一谈。本轮没有擅自修改新链初始化政策。

SDK 迁移还在不存在时写入治理 constitution：`This chain has no constitution.`。这是新增链上文字记录，不是新增宪法规则，也不是 Vota 自行制定的治理内容。

### 原有参数与显式保留项

| 范围 | 当前处理 |
|---|---|
| `block.max_gas`、`block.max_bytes` | 从源链 `upgrade/Consensus` 实际记录迁入新 consensus store。若源值是 600000000 就保留 600000000；不读 genesis 的 -1 替代，不再写入 100000000。这里只说明代码规则，本轮未重读实时主网值。 |
| evidence / validator / version 共识字段 | 与旧记录一并迁移，未额外设置观察值或 fallback 值。 |
| Vote extensions | 未主动启用；0.4.4 旧记录没有启用高度时，迁移不从观察 context 注入非零高度。 |
| 普通治理参数 | 保留旧 `min_deposit`、`max_deposit_period`、`voting_period`、`quorum`、`threshold`、`veto_threshold`、`min_initial_deposit_ratio` 及三个已有 burn 标志。三个 burn 标志在 0.4.4 已存在，不是本次才新增。 |
| IBC client / connection / transfer、ICA host / controller 参数 | 上游迁移读取旧 subspace 后写入自身 store。没有把旧 ICA `allow_messages` 重置成一套新默认；没有自行放开 allowed_clients。 |
| bank / auth / mint / staking / distribution / slashing 既有政策 | 未加入 Vota 自定义重设值逻辑。SDK 仍执行其对应版本的结构/索引迁移；不代表 gas 计量、错误返回、所有执行语义逐字节不变。 |
| DORA 精度 / voting power 换算 | 18 位、10^18；仅 math 包接口适配。 |
| Wasm 上传上限 | 原 `MaxWasmSize` / `MaxProposalWasmSize` 3 MiB 保留。 |
| Wasm 能力声明 | `app/wasm.go` 与 0.4.4 原文件一致；未自动扩大到新版可选 capability。 |
| 旧存储 | 本次只删除 `capability`、`feeibc`；保留 `params`。删除前保护为空 fee 状态、零余额记录、源模块版本及参数合法性，不是任意清库。旧 feeibc auth 账户保留并维持普通 bank-send blocked。 |

IBC v10 的 channel 迁移还移除旧 channel-upgrade/params 等已废弃布局；正常 0.4.4/IBC v7 不具备后续版本的 FLUSHING 通道业务。它不改变旧通道 ID，也不自动新开 Cosmos/Osmosis/Noble 对端通道。实际最终快照的通道、资产与余额仍需按升级前后固定高度复核。

## 节点本地配置：新增与默认值变化

对两个精确依赖集合生成默认 `app.toml`、`config.toml`，仅按 Vota 原/新根命令覆盖最低 gas price，再解析并逐字段比较。下面是所有新增及默认变化；逐键包括移除项的 **37 条差异**见 [CSV](sdk-053-config-review-evidence-2026-09-12/node-config-diff.csv) / [JSON](sdk-053-config-review-evidence-2026-09-12/node-config-diff.json)。不是读取生产节点配置后得出的线上配置清单。

### app.toml

| 配置 | 旧默认 → 新默认 | 实际作用 / 判断 |
|---|---|---|
| `minimum-gas-prices` | `100000000000peaka` → `10000000000peaka` | 用户已批准的 Vota 默认变化。已有 app.toml 及显式启动配置仍优先；不会由升级 handler 改写验证人的本地文件。 |
| `query-gas-limit` | 无 → `0` | SDK 新查询 gas 限额；0 为不限制。本轮已接入，有限值生效；不等同于 Wasm 查询限额或 block gas。 |
| `mempool.max-txs` | `5000` → `-1` | **模板默认变化，但 Vota 新旧启动路径均没有使用它设置应用层 mempool。** 实际默认 NoOp；本轮实测指定 5000 仍为 NoOp。没有趁机接入新交易池。 |
| `grpc.historical-grpc-address-block-range` | 无 → `"{}"` | 可将特定旧高度查询转发至历史 gRPC；空对象时不启用转发。 |
| `streaming.abci.keys` | 无 → `[]` | ABCI 流式插件订阅 store 列表；默认空。 |
| `streaming.abci.plugin` | 无 → `""` | 插件路径；默认未启用。不是自动新增状态导出进程。 |
| `streaming.abci.stop-node-on-err` | 无 → `true` | 启用插件后遇错误可停止节点；部署自定义插件时需要专门复核，当前无插件。 |
| `telemetry.metrics-sink` | 无 → `""` | 可选监控输出端。 |
| `telemetry.statsd-addr` | 无 → `""` | 可选 StatsD 地址。 |
| `telemetry.datadog-hostname` | 无 → `""` | 可选 Datadog 主机标识。 |

另外 `grpc.skip-check-header=false` 是 SDK 配置结构/启动选项支持但默认 TOML 没有打印的字段；不要开启以绕过查询高度检查。本轮没有改它。

以下 Wasmd 节点默认值比较未变化：`wasm.query_gas_limit=3000000`、`wasm.memory_cache_size=100` MiB；`simulation_gas_limit` 默认不设置，按 Wasmd/SDK 对模拟请求处理。默认值不变不等于新旧 WasmVM 对同一合约消耗的 gas 完全相同，真实 aMACI 业务仍需验收。

### config.toml（CometBFT）

| 配置 | 新增默认 | 实际作用 |
|---|---|---|
| `mempool.recheck_timeout` | `1s` | 重检等待上限。与 app.toml 的应用层 max-txs 不同。 |
| `rpc.max_request_batch_size` | `10` | 单个 JSON-RPC batch 最大请求数；使用大批量 RPC 的索引器须复核。 |
| `statesync.max_snapshot_chunks` | `100000` | state-sync 接收快照分块总数上限。 |
| 顶层 `version` | `0.38.19` | 上游默认配置格式标记；实际锁定的 Comet 仍是 0.38.21。既有 ICA CLI 修复防止它串入协议 `--version`。 |

### client.toml / 额外启动选项

| 配置 | 新增默认 | 边界 |
|---|---|---|
| `keyring-default-keyname` | 空字符串 | 上游 CLI 默认 key 名选择，不生成或替换用户密钥。 |
| `--iavl-sync-pruning` | `false` | SDK 提供此开关，但 Vota 手动组装 BaseApp options 当前未传递它；不能承诺配置后生效。本轮未无故改变 pruning 路径。 |

此清单覆盖节点配置文件和发现的启动接线差异；AutoCLI 新版新增的各模块交易/查询命令不是“节点新增配置”，未逐个混入本表。

### 被上游删除 / 替代的配置

| 旧项 | 处理与迁移含义 |
|---|---|
| `grpc-web.address`、`grpc-web.enable-unsafe-cors` | 使用 API listener 和 API CORS，参见 R2；不应盲目把 unsafe CORS 改为 true。 |
| `iavl-lazy-loading` | 上游去除旧开关；没有独立恢复旧 IAVL 实现。 |
| `rosetta.*`（9 项） | SDK 删除旧 Rosetta 服务配置；若业务使用则需单独替代方案，不能算旧节点配置无损兼容。 |
| `store.streamers`、`streamers.file.*`（6 个子项） | 新版改为 ABCI 插件接口，旧文件流配置不会自动变成插件配置。 |
| `block_sync` | Comet 删除旧配置字段，不代表区块同步关闭。 |
| `mempool.version`、`mempool.ttl-duration`、`mempool.ttl-num-blocks` | Comet 删除这些旧字段；保留旧文本不能恢复旧语义。 |

配置缺项时新版使用自己的默认；**不能用“现有配置优先”概括已删除或不再接线的选项**。也不要在已有主网 home 上重新 init 或用新模板覆盖全部配置。

## 构建 / 发布配置变化

| 选项 | 变化 / 当前值 | 原因及边界 |
|---|---|---|
| `GO_VERSION`（Docker） | 1.20 → 1.24.7 | 匹配当前源码最低 Go 指令；具体补丁号仍需解决 R4。 |
| release CI 的 Go | 固定 1.22 → 读取 go.mod | 避免源码与 CI 工具链不匹配。 |
| `VERSION`（发布脚本环境变量） | 必填；CI 从文件/tag 提供 | 注入二进制版本和产物名；本身不是链上计划名。 |
| `GIT_VERSION`（Docker） | 新默认 `v0.5.0-rc.1` | 可覆盖；应与被冻结候选包一致。 |
| `COMMIT_SHA` | 新显式构建标识 | CI 传 commit，脚本回退 git HEAD/unknown；Docker 兼容旧 `GIT_COMMIT`。发布产物不应接受 unknown 身份。 |
| `BUILD_TAGS` | 脚本可配置；默认 `muslc,netgo,osusergo,static_build` | 普通 release 默认延续旧 tags；Docker 额外显式保留旧 `ledger`。 |
| `GOTOOLCHAIN=local` | 容器发布步骤显式设置 | 避免构建时隐式下载另一套 Go。 |
| WasmVM 静态库 | 1.5.1 → 3.0.7；两架构固定 SHA-256 | 必须与 WasmVM Go 绑定版本匹配；不改链上参数。 |
| Linux 架构 | amd64 / arm64 | 现有发布目标继续保留；实际产物执行 smoke，非仅交叉编译成功。 |
| RC release 模式 | tag 支持 `v…-rc.N`，draft + prerelease | 候选包不会自动作为正式主网版本发布。 |

## 必要性复核与验证范围

源码检查重点：真实 daemon creator、BaseApp options、ABCI/PreBlock 顺序、旧 handler 和 StoreLoader、旧共识读写、治理迁移、Ante/IBC/Wasm 接线、codec/CLI、发布脚本。详细历史归属仍见 [基线保留复核](sdk-053-baseline-preservation-2026-09-12.md) 和 [逐文件来源](sdk-053-change-provenance-2026-09-12.csv)。已删除的 capability/fee middleware 类型、旧 SDK API 等与不必要清理分开记录。

本轮结果：

- `go test ./...` 通过；Go 1.24.7，Darwin/AMD64。
- 新查询限额回归通过：实际启动构造、提交后查询 context，默认不限额和有限 gas meter 都符合配置；同时确认应用 mempool 仍为 NoOp。
- 前轮显式的三项模拟和历史 handler 恢复测试有独立记录；不把普通 `go test` 默认跳过的模拟当成再次跑过。
- 全部配置模板来自基线与本分支的精确依赖，生成器不写仓库 go.mod，也不接触生产 home。
- 当前生产源码哈希、日志和模板在 [证据目录](sdk-053-config-review-evidence-2026-09-12/source-manifest.json)。工作区仍有未提交修改，历史 commit 单独不能代表本轮源码。
- 本轮没有重跑真实主网快照升级、Linux 双架构 CI、实际公网客户端或长期测试网业务。最终源码冻结后仍须重跑，不能挪用旧 RC1 的通过记录。

建议复核顺序：先确认本表未覆盖的三个治理默认（一天、0.667、空地址）及新 genesis 边界；核对节点是否使用 9091/Rosetta/streamer/大批量 RPC；完成依赖安全候选排查与最小补丁；最后统一候选身份、构建、运行最终快照和长期测试网验收。
