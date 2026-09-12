# 0.4.4 → SDK 0.53 桥接分支：参数逐项复核清单

基线：`0.4.4` / `1b0774785111d8a6e693cd155053c19a5a1d8bdc`。目标：`sdk-053-bridge` / `d37fa73ef456cfd985df3679cd87704509db9a42`。

范围：应用接线、已接入模块的链上 Params、生成的 app/config/client TOML、额外节点启动选项、构建发布设置。交易消息的业务字段、每个查询命令的筛选参数和依赖内部算法常量不属于本配置清单。代码审查不是实时主网参数快照；旧值写“保留源值”的项目，指升级时读取数据库实际值，而非 genesis 默认。

## A. 新增链上治理参数（6 项）

以下是旧链执行 `0.5.0` 升级 handler 后的结果。新建 genesis 不执行 handler，不能套用这三个自定义值。

| 复核 | 参数 | 0.4.4 | 当前升级结果 | 来源 / 含义 |
|---|---|---|---|---|
| ☐ | min_deposit_ratio | 无 | 0 | SDK 新增；按用户决定覆盖默认 0.01。取消单次押金比例门槛，不取消总押金要求。 |
| ☐ | proposal_cancel_ratio | 无 | 0 | SDK 新增；按用户决定覆盖默认 0.5。取消提案不按押金比例扣费，交易 gas 仍收取。 |
| ☐ | expedited_min_deposit | 无 | 110000000000000000000000 peaka（11 万 DORA） | SDK 新增；用户决定覆盖 SDK 默认 50000000 最小单位币。必须高于普通押金。 |
| ☐ | expedited_voting_period | 无 | 86400 秒（1 天） | SDK 迁移默认，应用未覆盖；必须短于普通投票期。 |
| ☐ | expedited_threshold | 无 | 0.667 | SDK 迁移默认，应用未覆盖；必须高于普通通过阈值。 |
| ☐ | proposal_cancel_dest | 无 | 空字符串 | SDK 迁移默认；若未来扣费比例大于 0，空目的地址意味着烧毁扣除部分；当前比例 0。 |

☐ 额外新增的治理状态：constitution，在不存在时写入 `This chain has no constitution.`。它是文本状态，不是新增投票规则。

这六项是新增字段，不是把原来的普通治理参数修改成新值。三项自定义治理政策同时用于删除存储前的合法性预检；源值与政策冲突时返回错误，不改旧值凑合法。

## B. 原有链上参数：保留、迁址与删除边界

| 复核 | 模块 | 逐项字段 / 对象 | 处理 |
|---|---|---|---|
| ☐ | 共识 | block.max_bytes、block.max_gas | 保留源链实际值。源值 600000000 时仍为 600000000；没有 100000000 兜底重写。 |
| ☐ | 共识 | evidence.max_age_num_blocks、max_age_duration、max_bytes；validator.pub_key_types；version.app | 旧记录整体迁移；不额外重设。 |
| ☐ | 共识新增结构 | abci.vote_extensions_enable_height | 新 Comet 支持此字段；未主动启用，旧记录缺省不注入非零值。不是新增非零政策。 |
| ☐ | gov | min_deposit、max_deposit_period、voting_period、quorum、threshold、veto_threshold、min_initial_deposit_ratio | 保留源值。 |
| ☐ | gov | burn_vote_quorum、burn_proposal_deposit_prevote、burn_vote_veto | 0.4.4 已有，保留源值，不属于新增参数。 |
| ☐ | auth | max_memo_characters、tx_sig_limit、tx_size_cost_per_byte、sig_verify_cost_ed25519、sig_verify_cost_secp256k1 | 不新增应用层覆盖；迁移旧参数。 |
| ☐ | bank | default_send_enabled、逐 denom 的 send_enabled 记录 | 不新增应用层覆盖；send_enabled 在旧版已是独立记录。 |
| ☐ | staking | unbonding_time、max_validators、max_entries、historical_entries、bond_denom、min_commission_rate | 保留政策值，执行上游结构/索引迁移。 |
| ☐ | mint | mint_denom、inflation_rate_change、inflation_max、inflation_min、goal_bonded、blocks_per_year | 保留政策值。 |
| ☐ | distribution | community_tax、withdraw_addr_enabled、base_proposer_reward、bonus_proposer_reward | 保留旧参数；后两项在旧版已废弃，不是本次删除。 |
| ☐ | slashing | signed_blocks_window、min_signed_per_window、downtime_jail_duration、slash_fraction_double_sign、slash_fraction_downtime | 保留政策值。 |
| ☐ | IBC | client.allowed_clients、connection.max_expected_time_per_block、transfer.send_enabled/receive_enabled | 保留旧值，迁移到模块自己的参数存储。 |
| ☐ | ICA | controller_enabled、host_enabled、allow_messages | 迁移旧值，不重置成新允许列表。 |
| ☐ | wasm | code_upload_access、instantiate_default_permission | 不改既有上传/实例化权限；模块版本均为 4，不重复跑旧 Wasm 参数迁移。 |
| ☐ | 存储迁址 | 旧 upgrade/Consensus → consensus store；部分 x/params subspace → 各模块 store | 地址/结构改变，不等于参数数值改变。旧 x/params 治理写入不会自动更新迁出的模块 Params。 |
| ☐ | 存储删除 | capability、feeibc | 删除模块存储，不是删除现有 IBC channel 或资产。feeibc 有状态/余额前检；历史 auth 账户和 bank-send 禁止规则保留。 |
| ☐ | 保留存储 | params | 不删除。 |

IBC v10 迁移会清理中间版本的旧 channel-upgrade 参数/状态；IBC v7 正常源状态没有这些后续新增布局，不应列成“0.4.4 原有 channel 参数被删除”。

以上是配置/参数保留规则，不代表 SDK、Comet、WasmVM 的 gas 计量和执行实现与旧版完全相同。

## C. 生成节点配置的全部差异（37 项）

旧/新值是精确依赖生成的默认配置，并应用 Vota 的 gas price 默认；不是线上节点实际值。已有配置中的有效字段继续使用；已删除字段不会因为旧 TOML 留着就恢复旧功能。

### 新增（12 项）

| 复核 | 文件 / 参数 | 旧默认 | 新默认 | 影响 |
|---|---|---|---|---|
| ☐ | `app.toml` / `grpc.historical-grpc-address-block-range` | `不存在` | `{}` | 历史高度 gRPC 转发映射；空对象不启用转发。 |
| ☐ | `app.toml` / `query-gas-limit` | `不存在` | `0` | SDK 新选项；本轮补上 SetQueryGasLimit 接线，0 仍为不限制。仅查询，非共识 block.max_gas。 |
| ☐ | `app.toml` / `streaming.abci.keys` | `不存在` | `[]` | 新 ABCI 流式插件导出的 store keys，默认空；不自动迁移旧 file streamer。 |
| ☐ | `app.toml` / `streaming.abci.plugin` | `不存在` | `空字符串` | 新 ABCI 流式插件路径，默认空、未启用。 |
| ☐ | `app.toml` / `streaming.abci.stop-node-on-err` | `不存在` | `True` | 启用插件后遇插件错误可停止节点；默认无插件时无作用。 |
| ☐ | `app.toml` / `telemetry.datadog-hostname` | `不存在` | `空字符串` | 上游监控配置，默认空；需主动启用并设置 telemetry。 |
| ☐ | `app.toml` / `telemetry.metrics-sink` | `不存在` | `空字符串` | 上游监控输出选择，默认空。 |
| ☐ | `app.toml` / `telemetry.statsd-addr` | `不存在` | `空字符串` | 上游 StatsD 地址，默认空。 |
| ☐ | `config.toml` / `mempool.recheck_timeout` | `不存在` | `1s` | Comet 重检等待上限，默认 1 秒；不同于应用层 max-txs。 |
| ☐ | `config.toml` / `rpc.max_request_batch_size` | `不存在` | `10` | 单批 JSON-RPC 请求数上限 10；批量调用客户端须核对。 |
| ☐ | `config.toml` / `statesync.max_snapshot_chunks` | `不存在` | `100000` | 快照分块总数上限 100000；state-sync 节点须核对。 |
| ☐ | `config.toml` / `version` | `不存在` | `0.38.19` | Comet 配置格式标记；0.38.19 是上游模板常量，实际二进制依赖为 0.38.21。 |

### 修改默认值（2 项）

| 复核 | 文件 / 参数 | 旧默认 | 新默认 | 影响 |
|---|---|---|---|---|
| ☐ | `app.toml` / `mempool.max-txs` | `5000` | `-1` | 模板变化，Vota 0.4.4 和本分支均未接 SetMempool；当前实际为 NoOp，不能视为运行时变更。 |
| ☐ | `app.toml` / `minimum-gas-prices` | `100000000000peaka` | `10000000000peaka` | Vota 显式且用户已批准；仅本地默认，不改链上参数、不覆盖现有配置。 |

### 删除 / 替代（23 项）

| 复核 | 文件 / 参数 | 旧默认 | 新默认 | 影响 |
|---|---|---|---|---|
| ☐ | `app.toml` / `grpc-web.address` | `localhost:9091` | `移除` | 上游移除；gRPC-Web 改由 API 地址提供，旧 9091 代理须检查。 |
| ☐ | `app.toml` / `grpc-web.enable-unsafe-cors` | `False` | `移除` | 上游移除；改由 api.enabled-unsafe-cors 控制，不应直接放开 CORS。 |
| ☐ | `app.toml` / `iavl-lazy-loading` | `False` | `移除` | 上游移除，当前根命令也不再传递；不要用旧字段推断新 IAVL 行为。 |
| ☐ | `app.toml` / `rosetta.address` | `:8080` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.blockchain` | `app` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.denom-to-suggest` | `uatom` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.enable` | `False` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.enable-fee-suggestion` | `False` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.gas-to-suggest` | `200000` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.network` | `network` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.offline` | `False` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `rosetta.retries` | `3` | `移除` | 上游移除 Rosetta 配置/服务。 |
| ☐ | `app.toml` / `store.streamers` | `[]` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.fsync` | `false` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.keys` | `['*']` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.output-metadata` | `true` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.prefix` | `空字符串` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.stop-node-on-error` | `true` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `app.toml` / `streamers.file.write_dir` | `空字符串` | `移除` | 上游移除旧 file streamer 配置；如曾使用，须单独迁移插件配置。 |
| ☐ | `config.toml` / `block_sync` | `True` | `移除` | 上游删除旧配置字段，不等于新版关闭区块同步。 |
| ☐ | `config.toml` / `mempool.ttl-duration` | `0s` | `移除` | 上游删除旧交易 TTL 配置。 |
| ☐ | `config.toml` / `mempool.ttl-num-blocks` | `0` | `移除` | 上游删除旧交易 TTL 配置。 |
| ☐ | `config.toml` / `mempool.version` | `v0` | `移除` | 上游删除旧版本选择字段；不可与仍存在的 mempool.type 混淆。 |

## D. 默认 TOML 之外的选项（不能漏算）

| 复核 | 项目 | 变化 / 默认 | 当前是否生效 |
|---|---|---|---|
| ☐ | client.toml: keyring-default-keyname | 新增，空字符串 | CLI 默认密钥名选择；不生成或更换密钥。 |
| ☐ | start --shutdown-grace | 新增，0s | 已注册；停机时给资源清理的额外等待时长，0 不增加等待。 |
| ☐ | grpc.skip-check-header | 配置结构新增，false；默认 TOML 不打印 | gRPC server 读取；不是已注册的同名 start flag。 |
| ☐ | --with-tendermint → --with-comet | 主名称替换，true | 旧名称仍经 normalize 兼容；不是关闭内嵌共识。 |
| ☐ | iavl-sync-pruning | SDK 常量/通用 BaseApp helper 内存在，布尔零值 false | 当前 start 未注册该 flag，Vota 也未接 helper；不是可用的新节点开关。旧清单称其为可用 flag 不准确。 |
| ☐ | fast_sync | 上游移除旧兼容结构字段 | 0.37 已是 Deprecated；不是本次关闭块同步。 |
| ☐ | fastsync | 上游移除旧兼容结构字段 | 0.37 已是 Deprecated；正常使用 blocksync 配置。 |
| ☐ | p2p.upnp | 上游移除旧兼容结构字段 | 旧版已注明 deprecated and unused，无有效旧功能被关闭。 |

历史 gRPC 转发选项在 TOML 默认显示 `{}`，start flag 默认是空字符串；两者均表示没有配置转发目标。`query-gas-limit` 同时有 TOML 与 CLI 入口，已在 C 中计数，不重复算新参数。

## E. Wasm、应用硬编码与未启用项

| 复核 | 参数 / 设置 | 旧 → 新 / 处理 |
|---|---|---|
| ☐ | wasm.query_gas_limit | 3000000 → 3000000；旧版已有，与新增通用 query-gas-limit 不同。 |
| ☐ | wasm.memory_cache_size | 100 MiB → 100 MiB。 |
| ☐ | wasm.simulation_gas_limit | 默认未设置 → 未设置。 |
| ☐ | ContractDebugMode | false → false；不是新增启用调试输出。 |
| ☐ | MaxWasmSize、MaxProposalWasmSize | 均保留 3 MiB。 |
| ☐ | DORA 精度 / DefaultPowerReduction | 18 / 10^18 保留；math 包类型适配。 |
| ☐ | gov.MaxMetadataLen | 默认 255 保留。 |
| ☐ | WasmConfig 类型 | 上游更名/拆分为 NodeConfig + VMConfig；节点配置 key 没有因此整体更名。 |
| ☐ | VMConfig.WasmLimits | 新 VM 支持静态验证限制结构；当前传空结构，所有指针 nil，采用原生库默认；没有应用自定义限额。 |
| ☐ | Wasm capability | app/wasm.go 与旧版一致，未自动扩大声明列表。 |
| ☐ | 应用 mempool | 新旧 Vota 默认均为 NoOp；模板 max-txs 变化不等于实际换交易池。 |
| ☐ | 可选功能 | 未接 protocolpool、epochs、unordered transactions、PQC、IBC callbacks 和 IBC v2 业务路由，不把它们的上游参数混算为本链新增。 |

VMConfig.WasmLimits 的字段逐项为：initial_memory_limit_pages、table_size_limit_elements、max_imports、max_functions、max_function_params、max_total_function_params、max_function_results、max_function_locals、max_total_function_locals。这里的 nil 不表示“无限”，表示采用 WasmVM 原生默认。该结构不是链上 Params 或当前可直接配置的 TOML 节点开关。

## F. 构建与发布配置

| 复核 | 参数 / 入口 | 0.4.4 → 当前 |
|---|---|---|
| ☐ | Cosmos SDK | 0.47.17 → 0.53.6 |
| ☐ | CometBFT | 0.37.5 → 0.38.21 |
| ☐ | IBC-Go | 7.3.0 → 10.5.0 |
| ☐ | Wasmd / WasmVM | 0.43.0 / 1.5.1 → 0.61.14 / 3.0.7 |
| ☐ | go.mod Go 指令 | 1.19 → 1.24.7 |
| ☐ | Docker GO_VERSION | 1.20 → 1.24.7 |
| ☐ | release CI Go | 固定 1.22 → 读取 go.mod |
| ☐ | CLI Version | 0.4.4 → v0.5.0-rc.1；构建注入版本非空时保留构建值 |
| ☐ | VERSION 文件 / 发布脚本变量 | 新版本文件 v0.5.0-rc.1；发布脚本要求 VERSION，CI 从文件或 tag 提供 |
| ☐ | 升级计划 UpgradeName | 新增 0.5.0；历史计划保留，无 v 前缀；Cosmovisor 目录同名 |
| ☐ | Docker GIT_VERSION | 无默认 → v0.5.0-rc.1 |
| ☐ | Docker GIT_COMMIT | 无默认 → unknown，旧参数仍兼容 |
| ☐ | COMMIT_SHA | 新增显式构建身份入口；正式候选应使用真实 commit |
| ☐ | BUILD_TAGS | 脚本可覆盖，默认 muslc,netgo,osusergo,static_build；Docker 另保留 ledger |
| ☐ | GOTOOLCHAIN | 发布容器设置 local，避免隐式换 Go 工具链 |
| ☐ | WasmVM 静态库 | 匹配 3.0.7，双架构 checksum 校验；不是链上参数 |
| ☐ | 发布 tag 规则 | 新增 v 前缀和 v…-rc.N；RC 为 draft + prerelease |
| ☐ | Linux 架构 | amd64/arm64 保留，新增产物启动检查 |

当前仍叫 rc.1，但历史 rc.1 发布说明对应旧计划；正式生成下一份候选 Release 前需要统一版本号、说明和产物身份。本清单不替用户决定新 RC 编号。

## 核对依据与边界

- 本地当前提交的 app/app.go、app/upgrades/v0_5_0/governance.go、preflight.go、cmd/dorad/cmd/root.go、app/wasm.go、Dockerfile 和发布脚本。
- 已提交的精确依赖默认 TOML 与 37 项逐键差异：sdk-053-config-review-evidence-2026-09-12/。
- 两版 SDK/IBC/Wasmd 的 Params protobuf 字段；SDK v0.53.6 gov v5 迁移、server/start.go、server/config/config.go；两版 Comet config/config.go；Wasmd types/types.go。
- 旧 evidence 文件是采集时点证据，当前检查已重新核对相关接线；没有读取生产节点的实时值，也没有声称完成参数前后快照对照。
- 本次仅新增此复核文档，不修改任何代码、参数、GitHub 分支或运行中节点。
