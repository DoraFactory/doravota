# SDK 0.53 真实快照升级演练（2026-09-11）

状态：隔离链已完成升级；主网 No-Go，仍有验收门槛。未修改主网，未创建正式 Release，代码未提交/推送。

## 1. 本次实际做了什么

使用 ITRocket 主网快照 `doravota_2026-09-11_17249823_snap.tar.lz4`，在 amaci-testnet-operator（77.42.3.141）上保留原始数据，并以 0.4.4 建立四节点隔离链。原始快照 SHA-256：`ace45e16775385c6483d03a884f7f3756edbc2af0bbf1b694737b90b812d2ff6`。

- 旧版本源码：release 0.4.4，`1b0774785111d8a6e693cd155053c19a5a1d8bdc`。
- 隔离链 ID：`vota-snapshot-rehearsal-20260911`。四个验证人使用测试共识密钥；钱包/资产私钥没有替换或获取。
- 测试治理提案 **19**，计划名 **`sdk-v0.53-bridge`**，高度 **17250460**。
- 旧程序停在已提交高度 **17250459**；新程序处理 **17250460** 的迁移并继续出块。
- 目标依赖：Cosmos SDK 0.53.6、CometBFT Go module 0.38.21、IBC-Go 10.5.0、Wasmd 0.61.14、WasmVM 3.0.7。
- 本轮使用 Go 1.24.7 / Linux AMD64 / musl 静态发布包；不是开发机动态链接包替代。
- 最终运行包：`bridge-6d03e3b-review5`；SHA-256：`066360c4ff46696bb41162b7ce5a505e58325311a3b73fefef07a90f5057bfe1`。
- 最终候选身份及同高度结果见本目录 `sdk-053-rehearsal-evidence/final-binary.sha256`、`final-four-node-consistency.json`、`candidate-source-manifest.json`。以哈希为准，基线 commit `6d03e3b` 不包含未提交修复。

最后核验：UTC 2026-09-11 10:18:13，四节点在高度 **17,251,520** 的 block hash/AppHash 一致，已跨过升级高度 **1,060 块**；这不等于完成 24 小时观察。

浏览器：[隔离测试链](http://77.42.3.141:18080/vota-snapshot)。RPC/REST 通过只读代理提供，四节点原始端口、P2P 和测试对端均限制在本机。不能在该浏览器使用主网资产。

### 人工测试准备与真实迁移的边界

第一次快照分叉改变了测试验证人相关状态，详见 [0.4.4 基线记录](snapshot-rehearsal-2026-09-11.md)。本轮还在旧版本上制作人工准备检查点 `17250295`：为测试账户增发 1000 DORA、缩短治理投票期至 60 秒、quorum 改为 0、最小押金 1 DORA。保留了准备前完整备份。

这些改动只用于让测试账户能执行治理与交易。**不能把测试余额、治理参数、分叉辅助程序或测试签名状态复制到主网。** 下文状态比较使用经过这些准备、并已执行旧版业务测试后的 H−1 与 H，因而不会把人工准备误当迁移损失。

## 2. 演练中实际发现并修复的问题

| 问题 | 影响 | 修复与验证 |
|---|---|---|
| Go 1.24.0 与 Sonic loader 链接不兼容 | Linux 静态包无法构建 | 使用本轮已验证的 1.24.7；不关闭链接检查；最终生产工具链还需安全支持复核 |
| WasmVM musl 静态库落盘文件名缺少架构后缀 | CGO 找不到 `wasmvm_muslc.x86_64` | 按上游资产名保存并验证 SHA-256，实际静态构建/合约执行通过 |
| 新版 genesis 用旧 Comet 读取器解析 | `init` 成功但新节点启动 panic：integer encoding | 改用 SDK AppGenesis 读取器兼容新旧格式；新对端启动及旧快照重放验证 |
| Comet config.toml 的 version 污染 ICA --version | 新建 home 默认注册失败，误传 `0.38.19` 为协议元数据 | ICA 注册默认值不从同名服务器配置填充；测试默认/显式版本、双向握手 |
| 初始化覆盖链接注入的发布版本 | 多个包都显示 `sdk-v0.53-bridge`，无法凭 version 区分候选 | 只为空值提供开发默认版本；单测和实际发布包 version 断言 |
| 静态 BasicManager 缺 feegrant/authz 地址 codec，group 适配器未启用 | 客户端命令可能 nil-pointer panic | 补 CLI codec 接线，发布包新增 generate-only 冒烟与真实交易验证 |

这几项后续修复不更改迁移 handler 或共识算法；仍对修正后的包重新执行了旧快照升级块重放、节点重启及测试。各候选不能只凭名称互相替代，具体证据需匹配哈希。

此前空 IAVL、ICA 重复包装、feeibc 删除前检查、提案预算和模拟隔离修复也包含在本轮候选内。普通测试与三项显式模拟（seed 42、10 块、block size 5）日志留存。短模拟不替代长时间或高负载测试。

## 3. H−1 → H 状态比对

比较 **17250459 → 17250460** 的已提交 multistore/IAVL 数据。对根相同的 store 直接验证根一致；对根不同的 store 逐 key 流式比较，输出增、删、改及值哈希，再对格式变化做语义核对。

| Store / 业务 | 实测结果 |
|---|---|
| auth / acc | 2,854,262 条；原账户记录未改动。唯一 key 迁移是全局账户编号计数；旧 protobuf 与新 big-endian 值均为 **1,427,130** |
| bank | 2,273,729 条原记录全部字节一致；新增 14 条资产 metadata；没有删除/修改余额或 supply 条目 |
| wasm | **4,180,549 条，store 根完全相同**；合约、代码与状态未被迁移改写 |
| feegrant | **2,139,783 条，store 根完全相同** |
| authz、group、params、evidence | 各自 store 根完全相同 |
| mint | 原 2 条 KV 完全相同；树内部结构变化不等于业务数据变化 |
| staking | 当前验证人、委托、解委托记录未被删改；新增 2,047 条反向索引；历史高度 key 编码改变。9,997 条重叠历史记录值一致，窗口移除 17240460、加入 17250460 |
| slashing | 旧逐 bit 记录压缩为 chunk 位图；**605 个 true 漏签标记逐项一致**。4 个活跃验证人 index offset 正常增加 1，其他签名信息字段一致 |
| IBC | 原实际 client/consensus state/connection/channel/packet 记录未改写；新增参数，移除内部 localhost client 状态 |
| transfer | 14 条 DenomTrace 转为 Denom/Hop；路径、base denom 与 key 中的 hash 全部对应一致；新增参数 |
| distribution | 仅 previous proposer 更新，属于新块正常处理 |
| consensus | 新 store 获得旧参数；区块最大 gas 为 600,000,000、最大 bytes 为 22,020,096，证据和验证人参数继续核对在证据中 |
| feeibc | H−1 store **0 条**，删除前保护通过；本次不是有费余额/未结算状态迁移案例 |
| capability | 删除旧 **22 条（21 个 owner 记录及索引）**；后续受控 ICS-20/ICA 测试证明新接线可工作，不能仅据此断言所有旧 Wasm IBC 回调已通过 |
| gov / upgrade | 治理参数格式、模块版本表、计划完成记录等按迁移变化；原始差异留存 |

完整差异在服务器 `upgrade-evidence/boundary-stores.diff.jsonl.gz`；摘要为 `boundary-stores.summary.json` 和 `semantic-checks.json`。此核对证明指定快照/候选在指定高度的结果，不证明主网升级当日的 feeibc 仍为空。

### 大数据量导出的限制

曾尝试完整 JSON export；进程触及设置的 12/16 GiB 内存边界，未成功完成，不计为通过。本轮改用内存有界的已提交 store 比较，并成功冷备份恢复。**尚不能宣布该主网体量的完整 JSON export/import 已验收**；主网恢复手册优先使用已验证的一致数据库备份，若需要 JSON 导出须单独测量资源并验证。

## 4. 已完成的业务与故障验证

- 旧版先执行转账、委托，部署并初始化 hackatom 测试合约；新版再次查询并执行同一合约，实际释放资金。
- 新版转账、委托、解委托、奖励提取成功。解委托交易成功不等于长期到期释放已验证。
- 余额不足、未授权 Wasm 执行、gas 不足、旧签名交易重放被拒绝；节点继续出块。
- 新建隔离对端 `vota-bridge-peer-1`，真实创建 client/connection/channel（快照链 connection-54、transfer channel-18）；ICS-20 转出到账、凭证返回解锁、停止 relayer 后超时退款成功，退款差额仅为手续费。
- 快照链 ICA controller：channel-19 / 对端 channel-1，注册、远端银行转账、ack 成功。
- 快照链 ICA host：channel-20 / 对端 channel-2，反向注册、执行、ack 成功；试图代表非 ICA 账户转账时返回错误 ack，接收方与 ICA 余额不变。
- 测试移除 node3 升级计划文件及 Wasm 编译缓存后，成功重启、追块并查询旧合约。保存缓存副本，没有删除合约字节码或状态。
- 停 node3 时其他三节点继续出块；四节点同时停止/重启后同高度 block hash 和 AppHash 一致。
- node3 停机制作 tar 冷备份，验证 SHA-256，恢复到原路径，签名状态一致，重启追块并与其他节点一致。原 home 另存；同一验证人身份没有同时运行两个副本。
- 使用升级前边界备份另建 **无网络、0 投票权** 的重放节点，使用新测试密钥重放已存在的升级块，核对实际 ABCI commit hash；不会向测试网或主网双签。

费用代付授权/使用/撤销、authz 授权/代执行/撤销、group 创建已在最终包实测成功，结果见证据目录。浏览器显示 SDK 0.53.6 和四个验证人；节点返回的 Comet 版本字符串可能仍为上游源码常量 0.38.19，依赖身份应结合 build deps 的 0.38.21 和二进制哈希判断，不能仅看 config.toml 的版本字段。

- 迁移中途强杀：在 slashing 迁移开始时对另一个无网络、0 投票权副本发送 SIGKILL。离线读取确认仍只提交 H−1；重启后成功完成 H，AppHash 与正常升级一致。这验证了本次中断位置，不等于穷尽每个底层写入点。

## 5. 留存的恢复点与操作边界

服务器工作根：`/root/doravota-snapshot-rehearsal-20260911`。

- `pristine` / `input`：原始快照、genesis 和校验记录。
- `baseline-v044`：人工资金/治理准备之前的旧版四节点备份。
- `before-bridge-17250460`：H−1 升级边界完整备份；用于确定性重放和问题复现。
- `node3-before-recovery`、`bridge-node3-recovery.tar`：本轮已升级状态冷备份恢复材料。
- `upgrade-evidence`：构建、交易、差异、重放与恢复证据。测试私钥另置，不能提交到仓库。
- `node0`…`node3`：当前运行目录；`bin-bridge/dorad` 为当前候选。

升级提交新状态之后，**不能将程序直接换回 0.4.4 继续使用新数据库**。恢复升级前状态需要一致的旧备份和网络协调；验证人签名状态不得退回导致重复签名。单个 RPC 节点恢复与整条链回退不是同一操作。

旧程序在升级高度的表现是停止共识并在日志中报告 upgrade-needed；本轮手工停止了仍存活的旧进程，再切新包。**尚未验证生产 Cosmovisor 自动退出/重启与下载路径**，主网操作手册不能假设本轮手工切换等同于自动切换验收。

## 6. 主网仍不能放行的事项

1. **实际旧资产业务覆盖**：按用户 2026-09-11 确认，优先 Cosmos Hub、Osmosis、Noble；旧通道业务验收仍待补齐。channel-16 NFT 全流程和历史 INIT 握手恢复暂缓，不再作为本轮独立阻断项，但历史状态与资产保留仍必查，不能标记为业务测试通过。通道、客户端状态及覆盖例外见主网执行方案的范围调整。
2. **更完整的故障矩阵**：state-sync snapshot 恢复、磁盘满/数据库损坏应对、真实负载峰值、长周期到期行为未全部验收。已验证的 tar 恢复不能替代这些项目。
3. **持续观察**：最终高度与已观察块数见证据；尚未完成至少 24 小时观察，不能写成持续稳定性已通过。没有后台自动监控任务。
4. **生产交付**：最终 commit/源码独立复核、GitHub CI、实际使用的 ARM64、支持期内 Go 工具链及依赖安全复核、实际 Cosmovisor/签名器切换仍待完成。
5. **主网最新条件**：临近升级重查 feeibc、余额、版本、参数、验证人投票权/就绪状态和备份。

本轮已将多处真实问题提前暴露并修复，但不作“所有潜在 bug 已消除”的保证。主网高度在上述关键项闭环后再确定。
