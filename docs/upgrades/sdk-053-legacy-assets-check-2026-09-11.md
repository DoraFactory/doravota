# SDK 0.53：旧资产通道及 NFT 状态复核

2026-09-11。仅对四节点隔离快照链进行只读核查，未操作主网、未改变任何通道、客户端、合约或资产状态。

## 结论

所选五个旧通道的状态与托管资金保留检查通过。此结论不等于旧通道完整跨链收发通过，也不等于主网可放行。

- 0.4.4 导出 initial_height=17250460，即最后提交高度 17250459；升级后导出 initial_height=17250511，即状态高度 17250510。两份导出中五个通道的通道记录、7993 条接收记录、7993 条 acknowledgement、收发及确认序列逐项相同，发送承诺均为零。
- 当前固定高度 17252862，四个 transfer 托管地址余额仍与升级前逐项相同，五个通道本地发送承诺仍为零。REST 响应高度与请求高度一致；已处理分页。
- H−1/H 流式数据库比对另已证明：原有 bank 条目无修改或删除；IBC 仅增加协议参数并删除 localhost 客户端；Wasm 的 4180549 条状态根完全相同。14 个旧资产路径与 denom 哈希语义一致。

## 主要资产及历史通道

| 对端 | 本链通道 | 对端通道 | 隔离链客户端 | 当前托管 peaka，原始整数单位 |
|---|---|---|---|---|
| Cosmos Hub | channel-4 | channel-750 | Active | 221732826210837911066 |
| Osmosis | channel-0 | channel-2694 | Active | 474762777110515299264757 |
| Noble | channel-14 | channel-94 | Active | 4000024290000000001 |
| Osmosis 历史通道 | channel-17 | channel-106136 | Expired | 1 |
| Stargaze NFT | channel-16 | channel-397 | Expired | 不适用 transfer 托管地址 |

固定高度 17252862 的本链代币供应：`transfer/channel-4/uatom` 为 795370120 uatom，`transfer/channel-0/uosmo` 为 6413122 uosmo，`transfer/channel-14/uusdc` 为 507428155 uusdc。资产路径、完整 IBC denom 哈希及其他存量币种见 JSON。通道托管的 peaka 与本链持有的外来 IBC 资产是两类不同状态，不能相互替代。

channel-17 仍有 1 peaka；即使金额极小且客户端过期，也不应当作空通道删除。客户端过期不是本轮迁移修改客户端数据的结果；对应旧客户端记录在升级边界未变。

## channel-16 并非空业务

固定高度 17252871，原 Donation 合约 code 98、两个 NFT 映射及五个 NFT 所有者均可成功查询：

- 第一个集合：token 551。
- 第二个集合：token 619、67、791、83。
- 三个 token 的所有者是 airdropper 合约，其余两个由普通地址持有。完整地址和原始响应在证据中。
- 本地历史 acknowledgement 为 5；本地发送承诺为 0。

按用户确认，其完整 NFT 跨链业务暂缓验收；保留历史 NFT 与合约状态检查，不标记为“从未使用”或“无资产”。合约 creator/admin 只能证明部署及管理地址，不能证明谁签署了通道握手；实际开通者仍未查明。

## 证据与覆盖边界

- [核对断言结果](sdk-053-rehearsal-evidence/legacy-assets-verification.json)
- [固定高度当前资产状态](sdk-053-rehearsal-evidence/legacy-assets-current.json)
- [两份导出的旧通道及托管状态](sdk-053-rehearsal-evidence/legacy-assets-boundary.json)
- [NFT 所有者及原合约查询](sdk-053-rehearsal-evidence/legacy-nft-current.json)
- [客户端状态](sdk-053-rehearsal-evidence/legacy-client-status.json)
- [迁移边界全 store 比对](sdk-053-rehearsal-evidence/boundary-stores.summary.json)

本轮未查询三个真实对端的发送承诺，也未搭建其隔离副本完成旧通道端到端传输。本地零发送承诺仅证明本链没有待确认的已发送包，不能证明对端没有待交付给本链的包；历史 acknowledgement 数量也不直接等于未完成交易数。

下一步仍为实际资产业务的兼容对端/证明验收及剩余发布门槛。不能让隔离分叉接入主网 relayer，不能通过更换旧客户端状态伪装成真实旧通道验收。
