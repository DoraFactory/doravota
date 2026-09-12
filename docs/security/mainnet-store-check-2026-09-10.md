# 主网 feeibc / capability 存储核查

日期：2026-09-10。仅执行公开 RPC 只读查询，没有广播交易或改动节点。

## 结论

在高度 **17,236,364**，feeibc 整个存储为空，模块账户全部币种余额为空，未发现待结算 ICS-29 费用或启用手续费的通道。前次审查 F1 的资金滞留触发条件在这个高度不存在。

capability 并不为空：有 21 条 capability 所有权记录，加一条 index 计数器；计数器值为 22（下一分配索引）。这些是端口/通道权限记录，不是用户余额。它们的存在不等于不能按 IBC-Go 10 设计移除旧模块，但要求现有业务在新路由与鉴权机制下回归通过。

## 数据定位和证明

- RPC：https://vota-rpc.dorafactory.org/
- 链 ID：`vota-ash`；RPC 返回 CometBFT 0.37.5，catching_up=false。
- 状态高度：17,236,364；对应块时间 2026-09-10 09:09:29.794700768 UTC（北京时间 17:09:29）。
- 用于验证状态证明的后继区块高度：17,236,365。
- 后继区块头 AppHash：`26BB6A6CBE50A507197B986BD01D8DCA46782F752C2C0599D806AF5F56863DBD`。
- feeibc 存储根：`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`，等于 SHA-256 空输入，即该 IAVL 版本的空树根。
- capability 存储根：`DEB55839F3FE17085FDF9E4C3FE840E915A5E26E489B944DE3AC80C71E15B13A`。

使用旧版本兼容的 ICS-23 库验证 feeibc/capability 在 multistore 中的成员证明，对照后继区块 AppHash；另逐项验证 capability index 和 21 条记录的 IAVL 成员证明。全部通过，见证据目录 proof-verification.log。

此验证是“响应证明与该 RPC 提供的区块头一致”，没有额外引入独立可信轻客户端检查点，也没有独立核验验证人签名；不是多个独立 RPC 的交叉确认。

最初的 capability subspace 扫描用于发现键。SDK 0.47 的该接口不能仅靠 response.height 认定返回了固定历史版本，因此随后对所有发现的键在固定高度进行精确查询及证明验证。21 条记录的索引连续为 1–21，固定高度 index=22，符合原模块的分配结构。

## feeibc 交叉检查

| 检查 | 结果 |
|---|---|
| 整个 store | 空树，并验证 store root 与区块 AppHash 的证明关系 |
| IncentivizedPackets（首批上限 100） | 0 条；由整个 store 为空进一步排除分页遗漏 |
| FeeEnabledChannels（首批上限 100） | 0 条；同上 |
| 模块账户 | dora176rcyfn5k9d0wcxel3kmwvxh0hy3xcwe6kxw3j |
| AllBalances（全部币种） | 空 balances，空 next_key，total=0 |
| locked 状态 | key 不存在；整个 store 为空 |

模块账户查询和 AllBalances 是指定同一高度的成功 ABCI/gRPC 查询，本次没有另做 bank 余额范围的密码学证明。空 fee store 不自动推导模块余额为零，余额是额外查到的。

结论只覆盖这个高度，不证明历史上从未使用，也不保证未来升级高度之前不会新增费用。无需基于该高度安排“退还现存 ICS-29 手续费”；仍需在升级准备及紧邻升级前复查，或以经过设计的升级前置条件保证不出现新余额/记录。不要把这条证据用于取消其他升级安全检查。

## capability 清单概览

- 3 个端口：transfer、icahost、一个 wasm 合约端口。
- 18 个通道：17 个 transfer 通道，1 个 wasm 通道。
- 通道状态：15 个 OPEN、3 个 INIT；分页 total=18，无 next_key。
- INIT 通道：transfer/channel-8、channel-9、channel-11。仅根据状态不能断言故障；需要确认是否为历史未完成握手。
- OPEN transfer 通道 14 个；均为 ics20-1。
- OPEN 合约通道：channel-16，协议版本 ics721-1。
- 本链合约：dora1q09v79ar0w99av6hlut0nhkstqt6up5mv3gmnut53t7jzxu4plyqt268vu。
- 对端：wasm.stars1r0a8ygvnjfaegy4n5z9325e0ew9uy2s7rn4vt7qf4ltv49fj4tnsk6pvtv / channel-397。

icahost 端口存在只说明该权限已绑定，不能据此认定存在活跃 ICA 账户或交易；本轮未枚举 ICA 账户状态。

## 对升级风险判断的更新

1. **费用资金滞留：本高度未触发。** 前次审查是条件性代码风险；本次链上证据将“是否已有待处理费用”的未知项排除到指定高度。
2. **capability 权限：有实际使用状态。** 不需要把这些旧权限记录当成余额退款，也不能手工清空旧主网 capability store；迁移应在协调升级中按新版本设计执行。
3. **跨链回归目标已具体化。** 用快照测试 14 条已打开 transfer 通道代表性收发、ack、timeout/退款，并针对链路差异扩大覆盖；单独测试 channel-16 的 ICS-721 合约发送、接收、ack、timeout、授权及状态保留。检查 3 条 INIT 通道迁移后能否按业务需要继续握手或保持预期状态。
4. **空 feeibc 不意味着桥接版本整体可以上线。** 数据库兼容入口、发布产物、ICA 接线和模拟验证缺口仍按原审查处理。

上游设计依据：[IBC-Go v10.5.0 迁移指南](https://github.com/cosmos/ibc-go/blob/v10.5.0/docs/docs/05-migrations/13-v8_1-to-v10.md)，要求移除 capability 和 fee middleware；本轮对照固定版本本地依赖源代码阅读。

## 完整通道列表

| 本地端口 | 通道 | 状态 | 协议 | 对端通道 |
|---|---|---|---|---|
| transfer | channel-0 | OPEN | ics20-1 | channel-2694 |
| transfer | channel-1 | OPEN | ics20-1 | channel-32 |
| transfer | channel-10 | OPEN | ics20-1 | channel-101 |
| transfer | channel-11 | INIT | ics20-1 | 未分配 |
| transfer | channel-12 | OPEN | ics20-1 | channel-64 |
| transfer | channel-13 | OPEN | ics20-1 | channel-146 |
| transfer | channel-14 | OPEN | ics20-1 | channel-94 |
| transfer | channel-15 | OPEN | ics20-1 | channel-394 |
| transfer | channel-17 | OPEN | ics20-1 | channel-106136 |
| transfer | channel-2 | OPEN | ics20-1 | channel-10 |
| transfer | channel-3 | OPEN | ics20-1 | channel-4092 |
| transfer | channel-4 | OPEN | ics20-1 | channel-750 |
| transfer | channel-5 | OPEN | ics20-1 | channel-182 |
| transfer | channel-6 | OPEN | ics20-1 | channel-15 |
| transfer | channel-7 | OPEN | ics20-1 | channel-125 |
| transfer | channel-8 | INIT | ics20-1 | 未分配 |
| transfer | channel-9 | INIT | ics20-1 | 未分配 |
| wasm（上述合约） | channel-16 | OPEN | ics721-1 | channel-397 |

原始响应、固定高度证明、解码清单和复核脚本保存在同目录 `mainnet-store-check-17236364/`。脚本没有发送交易；verify.go 使用该本地证据路径，搬移后需更新路径。
