# PQC 最近四天工作总结

> 统计范围：2026 年 8 月 27 日下午至 8 月 31 日。本文面向团队汇报，说明本阶段完成的链端实现、安全优化、测试数据和当前边界。

## 1. 阶段结论

过去四天的重点不是继续增加零散功能，而是把已经能够运行的 PQC 方案向“可升级、可约束、可审计、可跨链验证”推进。当前形成了两条互补的账户保护路径：新账户可以直接使用 Cosmos SDK 原生 ML-DSA-65 密钥；需要保留原地址和既有业务关系的经典账户，可以通过 `x/pqcauth` 增加 ML-DSA 第二因子。

在此基础上，本阶段重点完成了以下工作：

1. 收紧 `authz`、`feegrant` 和嵌套消息的授权边界，防止账户启用 PQC 后仍可通过历史授权绕过保护。
2. 完善经典账户注册和迁移门槛，区分原生 ML-DSA 账户与需要 `pqcauth` 的经典账户。
3. 建立确定性的 PQC gas 模型和区块级验签预算，控制恶意 ML-DSA 验签带来的 CPU 风险。
4. 增加升级前状态审计、保护条件预检和链上索引一致性检查。
5. 在受限资源双节点上完成容量、饱和和恶意流量测试，得到可量化的性能边界。
6. 完成 PQC-IBC 兼容层和最小 Relayer，实现共识密钥轮换后的真实双链 ICS20 中继。

一句话概括：**账户认证核心已经能够闭环，本阶段进一步补齐了权限旁路、资源上限、升级检查和 IBC 连续性。**

## 2. 四天工作脉络

| 时间 | 主要工作 | 阶段产出 |
| --- | --- | --- |
| 8 月 27 日 | 双节点容量基准、稳态压力、饱和压力、恶意流量注入 | 建立经典、Hybrid 和原生 ML-DSA 混合负载模型，获得 TPS、P99、区块容量和拒绝率数据 |
| 8 月 28 日 | `authz` 授权边界、注册迁移门槛、区块级 PQC 验签预算 | 关闭委托授权旁路；明确 FRESH 注册语义；在 Ante 与 proposal 两侧限制昂贵验签数量 |
| 8 月 29—30 日 | 升级前审计、保护条件预检、间接生命周期消息拦截、feegrant 链上索引 | 升级前可以发现不一致账户；注册前可以确认历史授权是否清理；代付授权获得确定性链上约束 |
| 8 月 31 日 | PQC-IBC Header 适配、原生 ML-DSA Relayer、内存双链测试和真实节点模拟 | Ed25519 共识密钥轮换为 ML-DSA-65 后，现有 IBC client 继续完成双向 ICS20 中继 |

## 3. 账户认证与授权边界加固

### 3.1 明确原生 ML-DSA 与 `pqcauth` 的职责

我们将账户分为两类处理：

- **原生 ML-DSA 账户**：地址由 ML-DSA 公钥派生，交易直接由 ML-DSA 私钥签署。该账户本身已经满足 PQC 要求，不需要也不允许重复注册 `pqcauth` 第二因子。
- **经典账户**：仍使用 secp256k1 等经典账户公钥。需要保留原地址时，可以注册独立的 ML-DSA signing key，并在经典签名通过后追加第二因子验证。

因此，即使治理把 enforcement mode 设置为 `REQUIRED`，原生 ML-DSA 账户也不会因为没有 `pqcauth` extension 而被阻断；`pqcauth` 只为经典账户提供 Hybrid 保护。这避免了原生 PQC 与第二因子方案互相冲突。

### 3.2 关闭 `authz` 委托旁路

Cosmos `x/authz` 的正常语义是：granter 预先授权后，后续由 grantee 签署 `MsgExec`，granter 不需要每次参与签名。如果只检查交易最外层 signer，一个已经启用 PQC 的 granter 仍可能通过旧 grant 被经典账户 grantee 操作。

本阶段增加了以下规则：

1. 经典账户在注册 `pqcauth` 或启用 `self_enforced` 前，必须先撤销已有的对外 authz grant。
2. 受保护账户只能向已经满足 PQC 要求的 grantee 创建新 grant。合格 grantee 可以是原生 ML-DSA 账户，也可以是已启用有效 `pqcauth` 策略的经典账户。
3. 执行历史 grant 时，再次检查 grantee 是否仍满足 PQC 要求，不能只在创建 grant 时检查一次。
4. 对嵌套 `MsgExec` 递归检查，并设置固定深度，避免通过多层包装隐藏不安全授权。
5. `MsgRegisterKey`、`MsgRotateKey`、`MsgRecoverKey` 等生命周期消息如果被包装在 authz、group、governance 或 Wasm 调用中，会在 Ante 阶段提前拒绝。

这项工作的核心不是改变 authz 的业务模型，而是保证“受保护 granter 的能力只能交给同样受 PQC 约束的执行方”。实现集中在 [`x/pqcauth/ante`](../../x/pqcauth/ante/)；详细规则见 [授权、Gas 与验证预算加固说明](authz-and-gas-hardening.md)。

### 3.3 补齐 `feegrant` 对称约束

Feegrant 虽然不能直接转走 granter 的余额，但能够长期代付手续费，并改变攻击成本和授权边界。原始 SDK store 主要按 grantee 排序，如果 Ante 为了查询“某个 granter 是否存在 allowance”而扫描全部状态，会引入不可接受的共识性能风险。

为此新增了确定性的派生状态：

```text
granter -> grantee 反向索引
expiration -> grantee -> granter 到期队列
```

链上所有 canonical mutation 路径同步维护该索引：创建、撤销、手续费扣减导致额度变化、额度耗尽以及 EndBlock 到期清理都会更新对应记录。注册或启用 `self_enforced` 时只读取 granter 前缀下的第一条记录，不进行全局扫描。

升级迁移会从 SDK feegrant 原始状态重建索引；审计和 invariant 会双向比较原始状态与派生索引，发现缺失、孤儿记录、重复 grant、到期时间不一致或解码失败时按 fail-closed 处理。

## 4. 注册迁移、升级检查与运维工具

### 4.1 收紧注册窗口

注册窗口现在具有明确语义：

- `OPEN`：允许符合账户类型和证明要求的经典账户注册。
- `FRESH_ACCOUNTS_ONLY`：只允许尚未发出交易、`sequence = 0` 且链上尚未写入经典公钥的账户注册。收款不会消耗 freshness，但先发送普通交易会永久失去该资格。
- `CLOSED`：关闭新的 `pqcauth` 注册，用于迁移结束后的稳定阶段。

FRESH 的目标是避免已经暴露经典公钥的存量账户在量子风险出现后重新进行不可信 bootstrap。它也带来明确的产品约束：如果未来启用该窗口，客户端必须保证注册是账户第一笔发出交易，不能让用户先发送普通转账。

### 4.2 增加保护条件预检

新增只读命令：

```bash
dorad pqcauth protection-readiness <account-address> --node <rpc>
```

该命令会：

- 判断账户是原生 ML-DSA 还是可注册的经典账户；
- 查询该账户作为 granter 创建的 authz grant；
- 查询该账户作为 granter 创建的 feegrant allowance；
- 给出账户是否具备注册或启用 `self_enforced` 的条件。

它用于在发起不可逆保护操作前暴露问题，减少用户提交交易后才发现旧授权未清理的情况。链上共识仍使用有界索引进行检查，CLI 查询不会被带入每笔交易的共识路径。

### 4.3 增加升级前状态审计

新增离线审计命令：

```bash
dorad pqcauth audit-state exported-state.json --height <export-height>
```

审计范围包括：

- 账户 policy 与当前/待生效 signing key 是否一致；
- key record、key sequence 和激活状态是否合法；
- 原生 ML-DSA 账户是否被错误注册为第二因子账户；
- authz、feegrant 与保护状态是否存在冲突；
- feegrant 原始状态是否可用于安全重建派生索引。

这使升级流程从“升级后发现异常”变为“升级前导出状态、离线检查、修复后再执行”。线上 invariant 和升级 handler 会对 live store 再做一致性检查。

## 5. Gas 模型与区块级抗 DoS

### 5.1 确定性验签 Gas

ML-DSA 验签比经典验签消耗更多 CPU。共识代码不能根据节点实际耗时动态计费，否则不同硬件可能得到不同结果，因此使用确定性模型：

```text
verification_gas =
    pqcauth_transaction_signatures × signature_verification_gas
  + lifecycle_proofs × proof_verification_gas
```

原生 SDK ML-DSA 验签保留 SDK 的 gas floor；`pqcauth` 的交易签名和生命周期证明使用独立的保守下限。交易大小、普通 SDK 签名、消息执行和 store 操作仍由标准 Cosmos gas 机制计费。

新增估算命令：

```bash
dorad query pqcauth estimate-verification-gas \
  --signatures 1 \
  --proofs 0
```

客户端进行完整估算时仍应调用 `/cosmos/tx/v1beta1/simulate`，并在模拟结果上增加合理 adjustment。

### 5.2 每笔交易和每个区块的验签预算

Gas 是经济约束，但不能完全替代 CPU 硬上限。恶意 proposer 可能构造 gas 合法但包含大量昂贵验签的 proposal，因此增加了独立的 consensus budget。

以下操作每发生一次计数一次：

- 原生 SDK ML-DSA 签名，包括受支持 multisig 中被选中的 ML-DSA leaf；
- `pqcauth` 交易第二因子签名；
- 注册、轮换等生命周期 proof；
- Recovery v2 recovery signature。

当前协议默认值为：

| 限制 | 默认值 |
| --- | ---: |
| 单笔交易最大 PQC 验证次数 | 16 |
| 单区块最大 PQC 验证次数 | 400 |

预算在三个位置保持一致：

1. **Ante**：结构解析完成后、费用与昂贵验签之前拒绝超限交易。
2. **PrepareProposal**：提案节点只选择累计预算未超限的交易。
3. **ProcessProposal**：所有验证人在重放 Ante 前先统计整个 proposal，恶意 proposer 无法塞入超预算区块迫使全体验签。

实现位于 [`x/pqcauth/ante/budget.go`](../../x/pqcauth/ante/budget.go)和 [`app/proposal.go`](../../app/proposal.go)。另外提供硬件标定工具，用目标验证人硬件的 ML-DSA P99 耗时反推 gas 与 block budget；开发机结果只能作为诊断，不能直接替代生产参数。

## 6. 双节点容量与对抗测试

### 6.1 测试环境

高性能服务器配置为 20 CPU、62 GiB 内存，部署两个相互独立的节点容器，每个节点限制为 10 CPU、30 GiB。负载由三类交易混合组成：

- 40% 经典 Cosmos 交易；
- 30% `pqcauth` Hybrid 交易；
- 30% 原生 ML-DSA 交易。

测试不仅统计广播成功，还持续查询交易是否真正进入区块，记录 committed TPS、确认延迟、区块交易数、gas、交易字节数和节点日志。

### 6.2 稳态与饱和结果

| 场景 | 已确认交易 | 失败 | 吞吐/容量观察 | P99 确认延迟 |
| --- | ---: | ---: | --- | ---: |
| 30% 稳态负载 | 6,780 | 0 | 55.41 TPS | 约 3.40 秒 |
| 60% 稳态负载 | 13,620 | 0 | 112.24 TPS | 约 3.44 秒 |
| 90% 压力负载 | 20,400 | 0 | 峰值约 380 tx/block | 约 27.38 秒 |

30% 和 60% 负载下确认延迟保持稳定。90% 压力下虽然没有交易失败，但 P99 上升到约 27.4 秒，说明系统已经进入排队和饱和区间。因此 380 tx/block 是本次环境中的压力观测值，不是建议的生产容量；生产目标应留出共识、网络波动和异常交易余量。

### 6.3 对抗流量结果

在合法负载运行的同时，以约 300 次/秒注入 36,000 笔恶意交易，包括：

- 无效 PQC 签名；
- 超出结构或大小限制的 extension；
- 非 canonical 编码；
- 错误 account sequence。

结果如下：

| 指标 | 结果 |
| --- | ---: |
| 恶意交易总数 | 36,000 |
| 被链接受 | 0 |
| 被拒绝 | 36,000 |
| 同期合法交易 | 13,620 |
| 合法交易失败 | 0 |
| 合法吞吐 | 约 111.28 TPS |
| 合法交易 P99 | 约 3.54 秒 |

该结果说明结构校验、签名校验和预算限制能够拒绝已覆盖的恶意输入，同时没有明显拖垮同期合法交易。它仍不是跨地域、生产验证人规模下的最终容量结论。

## 7. PQC-IBC 兼容实现与真实双链模拟

### 7.1 我们新增的部分

IBC 协议仍使用 IBC-Go v11 标准 `07-tendermint` light client。我们没有新建私有 IBC 协议，新增的是 ML-DSA 兼容边界：

1. [`pkg/pqcibc`](../../pkg/pqcibc/)：从 CometBFT LightBlock 构造标准 `07-tendermint Header`，识别 Ed25519 和 ML-DSA-65 validator key，验证超过 2/3 voting power 的 Commit，并限制 validator 数量、签名数量和 Header 大小。
2. [`cmd/pqcibc-relayer`](../../cmd/pqcibc-relayer/)：实现最小 `update-client` 与 `relay-transfer` 命令，使用原生 ML-DSA 账户签署 Relayer交易。
3. [`app/pqc_ibc_e2e_test.go`](../../app/pqc_ibc_e2e_test.go)：运行两个真实 Dora application，建立 client、connection 和 ICS20 channel，验证共识密钥轮换前后的双向 packet relay。

当前 Relayer不是 Hermes 或 `rly` 的完整替代品。它能够连接真实 RPC、构造 Header、查询 packet/ack proof，并提交 `MsgUpdateClient`、`MsgRecvPacket` 和 `MsgAcknowledgement`；但尚未实现长期事件监听、packet 队列、timeout、自动重试、多 path 管理和进程恢复。

### 7.2 Validator Set 轮换的连续信任

过渡 Header 不是 ML-DSA 特有机制，而是所有 CometBFT validator set 变化都使用的机制。本次之所以重点验证，是因为一次性 Ed25519 → ML-DSA 轮换会让新旧共识公钥和地址完全不同，可信 voting power 可能为零。

```text
过渡区块 T
  ValidatorsHash     = Hash(旧 Ed25519 集合)
  NextValidatorsHash = Hash(新 ML-DSA 集合)
  Commit             = 旧集合签名
          ↓
先把 T 的 Header 更新到对端 IBC client
          ↓
区块 T+1
  ValidatorsHash     = Hash(新 ML-DSA 集合)
  Commit             = 新集合使用 ML-DSA 签名
```

旧集合签署整个过渡 Header，因此也签署了其中的 `NextValidatorsHash`。对端先验证旧集合签名，再确认下一 Header 的 `ValidatorsHash` 与此前承诺一致，最终使用新 ML-DSA 公钥验证 Commit。当前测试脚本负责在正确高度调用更新；生产 Relayer还需要增加轮换事件监听、目标高度调度、失败重试和告警。

### 7.3 一笔 IBC Packet 的中继流程

```text
Chain A: MsgTransfer 写入 packet commitment
    ↓
Relayer 更新 Chain B 上跟踪 A 的 IBC client
    ↓
Relayer 查询 A 的 packet commitment Merkle proof
    ↓
Chain B: MsgRecvPacket，执行收包并写入 acknowledgement
    ↓
Relayer 更新 Chain A 上跟踪 B 的 IBC client
    ↓
Relayer 查询 B 的 acknowledgement proof
    ↓
Chain A: MsgAcknowledgement，结束 packet 生命周期
```

这里的 `proof_commitment` 是状态树 Merkle proof，不是 ML-DSA 签名。ML-DSA validator Commit 用来证明 Header 和 `AppHash` 可信；Merkle proof 再证明 packet commitment 确实存在于该 `AppHash` 对应的状态中。

### 7.4 真实节点结果

真实模拟使用两条独立 Dora 链、两个独立节点容器和原生 ML-DSA Relayer账户，完成：

- 标准 IBC client、connection 和 ICS20 `channel-0`；
- 轮换前 A → B ICS20；
- 两条链分别将共识密钥从 Ed25519 轮换为 ML-DSA-65；
- 过渡 Header 与第一个全 ML-DSA Commit 的连续 client update；
- 轮换后 A → B、B → A 的 client update、`RecvPacket` 和 `Acknowledgement`；
- 两条链持续出块，全部记录交易 `code = 0`。

| 指标 | Ed25519 | ML-DSA-65 | 变化 |
| --- | ---: | ---: | ---: |
| IBC Header 序列化大小 | 855 B | 11,794—11,796 B | 约 13.8 倍，增加约 10.9 KiB |
| 单次 client update gas | 267,819 | 377,170—377,229 | 增加约 40.8% |

完整环境、交易哈希、浏览器链接及问题修复记录见 [PQC-IBC 双链真实节点模拟报告](pqc-ibc-real-node-simulation-2026-08-31.md)。

## 8. 交付物清单

| 类型 | 交付内容 |
| --- | --- |
| 账户认证 | `x/pqcauth` 原生/经典账户分类、Hybrid Ante 验签、注册和密钥生命周期管理 |
| 授权防护 | authz 嵌套检查、间接生命周期消息拦截、feegrant 反向索引与到期队列 |
| 资源控制 | 确定性 gas 模型、单交易/单区块 PQC 验签预算、proposal 预检 |
| 运维工具 | `audit-state`、`protection-readiness`、verification gas 查询、硬件标定工具 |
| 测试体系 | 账户迁移 E2E、授权与 feegrant 回归测试、容量和恶意流量压测、PQC-IBC 双链测试 |
| 跨链组件 | `pkg/pqcibc` Header 适配库、最小 ML-DSA Relayer、真实节点模拟报告 |

## 9. 当前边界与下一步

当前结果证明账户认证、授权边界、资源预算、升级检查和 ICS20 主路径可以协同工作，但还不能直接等同于生产环境已经“端到端全部抗量子”。下一阶段建议按以下顺序推进：

1. **多验证人和跨机器模拟**：在真实 validator set 规模、网络延迟、丢包和节点重启条件下复测共识轮换及 IBC。
2. **生产 Relayer适配**：优先将 `pkg/pqcibc` 的 Header、keyring 和轮换调度逻辑接入 Go Relayer `rly`，补充事件监听、timeout、重试和持久化。
3. **目标硬件标定**：在最慢支持硬件上测量 ML-DSA P99，重新确定 gas、每区块验证预算和 `block max bytes`。
4. **扩大 IBC 覆盖**：增加 timeout、ordered channel、ICA、ICQ、Wasm IBC callback 和 relayer 故障恢复。
5. **升级发布准备**：处理上游依赖安全扫描问题，执行全量状态审计、参数检查、备份与回滚演练。

本阶段已经把 PQC 从单一签名功能扩展为一套覆盖账户、共识资源、升级和跨链的链端工程方案；后续工作的重点将从“功能是否可行”转向“生产规模、长期运行和生态组件兼容性”。
