# Dora 的 PQC 升级路径：原生 ML-DSA 与存量账户保护

量子计算对区块链的主要威胁之一，是削弱现有数字签名方案的安全假设。Dora Vota 采用双轨迁移方案：账户层和共识层使用 Cosmos SDK 与 CometBFT 原生的 ML-DSA 能力；无法更换地址的存量账户则通过 [`x/pqcauth`](https://github.com/DoraFactory/doravota/tree/pqc-auth/x/pqcauth) 增加 ML-DSA 认证因子。

## 1. 背景与迁移约束

Dora Vota 当前的用户账户主要使用 [`secp256k1`](https://github.com/cosmos/cosmos-sdk/tree/v0.55.0/crypto/keys/secp256k1)，验证人共识密钥使用 [`Ed25519`](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/ed25519)。两种方案的安全性均依赖椭圆曲线离散对数问题，无法抵抗具备足够规模的量子计算机所运行的 Shor 算法。账户首次发送交易后，经典公钥会公开记录在链上，长期暴露会提高未来遭受密钥恢复攻击的风险。

对于已经运行的链，签名算法无法通过直接替换完成迁移。公钥参与账户地址派生，采用 PQC（Post-Quantum Cryptography）公钥通常会生成新地址；旧地址关联的余额、质押、合约权限、authz、feegrant 以及外部系统映射不会自动转移。钱包、交易所和托管系统也需要独立完成兼容性升级。

因此，账户迁移按地址是否允许变化分为两类：

- 可以更换地址的用户，迁移到原生 PQC 账户；
- 地址不能变化的用户，保留原地址并增加 PQC 第二因子。

## 2. 原生 ML-DSA 支持

[Cosmos SDK v0.55.0](https://github.com/cosmos/cosmos-sdk/releases/tag/v0.55.0) 和 [CometBFT v0.40.0](https://github.com/cometbft/cometbft/releases/tag/v0.40.0) 提供了符合 [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) 的 ML-DSA-65 支持。密码学实现来自 [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/sign/mldsa/mldsa65)；Cosmos SDK 与 CometBFT 在此基础上实现密钥接口、protobuf 编码、地址派生以及账户和共识验签流程。

| 实现层 | 实现范围 |
|---|---|
| [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/sign/mldsa/mldsa65) | ML-DSA-65 的密钥生成、签名和验签 |
| [CometBFT v0.40 `crypto/mldsa65`](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/mldsa65) | 定义 `PubKeyMlDsa65` 和共识签名接口，可将 ML-DSA 用作验证人共识密钥 |
| [Cosmos SDK v0.55 `crypto/keys/mldsa65`](https://github.com/cosmos/cosmos-sdk/tree/v0.55.0/crypto/keys/mldsa65) | 接入 protobuf codec、keyring、助记词恢复、地址派生和 [`x/auth` 原生验签](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/x/auth/ante/sigverify.go) |

### 2.1 账户层：原生 ML-DSA 交易签名

升级后的 `dorad` 可以直接创建原生 ML-DSA 账户：

```bash
dorad keys add alice-pqc \
  --key-type ml_dsa_65 \
  --keyring-backend os \
  --home ~/.dora
```

该账户地址由 ML-DSA-65 公钥派生，交易由对应私钥签名，Cosmos SDK 的 `x/auth` 使用账户公钥完成验证。ML-DSA-65 的安全性基于模块格困难问题，不依赖 secp256k1 和 Ed25519 使用的椭圆曲线离散对数假设。FIPS 204 对算法、参数和编码作出标准化定义，其目标是在经典和量子攻击模型下提供数字签名安全性。

### 2.2 共识层：ML-DSA 验证人密钥

[CometBFT v0.40 的 ML-DSA-65 实现](https://github.com/cometbft/cometbft/tree/v0.40.0/crypto/mldsa65) 实现了与 Ed25519 共识密钥一致的接口。共识参数允许 `ml_dsa_65` 公钥类型后，验证人可以使用 ML-DSA-65 私钥签署区块提案（proposal）和共识投票（vote），其他节点依据验证人集合中的公钥完成验签，区块 commit 记录相应的 ML-DSA-65 签名。该机制覆盖验证人身份认证和新区块的共识签名。

该升级不改变 CometBFT 的 BFT 共识流程和验证人运营地址，只替换验证人参与共识时使用的密钥与签名算法。已有验证人可通过 Cosmos SDK v0.55 的 [`MsgRotateConsPubKey`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/docs/architecture/adr-016-validator-consensus-key-rotation.md) 将新公钥绑定到原验证人，再由 ABCI validator update 更新 CometBFT 验证人集合，具体流程见 4.2。ML-DSA 公钥和签名的尺寸显著大于 Ed25519，生产部署前需重新评估区块容量、网络带宽、共识超时和密钥托管方案。

## 3. PQC Auth 补充认证模块

SDK 的原生 ML-DSA 适用于新账户，但无法在保留现有 secp256k1 地址的同时替换账户公钥。[`x/pqcauth`](https://github.com/DoraFactory/doravota/tree/pqc-auth/x/pqcauth) 用于处理此类兼容场景：账户地址和经典账户模型保持不变，ML-DSA 作为附加认证因子参与交易授权。

![IMG_8052](https://hackmd.io/_uploads/r1pq68VvGl.jpg)

模块仅保存 [公钥记录和账户策略](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/state.proto)，不保存用户私钥。每个账户可登记用于日常交易的 Signing Key、离线保存的 Recovery Key，以及强制认证状态、当前 key ID 和 policy version。注册、轮换、恢复、撤销和策略变更均通过 [专用生命周期消息](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/tx.proto) 执行，并在 H+1 生效，确保 CheckTx 与 DeliverTx 在同一高度使用一致的认证状态。

受保护交易保留标准 Cosmos 签名，并在 SDK 定义的 [`TxBody.critical_extension_options`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/proto/cosmos/tx/v1beta1/tx.proto) 字段中写入自定义 [`ExtensionPQCAuth`](https://github.com/DoraFactory/doravota/blob/pqc-auth/proto/doravota/pqcauth/v1/extension.proto)，其中包含每个 signer 对应的 ML-DSA 签名：

```text
secp256k1 经典签名
          AND
ML-DSA-65 第二因子签名
```

[Ante Handler 集成](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/ante.go) 在业务消息执行前完成验证：

1. 检查 extension 的唯一性、位置、canonical 编码、大小上限和 signer 数量上限；
2. 验证标准 Cosmos 签名；
3. 查询账户当前策略和 active ML-DSA key；
4. 重建确定性的 [`PQCSignDocV1`](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/types/canonical_tx.go) 并验证第二签名；
5. 两类签名均验证通过后，执行 bank、staking、Wasm 等业务消息。

`PQCSignDocV1` 绑定 chain/network、账户号、sequence、消息、fee、gas、signer 顺序、key ID 和 policy version，用于防止跨链重放、旧密钥重放和交易字段替换。Recovery Key 仅用于恢复 Signing Key，不参与日常交易；客户端或托管系统应采用离线存储或分片备份。

PQC 校验集中在 [`VerifyPQCDecorator`](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/ante/verify.go)，因此 bank、staking、Wasm 等业务模块无需分别集成 ML-DSA。生命周期消息只能作为顶层消息直接执行；消息指纹将 Ante 授权绑定到同一条消息，阻止通过 authz、group 或合约嵌套绕过证明校验。[`PrepareProposal` 和 `ProcessProposal`](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/proposal.go) 会再次执行认证检查，防止提议节点绕过 mempool 将无效交易纳入区块提案。

## 4. 技术迁移路径

整体迁移先完成应用与链上状态升级，再在目标版本上分批推进账户认证和验证人共识密钥迁移：

![image](https://hackmd.io/_uploads/HyJktQ4vze.png)

### 4.1 应用软件与链上状态升级

生产链不支持从 SDK v0.47 / IBC-Go v7 直接升级至 SDK v0.55 / IBC-Go v11。SDK v0.55 已移除部分依赖旧 `x/params` 的迁移代码和 Wasm 历史迁移实现，IBC-Go v11 也无法直接处理现有 IBC module version。Dora 旧版本还在 `upgrade/Consensus` 中保存了一份需要迁移的共识参数状态。

升级分为两个阶段：

```text
当前生产版本
SDK v0.47 / IBC-Go v7 / CometBFT v0.37
        │
        ▼
桥接版本
SDK v0.53 / IBC-Go v10 / CometBFT v0.38
迁移旧 params、IBC、Wasm 和共识参数状态
        │
        ▼
PQC 目标版本
SDK v0.55 / IBC-Go v11 / CometBFT v0.40
原生 ML-DSA + x/pqcauth
```

目标版本通过 [升级前置检查](https://github.com/DoraFactory/doravota/blob/pqc-auth/app/upgrades/v1_0_0/migration.go) 核对 module version map。桥接迁移未完成时，升级处理器将终止执行，防止历史状态迁移被遗漏而未显式报错。

### 4.2 迁移共识密钥

共识密钥轮换由 Cosmos SDK v0.55 的 [`MsgRotateConsPubKey`](https://github.com/cosmos/cosmos-sdk/blob/v0.55.0/docs/architecture/adr-016-validator-consensus-key-rotation.md) 和节点私钥切换共同完成，流程如下：

1. 治理提交 `cosmos.consensus.v1.MsgUpdateParams`，将 `ml_dsa_65` 加入共识参数中的验证人公钥类型白名单；
2. 验证人在隔离目录执行 `dorad init --consensus-key-algo ml_dsa_65` 生成新密钥，再用 `dorad comet show-validator` 导出新公钥；
3. 验证人运营账户提交 `dorad tx staking rotate-cons-pub-key '<new-pubkey-json>' --from <operator>`。SDK 检查密钥类型、重复使用、轮换历史和费用，并在 staking 状态中记录新公钥；运营账户启用 `x/pqcauth` 时，该交易同时接受经典签名和 ML-DSA 签名验证；
4. 交易返回 `apply_height` 后，验证人备份原 `priv_validator_key.json`，并在计划窗口安装新私钥。staking 模块通过 `ValidatorUpdate` 移除旧共识地址并加入新地址；
5. 节点重启后，分别查询 staking validator、CometBFT `/validators` 和 `/block?height=...`，确认新公钥已进入验证人集合，且区块 `commit` 中包含新地址的 ML-DSA 签名，再执行下一位验证人的轮换。

生产环境应逐个轮换，并持续保持超过三分之二的投票权在线。[多节点模拟脚本](https://github.com/DoraFactory/doravota/blob/pqc-auth/scripts/rehearse-multinode-pqc-upgrade.sh) 按照“提交交易 → 读取生效高度 → 停止单个节点并安装新私钥 → 由其他节点跨过生效高度 → 重启并验证区块”的顺序完成了四个验证人的轮换。

### 4.3 账户迁移

账户迁移按地址和业务状态约束分流：

- 新建账户直接采用 SDK 原生 ML-DSA 密钥；
- 可更换地址的存量账户，将余额和业务权限迁移至新的 ML-DSA 地址；
- 地址不能变化的账户，启用 `x/pqcauth` hybrid 双签；
- 支持变更 owner、admin 或 operator 的业务，应提供显式地址替换流程。

网络策略首先运行于 `OPTIONAL` 模式，为钱包和用户提供接入窗口；随后切换至 `REQUIRED_FOR_REGISTERED`，对已注册账户强制执行双签。首次注册窗口可持续开放，避免未迁移账户被永久阻断。

下一节给出四验证人网络的模拟结果。

## 5. 多节点升级模拟与性能数据

测试环境在一台高性能服务器上运行 4 个隔离的验证人进程、4 个普通钱包和 4 个验证人运营账户。每个节点使用独立的节点目录（node home）、数据库、端口和共识私钥，并按 SDK v0.47 → v0.53 → v0.55 的顺序完成两阶段升级。两次升级后，四个节点的 App Hash 均保持一致。该环境用于验证多验证人状态机和密钥轮换流程，不覆盖跨主机延迟、丢包及故障域隔离测试。

测试覆盖 PQC Auth 注册、混合认证交易和验证人共识密钥轮换。受保护账户的经典单签交易按预期被拒绝，包含有效 ML-DSA 签名的交易执行成功；四次 Ed25519 → ML-DSA-65 共识密钥轮换均在提交高度 H+2 生效。轮换后，验证人集合中的公钥类型全部为 `cometbft/PubKeyMlDsa65`，全节点重启后继续正常出块。测试共记录 53 笔成功上链交易，其中包括两个原生 ML-DSA 账户直接签署的 4 笔转账。

性能对比统一使用 SDK v0.55 二进制和标准 `MsgSend`，每组包含 4 笔成功交易。交易大小按 RPC 返回的原始 protobuf 字节数统计：

| 测试阶段 | 账户认证 | 共识密钥 | 单笔交易大小 | Gas 消耗 |
|---|---|---|---:|---:|
| 经典基线 | secp256k1 | Ed25519 | 314 B | 75,241 |
| PQC Auth 混合认证 | secp256k1 与 ML-DSA-65 | Ed25519 | 3,730 B | 376,597 |
| PQC Auth 混合认证 + ML-DSA 共识 | secp256k1 与 ML-DSA-65 | ML-DSA-65 | 3,731 B | 376,607 |
| 原生 ML-DSA 账户 + ML-DSA 共识 | ML-DSA-65 | ML-DSA-65 | 5,483–5,485 B | 首笔 282,691；后续 228,941 |

PQC Auth 交易包含 3,309 B 的 ML-DSA-65 签名，单笔交易因此增加约 3.4 KB。原生 ML-DSA 交易还需在 `SignerInfo` 中携带 1,952 B 公钥，交易体积进一步增加。其后续交易的 Gas 低于混合认证交易，因为验签路径仅包含原生 ML-DSA，不包含 secp256k1 验签和 PQC Auth 配置为 250,000 gas 的 extension verification。

共识签名不属于交易原始字节，因此共识密钥轮换基本不影响同类混合认证交易的大小和 Gas。新增开销位于区块 commit：Ed25519 单签名为 64 B，ML-DSA-65 单签名为 3,309 B；在四验证人网络中，commit 签名总量从 256 B 增至 13,236 B，相当于每个区块增加约 13 KB 固定开销。生产部署需根据实际验证人数量继续测试满块吞吐、P2P 带宽和共识超时。

上述流程已固化在 [多节点升级模拟脚本](https://github.com/DoraFactory/doravota/blob/pqc-auth/scripts/rehearse-multinode-pqc-upgrade.sh) 中；脚本会保存全部交易、节点日志、共识密钥轮换证据，并自动生成交易大小与 Gas 对比报告。

## 6. PQC-IBC 双链兼容性实验

我们在两条独立 Dora 链上建立了 IBC client、connection 和 ICS20 channel，并将两条链的验证人共识密钥依次从 Ed25519 轮换为 ML-DSA-65。轮换前后均完成了双向转账、client update、`RecvPacket` 和 `Acknowledgement`，现有 IBC client 无需删除或重建。

实验使用旧验证人集合签署的过渡 Header，先向对端承诺下一高度的 ML-DSA 验证人集合，再提交首个由新集合签署的 Header。PQC-aware relayer 负责构造和中继 ML-DSA Header，相关 IBC 交易由原生 ML-DSA-65 relayer 账户签署。

| 验证项 | 结果 |
|---|---|
| 共识密钥轮换前后双向 ICS20 中继 | 通过 |
| ML-DSA Header、validator set 与 commit 验证 | 通过 |
| 原生 ML-DSA relayer 账户签名 | 通过 |
| IBC Header 大小 | 855 B → 11,794–11,796 B，增加约 10.9 KiB |

该结果验证了真实 CometBFT、RPC、IBC proof 和状态机路径的兼容性，但不代表已经覆盖生产规模验证人集合、跨机房网络和全部 IBC 应用。

## 7. 端到端抗量子安全的剩余工作

账户签名和共识签名完成 PQC 迁移后，仍需处理钱包、业务状态、跨链协议和运维基础设施中的经典密码依赖：

- 钱包与托管集成：Keplr、硬件钱包、交易所和托管系统需支持原生 ML-DSA、PQC Auth 扩展字段、密钥轮换和恢复；
- 认证策略：全局 `REQUIRED` 当前仍要求原生 ML-DSA signer 提供 PQC Auth 扩展字段；Ante 应识别原生 ML-DSA 账户签名，并将其视为满足 PQC 认证要求；
- 业务状态迁移：staking、vesting、合约管理员、authz、feegrant、DAO 和 ICA 等地址绑定状态需要迁移接口，同时应排查合约内部使用 secp256k1 或 Ed25519 验签的逻辑；
- 共识密钥托管：验证人基础设施需支持 ML-DSA 的 HSM、remote signer、备份和事故恢复；
- 跨链验证：IBC light client、relayer、对端链和跨链应用均需验证 ML-DSA 共识公钥的兼容性；本链升级不会自动改变跨链路径的安全属性；
- 地址与哈希：原生 ML-DSA 地址仍沿用 Cosmos 的截断公钥哈希规则，应根据目标量子安全等级评估是否引入更长且带版本的地址格式；
- 网络与发布：P2P 节点身份、RPC TLS、升级包和发布签名仍可能依赖经典密码，这些组件属于完整运维安全边界；
- 性能与审计：应根据生产验证人数量重新标定 Gas、区块大小、P2P 带宽和 proposal timeout，并完成独立密码学审计、升级审计与依赖漏洞清理。

建议先为新账户启用原生 ML-DSA，再为必须保留地址的存量账户配置 PQC Auth 混合认证，并分阶段迁移共识密钥、业务权限和生态工具。存量账户无需在同一升级高度完成全部迁移。

进一步了解模块细节可阅读 [PQC Auth 模块说明](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/README.md) 和 [实现导读](https://github.com/DoraFactory/doravota/blob/pqc-auth/x/pqcauth/implementation.md)。
