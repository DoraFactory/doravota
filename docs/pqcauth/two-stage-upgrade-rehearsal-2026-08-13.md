# PQC 两阶段升级本地演练报告（2026-08-13）

## 结论

本次在全新、隔离的单验证人网络上完整重放了生产形态的两阶段升级，结果为
`PASS`：

1. Dora Vota v0.4.4（Cosmos SDK v0.47.17 / CometBFT v0.37.5）；
2. `sdk-v0.53-bridge`（SDK v0.53.6 / CometBFT v0.38.21 / IBC-Go v10.5.0）；
3. `v1.0.0` 目标版（SDK v0.55.0 / IBC-Go v11.2.0 / `x/pqcauth`）。

演练使用同一份 node home 和 application database，在两个链上治理高度分别
停机并替换二进制，没有使用 genesis export/import 绕过模块迁移。

## 关键高度与状态

| 项目 | 结果 |
| --- | --- |
| 桥接升级高度 | 32 |
| PQC 目标升级高度 | 72 |
| 导出后重启并继续出块 | 87 |
| 测试账户 | `dora152syd6uedel7vql8klpq4c4dhpx0ufs02cvnnu` |
| 最终结果 | PASS |

桥接阶段确认执行了累计迁移，其中包括 `gov 4→5`、`ibc 4→8`、
`interchainaccounts 2→3`、`transfer 3→6`、`auth 4→5`、`staking 4→5`
和 `slashing 3→4`。目标阶段随后完成 SDK v0.55 的累计迁移，并初始化
`pqcauth` 与目标版本所需的新 store。

## PQC 功能验证

目标版启动后依次完成：

1. 目标升级后先发送一笔经典签名转账，证明未注册账户仍可正常使用；
2. 生成 ML-DSA-65 signing key 与 recovery key；
3. 为两把 key 生成绑定账户、链 ID、network ID、角色和 key ID 的 PoP；
4. 发送 `MsgRegisterKey` 并启用 `self_enforced`；
5. 等待 H+1，确认 signing key ID 1、recovery key ID 2 和 policy version 1 生效；
6. 再发经典单签交易，Ante 以 `pqcauth` code 11 拒绝；
7. 对普通 bank tx 生成 canonical PQC bundle，用经典私钥和 ML-DSA 私钥完成
   混合签名；
8. 广播后成功上链，gas wanted/used 为 `800000/376919`；
9. 导出完整 genesis，确认 PQC 参数及完整共识参数存在；
10. 使用同一数据库重启目标二进制，继续正常出块。

## 交易证据

| 交易 | 高度 | code | tx hash |
| --- | ---: | ---: | --- |
| 第一阶段升级提案 | 3 | 0 | `866AFB572CCD4498A4DF96CAEF6498F05C7CD913683CB9720AC1A968CB566210` |
| 第一阶段投票 | 4 | 0 | `8B9F3198DB274DA18A84DD427345B9CD644CAEE4CE88400DFB4E65C7D275E465` |
| 桥接版经典转账 | 37 | 0 | `422C3C2A3C8E9D7A93404E889C8145E16B54E3945946B9D882238A430A49A93B` |
| 第二阶段升级提案 | 39 | 0 | `7D4F15244ABB921C53194DF11BF87824A0D354D5BB4BBD4033842B831BCBDD6F` |
| 第二阶段投票 | 41 | 0 | `F77DD586626430D6A2A55A9AF8DAEEE3D2320F192065B0A50119C68CFF8A0161` |
| 目标版经典转账 | 76 | 0 | `C1E9F32E89ABD85E664EDE43DA5B5F0A92F6A2B75EFC82C0323D1CD5381F4197` |
| PQC 注册 | 80 | 0 | `B5CE249AD49E1F6EE6263BA82E0728103F253D634ADF044737F732A52CAA4A94` |
| self-enforced 后经典单签 | CheckTx | 11（预期拒绝） | `7BB46DA1D3F3AED4604DBAC41972FBE17DE182986D6150F9F8F3471036E9C1C6` |
| 经典 + ML-DSA 混合签名转账 | 84 | 0 | `91151D1082A46FE20A3C7630797AFC86BE905FFDD95389544B5506D04B3FA0A9` |

这是一次本地临时网络，节点在验收后已停止，因此交易 hash 不是公共浏览器链接。
原始日志、回执、PQC bundle、导出状态和机器可读总结保存在
`/private/tmp/doravota-two-stage-final8/`。

## 演练中发现并修复的问题

首次导出暴露了一个 Dora 特有的共识参数存储兼容问题。v0.4.x 虽然已经使用
`x/consensus` keeper，但 keeper 实际挂在 `upgrade` store，参数记录位于
`upgrade/Consensus`；SDK 通用的 v0.47 迁移示例只处理 `baseapp` x/params，无法
覆盖该布局。

桥接 handler 现在优先从这个真实旧位置读取并解码完整参数，写入 v0.53 的专用
`consensus` store；如果记录损坏则 fail closed，而不是生成部分参数继续运行。
修复后已验证 block、evidence、validator、version 与 ABCI 参数能够通过第二阶段
升级、状态导出和重启。

## 覆盖范围与上线前剩余工作

本次证明单验证人、合成状态下的二进制兼容、治理停机、模块迁移、PQC 生命周期、
导出与重启路径可用。它不替代以下上线门禁：

- 使用真实生产快照做两阶段演练；
- 至少四验证人的统一 app hash、延迟升级节点追块和回滚演练；
- IBC channel/client、ICA、CosmWasm 合约状态的真实业务回归；
- 接近 block gas 上限的 ML-DSA 批量性能和 proposal timeout 压测；
- 依赖漏洞清理、可复现构建和最终发布二进制哈希确认。
