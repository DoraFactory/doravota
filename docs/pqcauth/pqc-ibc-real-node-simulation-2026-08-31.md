# PQC-IBC 双链真实节点模拟报告

## 1. 结论

本次高性能机器模拟结果为 **PASS**。

测试在两条独立 Dora 链上完成了真实 IBC 客户端、连接和 ICS20 通道建立，并在两条链的验证人共识密钥分别由 Ed25519 轮换为 ML-DSA-65 后，继续完成双向 IBC 转账、客户端更新、`RecvPacket` 和 `Acknowledgement`。这证明当前实现能够在真实 CometBFT/RPC/IBC 状态机中识别和验证 ML-DSA-65 共识头，而不只是通过内存单元测试。

本报告所称“完整 IBC”指本次范围内的 ICS20 端到端数据流；它不等同于已经覆盖所有 IBC 应用、跨机房网络条件和生产规模验证人集合。

## 2. 模拟环境

| 项目 | 配置 |
| --- | --- |
| 服务器 | `amaci-testnet-operator`，20 CPU、62 GiB 内存 |
| Chain A | `dora-pqc-ibc-a-1`，RPC `127.0.0.1:26657` |
| Chain B | `dora-pqc-ibc-b-1`，RPC `127.0.0.1:36657` |
| 节点资源限制 | 每节点 10 CPU、30 GiB 内存 |
| IBC client | 两端均为 `07-tendermint-0` |
| ICS20 channel | 两端均为 `channel-0` |
| Relayer 交易账户 | 原生 ML-DSA-65 账户 |
| 运行目录 | `/root/doravota-pqc-ibc-real/20260831T025430Z` |
| 机器证据 | `artifacts/result.json`、`artifacts/report-zh.md`、节点日志及交易回执 |

运行结束后两个容器保持在线，便于继续查询：

- `dora-pqc-ibc-a-20260831T025430Z`
- `dora-pqc-ibc-b-20260831T025430Z`

### 2.1 区块浏览器

- [Chain A PingPub](http://77.42.3.141:18180/dora-pqc-ibc-a-1)
- [Chain B PingPub](http://77.42.3.141:18280/dora-pqc-ibc-b-1)

两个浏览器使用独立的前端、RPC 代理和 REST API 代理。以下链接可以直接查看一组完整的轮换后双向 IBC 交易：

- A → B：[Chain A Transfer](http://77.42.3.141:18180/dora-pqc-ibc-a-1/tx/9B142DC5E012A3926FF96089D18434E983B96773307F869A8AEDDE2F5D2E3896) → [Chain B RecvPacket](http://77.42.3.141:18280/dora-pqc-ibc-b-1/tx/B138A0915C1D64656A643FC238E9787664A6F6E107C8E47CA39737AC4A73020F)
- B → A：[Chain B Transfer](http://77.42.3.141:18280/dora-pqc-ibc-b-1/tx/699540A732AFE5C291CA1FD4AD716BA365441DFFE9B0574FA95C14A519440C53) → [Chain A RecvPacket](http://77.42.3.141:18180/dora-pqc-ibc-a-1/tx/E607681AE7164BC59673E4370BF816682C091C1FCF31512BA5B93AE123791012)

第 4 节中的其他交易也可以把哈希追加到相应链的 `/<chain-id>/tx/<hash>` 路径查看。

## 3. 测试流程

1. 以 Ed25519 共识密钥启动 Chain A 和 Chain B。
2. 使用标准 Cosmos Relayer 建立两个 IBC client、connection 和 ICS20 channel。
3. 使用原生 ML-DSA-65 relayer 账户发起并中继轮换前的 A → B 转账。
4. 两条链分别通过治理提案，把 `ml_dsa_65` 加入允许的验证人公钥类型。
5. Chain A 提交 `MsgRotateConsPubKey`，先向 Chain B 中继 H+1 生效前的过渡 header，再安装新的 ML-DSA-65 私钥并重启节点。
6. Chain B 使用同样流程完成轮换。
7. 确认两端验证人公钥类型均为 `cometbft/PubKeyMlDsa65`。
8. 使用 PQC relayer 完成轮换后的 A → B 和 B → A 双向 ICS20 转账，包括 client update、packet proof、`RecvPacket`、ack proof 和 `Acknowledgement`。
9. 检查全部交易 `code = 0`，并确认两条链继续出块。

## 4. 核心交易记录

### 4.1 IBC 握手

| 顺序 | 交易哈希 |
| --- | --- |
| Create Client A | `3905BC568FF25DB459A0006EABFFA9BC0F34BE226E575BE825C0F31F0F1DFE87` |
| Create Client B | `61E5BA76FF5CD37A4D89DADD6E928415E2481D2B0EE29B8B1FBF8723917D14C3` |
| Connection Open Init | `6308EE169D999C5BFCC7AF46C284B228CB4BE27A9441B84FF3BBF5DE9EFF6DDF` |
| Connection Open Try | `9C404F5AB206BA846AB7A1DBE5BF103123102ED35BABE1FB858CED5240F923BB` |
| Connection Open Ack | `84E17A866ECEAD41FA8B0B25991E0B0365F3AD870A7C09B72DB3B2318167A11E` |
| Connection Open Confirm | `F5B1224101DAD2A9A2209825B80B2D3D58336FC88A48CB1647742CEF3E3089CA` |
| Channel Open Init | `DA364247062CF0044AA2638E18B49490AE426EBB0CF0A594C7726AE9A03A15E5` |
| Channel Open Try | `861F252780CB4AA37699218DC59672D356C33A2151CC3349F77EE6D04B17792B` |
| Channel Open Ack | `BE496FF853F1775B93AC9AB827FEFFCAA9607E99D5A35C1C902B20C1E7B9B7AF` |
| Channel Open Confirm | `92ED9786CDC16F6E4150687343486E78A7C7F114AF0FDB1084DAF594B9748F3F` |

### 4.2 开启 ML-DSA-65 共识密钥类型

| 链 | 提案 | Submit Proposal | Vote |
| --- | ---: | --- | --- |
| Chain A | 1 | `BEB6C9C89F265EDB888AC6464F8A88EB0C3A3900DBA116F3416FFB7DDA9D4B6D` | `9F9C27FEBD2A75C97DD529994B7FE3F933386D343E7AE0ED4FE20ADA0BFCC8FD` |
| Chain B | 1 | `0C2C2F481B6DA51586CC90CDB10A7760A9526CF4C19CDE67520B86497944419A` | `4F8BAA80840AE8E021DF5480E214886087D411889873AAB391A6F0B309B37912` |

### 4.3 共识密钥轮换

| 链 | 轮换交易 | 过渡高度 | 生效高度 | 过渡 header 更新 | 轮换后 header 更新 |
| --- | --- | ---: | ---: | --- | --- |
| Chain A | `B9B3A10227DF1E0F478A2934431932D5C0E66E0BCA916AD002458050A6BC40FD` | 62 | 63 | `F5134B4A3242FDD4F7D68732C2F574A913A1304DD2D3D68FD9FFFAB7EA322DF7` | `DCB492FA2D0F6D6E5B73BF264AA58BB1FB531466C7237DDCCC1B1121584FCEB8` |
| Chain B | `2244439830C58D5BDAB6734B6EED99D013983B5A8B97D75A4DB5B851908AC41E` | 69 | 70 | `DA84A30A449EFEED2C09A4FF9D1B971704588FF969B722E284941FB737B0CC8E` | `44015BDAC8570E8B22C2294BC763E409599F101C98F8D8DA2C1042E2265DDA33` |

### 4.4 ICS20 转账与中继

| 阶段 | 动作 | Chain | 交易哈希 | Gas used |
| --- | --- | --- | --- | ---: |
| 轮换前 A → B | Transfer | A | `21B06A679049AF2BD5E39F739E8212C0231CCCD2AF426DDA7F49F61B1C9F19E7` | 334,671 |
| 轮换前 A → B | Update destination client | B | `36E3EC0B672937F540031D416A6F26CE88421B314EAC178BD34BFAAFE0D396C4` | 321,269 |
| 轮换前 A → B | RecvPacket | B | `768B3B2F5223DECDFC43ADCD1735EA2EA135E513825D5746423B63EAEE8EEE4B` | 309,811 |
| 轮换前 A → B | Update source client | A | `23721B018A321E9B521EE65898194A2183A31B2641B71B436673CA110AE4C96E` | 267,819 |
| 轮换前 A → B | Acknowledgement | A | `B13858469387E0541D85051E16CFAE4D7BF9ABE16224EC0CBBEAFD819A6FE49F` | 236,132 |
| 轮换后 A → B | Transfer | A | `9B142DC5E012A3926FF96089D18434E983B96773307F869A8AEDDE2F5D2E3896` | 270,580 |
| 轮换后 A → B | Update destination client | B | `BBD2467E397E52B5029C8ADBC7B31EEB0E56484F2581187CDDC4BD2C19DCFD93` | 377,220 |
| 轮换后 A → B | RecvPacket | B | `B138A0915C1D64656A643FC238E9787664A6F6E107C8E47CA39737AC4A73020F` | 285,076 |
| 轮换后 A → B | Update source client | A | `7AABCA9A488A879328AC8BB007A61BEACD7D4B3A9EF7541B7DC9F568424B4520` | 377,170 |
| 轮换后 A → B | Acknowledgement | A | `AFC13CE45B1B21D736CDC04FBD1252C17B435C2A2573BF7F96A303881FE7E0C1` | 236,176 |
| 轮换后 B → A | Transfer | B | `699540A732AFE5C291CA1FD4AD716BA365441DFFE9B0574FA95C14A519440C53` | 281,221 |
| 轮换后 B → A | Update destination client | A | `421092D1BA1E4F5BCA7E71FE01C7B5515166F4FA7CEDB2EEE9B7FAA31D88D24F` | 377,170 |
| 轮换后 B → A | RecvPacket | A | `E607681AE7164BC59673E4370BF816682C091C1FCF31512BA5B93AE123791012` | 310,315 |
| 轮换后 B → A | Update source client | B | `1BBECE8B0F9F00BEB2650F9D9C40E644056B71AB7FAD3EEF615A9DA44A02AB92` | 377,229 |
| 轮换后 B → A | Acknowledgement | B | `925F21C21C8A2BA1501A0360927D86A78E40DC4783793C33030432203501DFBD` | 235,742 |

## 5. ML-DSA IBC 开销

在相同的单验证人拓扑中，Ed25519 和 ML-DSA-65 Tendermint header 的实测对比如下：

| 指标 | Ed25519 | ML-DSA-65 | 变化 |
| --- | ---: | ---: | ---: |
| IBC header 序列化大小 | 855 B | 11,794–11,796 B | 约 13.8 倍，增加约 10.9 KiB |
| 单独 client update gas | 267,819 | 377,170–377,229 | 增加约 109,351，约 40.8% |

转账、`RecvPacket` 和 acknowledgement 的 gas 不宜直接用轮换前后单笔数据判断 ML-DSA 成本，因为第一笔账户交易包含公钥写入，且每笔 IBC 状态高度和证明内容不同。共识迁移最稳定的增量来自 validator set、commit signature 和 IBC client update。

## 6. 真实节点模拟中发现并修复的问题

1. `dorad init` 生成的 `initial_height` JSON 类型与 CometBFT v0.40 的解析要求不一致，启动前需规范化为字符串。
2. 默认 `minimum-gas-prices` 不适合隔离测试网，脚本显式设置为 `0peaka`。
3. Relayer path JSON 不返回 channel ID，改为从链上 channel 状态发现。
4. 自定义 relayer 的 CLI flag 原先绑定到局部结构体副本，解析后配置为空；已改为返回指针并增加回归测试。
5. IBC packet 和 acknowledgement proof 不能直接在交易高度读取，必须等待下一高度再查询状态证明。
6. ML-DSA-65 验证人类型必须先通过链上治理加入 consensus params，不能只替换本地私钥。
7. 单验证人 H+1 轮换时，必须在旧节点仍在线时先把过渡 header 更新到对端，再停止节点、安装新私钥并重启，否则对端无法连续验证信任根。

## 7. 当前边界与后续验证

本次模拟验证了真实二进制、真实状态机、真实 IBC proof 和真实 ML-DSA-65 共识头，但仍有以下边界：

- 两条链运行在同一物理服务器，未模拟跨地域网络延迟、丢包和分区。
- 每条链只有一个验证人，未测多验证人集合下 commit 体积、轮换排序和阈值变化。
- 只覆盖 ICS20 transfer，尚未覆盖 ICA、ICQ、Wasmd IBC 回调和 timeout 路径。
- 尚未在生产规模验证人数量下标定 block max bytes、client update gas 和 relayer吞吐。

因此，本次结果可作为 PQC-IBC 协议兼容性和真实节点可运行性的通过证据；生产发布前仍需补充多验证人、故障注入、跨机房和长期稳定性测试。
