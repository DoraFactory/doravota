# 0.4.4 主网快照四节点隔离演练记录

> 本文保留升级前的 0.4.4 基线结果。后续已完成隔离链升级，最新状态见 [SDK 0.53 升级演练报告](sdk-053-snapshot-upgrade-2026-09-11.md)。

## 当前结果

2026-09-11，在 `amaci-testnet-operator`（77.42.3.141，用户所指的 amaci-test-operator）恢复 ITRocket 原始数据库快照，建立四个使用新测试共识密钥的 0.4.4 验证节点，已持续出块并通过单节点停机、全节点重启及同高度一致性检查。

- Ping.pub：<http://77.42.3.141:18080/vota-snapshot/block>
- 只读 RPC：<http://77.42.3.141:18081/status>
- 只读 REST：<http://77.42.3.141:18082/cosmos/base/tendermint/v1beta1/node_info>
- 链 ID：`vota-snapshot-rehearsal-20260911`。
- 服务器目录：`/root/doravota-snapshot-rehearsal-20260911`。
- 容器：`vota-snapshot-node0` 至 `vota-snapshot-node3`、`vota-snapshot-pingpub`；配置为自动重启。

**当前仅完成 0.4.4 基线环境。没有执行 0.53 升级，也没有修改主网。** 不应据此认定迁移、真实交易、跨链收发或长时间稳定性测试通过。

## 输入与版本

- 来源：<https://itrocket.net/services/mainnet/doravota/>；实际下载服务器由页面脚本配置解析，为 `server-1.itrocket.net`。
- 快照：`doravota_2026-09-11_17249823_snap.tar.lz4`，下载时最新，约 4.8 GB 压缩、7.1 GB 解压。包含 application/state/blockstore 数据库及 Wasm 文件。
- SHA-256：`ace45e16775385c6483d03a884f7f3756edbc2af0bbf1b694737b90b812d2ff6`。这是本次下载后计算的校验值，不是供应方签名认证。
- 原始应用和共识高度均为 `17249823`；二者 App Hash 均为 `33C38FB34DF70094118170FD0640A05BF5B4600BDED0CB38DFF5AFB51EDE5499`。
- 运行程序由 `0.4.4` 源码提交 `1b0774785111d8a6e693cd155053c19a5a1d8bdc` 构建：SDK `0.47.17`、CometBFT `0.37.5`、WasmVM `1.5.1`，Linux amd64 / Go `1.26.5`。
- 此程序是本次源码构建的基线，不是已经完成验收的 0.53 CI 发布包。源码与一次性工具在服务器 `source-v044`；运行文件在 `bin`，哈希见证据。

## 如何从快照独立出块

没有通过 export/import 建新链替代数据库迁移测试。原始压缩包、`pristine` 解压副本保留，实际操作在复制的节点 home 上进行。

一次性离线工具 `source-v044/cmd/snapshot-fork/main.go` 使用 0.4.4 keeper 读取原始数据库，并：

1. 为原活跃验证人中投票权最高的四个生成全新测试共识密钥，更新对应索引和签名信息，保留其 operator 地址、委托关系和真实投票权。
2. 将最大验证人数设置为 4，通过 staking keeper 更新验证人集合；其余验证人的退出引起质押池之间的正常模块资金转移。
3. 提交一个**人工准备检查点 `17249824`**，更新测试共识集合、chain ID、签名及 CometBFT 缓存的 genesis。该检查点不是主网真实区块，也不是 0.53 迁移区块。正常四节点共识从 `17249825` 开始。
4. 比较检查点前后的模块存储根，仅允许预期的 staking/slashing/bank/params 变化，否则停止准备。本次实际变化为 `staking`、`slashing`、`bank`。

`acc`、`authz`、`capability`、`consensus`、`distribution`、`evidence`、`feegrant`、`feeibc`、`gov`、`group`、`ibc`、`icacontroller`、`icahost`、`mint`、`params`、`transfer`、`upgrade`、`wasm` 的存储根保持一致。详见 [fork-report.json](evidence/snapshot-20260911/fork-report.json)。这些比较针对离线准备检查点；正常出块后奖励等状态会继续变化。

四节点均只监听本机 P2P 地址，seeds 为空、PEX 关闭，三个对端均为 `127.0.0.1`。没有导入主网私钥，没有连接主网 peers 或运行 relayer。公网仅发布浏览器和只读代理；RPC 代理不开放广播及管理方法。

## 已完成验证

| 检查 | 结果 |
|---|---|
| 快照恢复与 0.4.4 加载 | 应用/共识高度与 App Hash 一致；原快照有 21 个活跃验证人 |
| 四节点正常出块 | 高度 `17249853` 四节点 block hash、App Hash 完全一致，各有三个本机对端 |
| 停一个节点 | 停 node3 期间，其余节点从 `17249860` 推进至 `17249865`；随后恢复 node3 |
| 全部节点重启 | 重启前 `17249875`，重启后推进至 `17249922` |
| 重启后一致性 | 同高度 `17249921` 四节点 block hash、App Hash 完全一致 |
| 业务状态只读抽查 | 4 个活跃测试验证人；18 条 IBC channel；已知 ICS-721 合约仍可查询，code ID 为 98 |
| 浏览器实际验证 | Ping.pub 显示演练提示、实时区块、4 验证人、0.4.4 和正确的测试 chain ID；已截图 |

首次准备发现检查点签名时间未递增、CometBFT 的 genesis 缓存仍为主网名称；修正工具后从原始快照重新生成，使用新测试密钥，未在失败副本上继续演练。四节点启动还暴露默认 pprof/grpc-web 端口冲突，已关闭这两个未使用服务并重启验证。

旧 Dora IBC 演练节点和相应浏览器容器已停止并移除；旧 pqcauth 浏览器已停止，18080–18082 改为本次浏览器。旧运行数据/源码保留，未清空其他 AMACI、prover 或 operator 数据。

## 下一步

1. 冻结并验证最终 0.53 Linux 候选产物，记录完整源码状态、构建信息及 SHA-256。
2. 在当前四节点共同高度停止并制作新的 **0.4.4 演练基线备份**，连同测试签名状态保存。
3. 在隔离链安排 `sdk-v0.53-bridge`，演练旧版本停机、新版本迁移、恢复出块和重复重启。
4. 对同高度各节点状态及升级前后业务状态做核对，执行真实交易、Wasm 和受控对端 IBC 测试，覆盖 channel-16 及 feeibc/capability 去除后的行为。

当前没有执行步骤 3，也未为此发起主网治理提案。四节点同机测试不能替代跨机器网络故障、磁盘故障及真实验证人操作演练。

证据目录：[snapshot-20260911](evidence/snapshot-20260911/)。服务器 `evidence` 另保留下载、解压、准备和查询日志；测试私钥只留在服务器，不纳入文档或版本控制。
