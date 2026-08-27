# 双节点 PQC 容量基准测试

本测试会启动两个受 Docker 资源约束的 Doravota 验证节点，分别测量以下三类交易在区块接近满载时的表现：

- 经典 secp256k1 交易；
- PQC Auth 混合双因子交易；
- Cosmos SDK 原生 ML-DSA-65 交易。

两个验证节点的共识密钥均使用 ML-DSA-65。

默认服务器配置为：第一个验证节点使用 CPU `0-7`，第二个验证节点使用 CPU `8-15`，每个节点分配 24 GiB 不可交换内存；CPU `16-19` 留给测试数据生成和交易发送。两个容器共享宿主机内核、存储和回环网络，因此该测试适合复现单机资源约束下的容量表现，但不能替代多机网络延迟和容错测试。

压测工具会为每笔交易创建一个独立的、已注资的创世账户。这样可以避免 Cosmos 有序内存池中的 sequence 冲突：如果同一账户在区块提交前连续发送多笔交易，后续交易可能因 sequence 尚未更新而无法进入内存池。测试私钥由确定性方式生成，只能用于一次性测试网络，严禁用于其他环境。

默认单笔交易 gas limit 已为账户首次写入状态预留余量：

- 经典交易：120,000；
- PQC Auth 混合交易：400,000；
- 原生 ML-DSA 交易：320,000。

任何 `DeliverTx` 失败都会使测试整体失败。

在目标 Linux 服务器的项目根目录执行：

```bash
PQC_CAPACITY_WORK_DIR=/root/pqcauth-capacity-$(date -u +%Y%m%dT%H%M%SZ) \
  ./tests/performance/pqcauth-two-node/run.sh
```

测试工作目录会保存以下数据：创世账户清单、`CheckTx` 结果、逐区块交易数/字节数/gas 数据、Docker CPU 与内存采样、ML-DSA gas 标定结果、验证节点日志，以及汇总文件 `capacity-summary.json`。

脚本使用任意精度整数重新计算创世银行总供应量，因此 DORA 的 18 位小数质押金额不会被 JSON 工具舍入。

可以通过环境变量调整默认配置，常用参数包括：

- `PQC_CAPACITY_CLASSIC_COUNT`：经典交易数量；
- `PQC_CAPACITY_HYBRID_COUNT`：PQC Auth 混合交易数量；
- `PQC_CAPACITY_NATIVE_COUNT`：原生 ML-DSA 交易数量；
- `PQC_CAPACITY_NODE_MEMORY`：每个验证节点的内存上限；
- `PQC_CAPACITY_BUILD_CACHE`：多个一次性测试复用的 Go module 和编译缓存目录。

三个 CPU 集合参数及其他完整配置见 `run.sh` 文件开头。

## 稳态与恶意流量测试

同一套双节点网络还可以运行持续在线的稳态和恶意流量测试。有效交易默认由以下比例组成：

- 40% 经典交易；
- 30% PQC Auth 混合交易；
- 30% 原生 ML-DSA 交易。

测试会依次按计划中的区块 gas 容量运行 30%、60% 和 90% 三档负载，然后在维持 60% 有效交易负载的同时，并发发送以下预期应被拒绝的恶意交易：

- 长度正确但签名内容无效的 ML-DSA 签名；
- 超过字节上限、但编码规范的 pqcauth extension；
- 非规范 protobuf 编码；
- 经典签名有效、但账户 sequence 错误的交易。

默认工程测试中，每个阶段持续 2 分钟，恶意流量发送速率为每秒 300 笔。持续时间和速率均可配置。正式发布前的稳定性测试应至少持续 1—2 小时，不能把默认短时测试视为长时间稳定性结论。

执行命令：

```bash
PQC_CAPACITY_PROFILE=stress \
PQC_CAPACITY_WORK_DIR=/root/pqcauth-stress-$(date -u +%Y%m%dT%H%M%SZ) \
  ./tests/performance/pqcauth-two-node/run.sh
```

可以使用以下环境变量调整负载方案：

- `PQC_STRESS_DURATION`：每个稳态阶段的持续时间；
- `PQC_ADVERSARIAL_DURATION`：恶意流量阶段的持续时间；
- `PQC_ADVERSARIAL_RATE`：每秒恶意交易数量；
- `PQC_STRESS_TARGETS`：稳态负载目标；
- `PQC_STRESS_VALID_WEIGHTS`：三类有效交易的比例；
- `PQC_STRESS_ATTACK_WEIGHTS`：各类恶意交易的比例。

生成的 `stress-summary.json` 会记录交易确认延迟、出块间隔、共识轮次、吞吐量、gas、交易字节数和执行失败情况。

确认延迟以实时观察程序发现已提交区块时的本机时间为准，不使用区块头时间充当交易提交时间。每份汇总中都会记录该指标的计算依据和观察轮询间隔。

恶意流量汇总会按照攻击类型和 ABCI 错误码统计结果。Docker 资源采样保存在 `docker-stats.csv`；一次性验证节点容器删除前，其运行日志也会被保留。

超大 extension 测试交易单独使用 2,000,000 gas limit，防止它在进入 pqcauth 字节上限检查前，先被 Cosmos SDK 的交易大小 gas 计费拒绝。只有每一种恶意交易都命中预期的 ABCI 错误码，测试才会通过；仅仅“交易被某个环节拒绝”不能算作安全校验成功。

## 测试边界

该方案仍然属于单机双节点测试。它可以验证固定 CPU 和内存限制下的交易校验、容量与共识表现，但不能替代以下生产级测试：

- 跨机器网络延迟与丢包测试；
- 验证节点故障与恢复测试；
- 验证节点 HSM 或远程签名器测试；
- IBC 对端兼容与跨链验证测试。
