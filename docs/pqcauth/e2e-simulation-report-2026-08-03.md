# PQCAuth 四验证节点真实网络模拟报告

## 1. 结论

`x/pqcauth` 在隔离的四验证节点 Doravota 网络上完成了本次计划内的完整功能、异常、安全边界、治理切换和节点故障恢复模拟：**150 项断言通过，0 项失败**。网络执行了 80 笔成功上链交易，最终到达高度 190；四个验证节点最终得到相同的 AppHash：

```text
E2A6A08BB56391AE0A18D97BD96BA89FA1B3A77F83B5827F1AF41E3C30AC4781
```

本次结果说明 PQCAuth 的 hybrid AND 认证、ML-DSA-65 验签、H+1 状态生效、密钥生命周期、故障关闭和 Ante 集成在该测试矩阵内行为一致。它不等于生产发布批准：最新依赖扫描仍有 8 个可达的上游漏洞，生产启用前必须解决；真实业务负载下的 gas 定价也仍需校准。

## 2. 可复现信息

| 项目 | 数据 |
| --- | --- |
| 测试服务器 | `amaci-testnet-operator` |
| 系统 | Ubuntu 22.04, Linux 5.15, x86_64 |
| CPU | Intel Core Ultra 7 265，20 个逻辑 CPU |
| 内存 | 62 GiB |
| Go | 1.25.12 linux/amd64 |
| 被测源码提交 | `1bcde6a67bc94c86c0bcff9dcda96892964773db` |
| 分支 | `pqc-auth` |
| Chain ID | `pqcauth-e2e-20260802174721-3715852` |
| 开始时间 | 2026-08-02 17:47:21 UTC |
| 结束时间 | 2026-08-02 17:51:45 UTC |
| 持续时间 | 264 秒 |
| 验证节点 | 4 个，均为真实 CometBFT 进程 |
| 成功交易指标 | 80 组 |
| 断言 | 150 通过，0 失败 |
| 最终高度 | 190 |

构建产物摘要：

```text
dorad  c5033216a620047849ba6a8c941f8b95ff8a681aeb641167730505d8132ba128
pqctx e69953273c932a4d1ceadbebaa0e16848b93bf2074703fa17ff4b7c2c308e7be
```

模拟只使用新建的隔离目录，没有读取、停止或修改服务器上的既有链服务。测试结束后四个测试节点均已停止。测试目录包含测试专用助记词和 ML-DSA 私钥，权限受限且未写入 Git；为了审计，本次没有删除这些原始证据。

## 3. 功能与生命周期模拟

### 3.1 账户注册与日常交易

- 未注册账户在 `OPTIONAL` 模式下可以发送普通经典签名交易。
- 错误 Key ID 绑定的注册 proof 被拒绝。
- 分别模拟了“签名密钥 + recovery 密钥”和“仅签名密钥”注册。
- 注册、轮换、恢复和保护策略变更都在 H+1 生效；生效前后状态查询与交易行为一致。
- `self_enforced=true` 的账户缺少 PQC 扩展时被拒绝。
- 同一笔银行转账同时通过经典 Cosmos 签名和 ML-DSA-65 签名后成功上链。
- 离线签名 bundle 被篡改后，客户端在广播前拒绝。

### 3.2 密钥生命周期

- 签名密钥轮换成功；旧 policy 生成的预签 bundle 在 H+1 后失效。
- recovery 密钥轮换成功。
- 已不活跃的历史签名密钥可以撤销，查询结果永久记录撤销状态。
- 使用 recovery 密钥完成了与目标交易绑定的离线签名密钥恢复；恢复前 bundle 随 policy 版本更新而失效。
- 保护开关只能由当前有效 PQC 签名授权，且按 H+1 生效。
- `--gas auto` 走真实 Simulate 后成功执行生命周期交易，不要求客户端为了估 gas 先做一次真实 ML-DSA 验签。

### 3.3 Key ID 终身配额

使用独立账户实际创建并激活 Key ID 1 到 8。历史记录为 append-only，撤销或轮换不会回收 ID；第 9 个 Key ID 被拒绝，返回 code 7，最终查询恰好得到 8 条记录。这证明当前参数是“终身创建记录上限”，不是“同时活跃密钥数上限”。

### 3.4 authz 嵌套边界

测试账户先真实提交 `MsgGrant`，再由 grantee 通过 `authz.MsgExec` 尝试嵌套 PQC 生命周期消息。DeliverTx 以 code 21 拒绝，且前后 PQC 状态完全一致。因此 lifecycle proof 不能从外层交易错误继承给内层 granter。

## 4. Ante 对抗矩阵

脚本直接构造 protobuf 原始交易，避免只测试 CLI 的友好输入检查。下列 12 类异常 critical extension 全部在 Ante/CheckTx 被拒绝：

| 异常 | 返回 code |
| --- | ---: |
| ML-DSA 签名错误 | 10 |
| signer 地址错误 | 12 |
| Key ID 错误 | 12 |
| policy version 错误 | 12 |
| signer index 越界 | 12 |
| 未知算法 | 1 |
| 签名长度错误 | 12 |
| entries 为空 | 11 |
| 放入 non-critical options | 12 |
| critical extension 不是最后一个 | 12 |
| 非 canonical protobuf | 12 |
| 超过 64 KiB 的合法 protobuf 扩展 | 12 |

在该拒绝矩阵之后又发送了一笔正确的 hybrid 交易并成功提交，验证异常输入没有污染账户或模块状态。

## 5. 治理、紧急模式与故障恢复

四个 bonded validator 对 10 个真实治理提案逐一投 Yes，并验证参数在 H+1 原子生效：

1. `REQUIRED_FOR_REGISTERED`：所有已注册账户强制 PQC。
2. 恢复 `OPTIONAL`。
3. `DISABLED`：只关闭治理层强制，不能覆盖账户自己的 `self_enforced`。
4. 再恢复 `OPTIONAL`。
5. `PAUSE_NEW_KEYS`：暂停注册、轮换和恢复，已有 PQC 密钥仍可完成普通交易。
6. 恢复 `NORMAL`。
7. `PAUSE_PQC_TRANSACTIONS`：密码学上正确的 PQC 扩展也以 code 15 fail-closed；未注册经典账户仍可交易。
8. 恢复 `NORMAL`。
9. 设置不可逆 registration cutoff；截止后新账户注册以 code 14 拒绝。
10. 最终切换到 `REQUIRED`；未注册账户也被拒绝。

故障恢复测试中主动停止一个验证节点，剩余三个节点继续达成共识并提交受 PQC 保护的交易；随后重新启动该节点，它追赶到同一高度。测试末尾四节点在高度 190 的 AppHash 一致。

## 6. Gas、交易大小与 ML-DSA 基准

下面是有代表性的真实 DeliverTx 数据。测试多数交易故意给出宽松的 `gas_wanted=5,000,000`；应以 `gas_used` 作为本次环境中的执行成本观测值。

| 场景 | 高度 | Gas used | 原始 Tx 字节 |
| --- | ---: | ---: | ---: |
| 未注册账户经典银行转账 | 3 | 76,707 | 314 |
| 注册 signing + recovery | 5 | 806,013 | 10,805 |
| Hybrid PQC 银行转账 | 13 | 368,220 | 3,730 |
| 轮换 signing key | 15 | 807,024 | 8,948 |
| 轮换 recovery key | 20 | 814,362 | 8,956 |
| 撤销历史 key | 22 | 424,677 | 3,677 |
| Recovery 恢复 signing key | 24 | 813,160 | 8,849 |
| 变更保护状态 | 27 | 362,925 | 3,679 |
| 单验证节点离线期间的受保护转账 | 60 | 368,256 | 3,730 |

在同为单一 `MsgSend` 的样本中，hybrid 交易相对经典交易：

- 多消耗 291,513 gas，总 gas 约为 4.80 倍；
- 多 3,416 字节，线宽约为 11.88 倍。

`--gas auto` 样本估算 `gas_wanted=430,214`，实际 `gas_used=362,839`，余量 67,375，约为实际消耗的 18.57%。这证明模拟路径可用，但单个样本不能替代生产 gas 参数标定。

Cloudflare CIRCL ML-DSA-65 Verify 在目标服务器上的 5 次 Go benchmark 为 78,994–87,341 ns/op，平均约 84.1 微秒，每次 33,218 B、4 allocs。该数据只反映这台 CPU 和当前 Go/CIRCL 版本。

## 7. 代码质量验证与覆盖率

在与模拟相同的 linux/amd64 环境中完成：

- `go test ./...`：全仓通过；
- `go test -race ./x/pqcauth/...`：全部通过，未报告 data race；
- `go vet ./x/pqcauth/... ./tests/e2e/pqcauth/...`：无输出，检查通过；
- `go test -coverpkg=./x/pqcauth/... ./x/pqcauth/...` 汇总后：52.9% statement coverage。

覆盖率不是 100%。总数包含大量自动生成的 protobuf/gRPC 方法，其中许多为 0%；核心安全函数覆盖较高，例如 `requireDirectSignMode`、`pqcRequired`、lifecycle proof substitute、key-change gate、crypto Verify、quota compatibility 和核心 Query 路径均为 100%，Ante 主验证入口为 83.8%，key proof 验证为 81.2%。因此当前状态是“核心路径有单测且真实 E2E 矩阵全面”，不能表述为“代码测试全覆盖”。后续仍应继续补足生成代码之外的手写低覆盖分支、fuzz/property tests 和长期 simulation operations。

## 8. 依赖安全扫描

使用 Go 1.25.12 和 `govulncheck` 1.6.0 对被测提交执行 `govulncheck -show verbose ./...`。退出码为 3，结果为：

- **8 个有实际调用路径的漏洞，来自 5 个模块**；
- 另有 2 个位于已导入包、1 个位于依赖模块，但扫描器未发现本项目调用漏洞符号。

8 个可达项如下：

| ID | 依赖与当前版本 | 问题 | 扫描器给出的修复版本 |
| --- | --- | --- | --- |
| GO-2026-6061 | gRPC 1.79.3 | xDS RBAC 与 HTTP/2 transport | 1.82.1 |
| GO-2026-5932 | x/crypto 0.53.0 | OpenPGP 已停止维护且设计不安全 | 无 |
| GO-2025-3443 | CometBFT 0.37.18 | 恶意 peer 通过 block parts 阻塞网络 | 0.38.17 |
| GO-2025-3442 | CometBFT 0.37.18 | 恶意 peer 使 blocksync 卡住 | 1.0.1 |
| GO-2024-3319 | Wasmd 0.46.0 | 消息模拟可导致崩溃 | 0.53.2 |
| GO-2024-3059 | Wasmd 0.46.0 | ValidateBasic 地址数量无界 | 0.52.0 |
| GO-2023-1881 | Cosmos SDK 0.47.17 | `x/crisis` 未收取 ConstantFee | 无 |
| GO-2023-1821 | Cosmos SDK 0.47.17 | `x/crisis` 未按预期停止链 | 无 |

无已识别调用路径的三项是 GO-2026-5426（OpenTelemetry SDK）、GO-2025-3803（Cosmos SDK validator rewards overflow）和 GO-2026-5841（klauspost/compress）。它们仍应在整链依赖升级时一并处理。

这些是运行 PQCAuth 的完整节点所继承的风险，并非 ML-DSA/PQC 验签逻辑本身新增的问题。但安全边界由整条链决定，所以 8 个可达项必须继续作为生产发布阻断项，不能因为模块 E2E 通过而豁免。

## 9. 原始证据位置

服务器保留目录：

```text
/root/doravota-pqcauth-e2e-20260802T173646Z/
```

关键文件：

```text
artifacts-four-node-v4/reports/report.json        # 机器可读汇总、150 条断言、80 组交易指标
artifacts-four-node-v4/tx/                        # 交易、查询、提案和拒绝证据
artifacts-four-node-v4/logs/                      # E2E 步骤日志
artifacts-four-node-v4/nodes/                     # 四节点配置、数据与日志
four-node-e2e-v4.log                              # E2E 控制台日志
verification/go-test-all.txt                      # 全仓测试
verification/go-test-race.txt                     # PQC race 测试
verification/go-vet.txt                           # 静态检查
verification/pqcauth-coverage.out                 # Go coverage profile
verification/pqcauth-coverage-functions.txt       # 函数级覆盖率
verification/mldsa65-benchmark.txt                # 目标 CPU benchmark
verification/govulncheck.txt                      # 完整依赖漏洞扫描
verification/govulncheck.exit-code                # 扫描退出码
```

原始目录包含测试私钥，只应通过受控 SSH 访问，不应上传到 GitHub 或公开制品库。

## 10. 发布前剩余工作

1. 完成 Cosmos SDK、CometBFT、Wasmd、gRPC 和 keyring/OpenPGP 的兼容升级或风险消除，并在最终发布提交上重新扫描。
2. 在目标生产硬件上做多并发、满块和恶意无效签名压力测试，再据此标定 `signature_verification_gas`、`proof_verification_gas` 与区块 gas 上限。
3. 持续增加手写低覆盖分支、fuzz/property 测试和 Cosmos simulation operations；不要把当前 52.9% 描述为全覆盖。
4. 用候选主网 genesis、真实 validator 数量和网络延迟再次演练升级、紧急暂停、节点落后追赶及回滚预案。
5. 接入生产级 HSM/remote signer、监控告警和审计日志；本次文件 key 仅用于 E2E。

在这些发布阻断项完成前，可以继续做测试网集成和性能标定，但不建议开启生产级 `REQUIRED` enforcement。
