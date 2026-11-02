# PQCAuth 治理执行与有界负载测试

日期：2026-11-02 UTC。实现基线：`1997bcdac2998584ca5d42169976110d5e927880`，分支 `feature/pqcauth-sdk-keyring`。本轮新增应用集成测试、发布门禁和说明，不修改共识执行代码、750 gas 定价、16/400 验签预算或治理语义。

真实治理执行回归和本机有界负载测试通过，未发现这些场景下的新增授权绕过、状态污染或无法继续提交区块。共享额度不保证恢复优先级：固定候选排序下可以持续推迟恢复；本轮明确验证了这种边界，而不是声称已经消除。

## 治理执行与回滚

`app/pqcauth_governance_execution_test.go` 新增两个测试入口：

- `TestPQCAuthGovernanceEndBlockOrderingAndRollback`：两种暂停模式 × 有无普通 pending × 五种消息/提案顺序，共 20 个子场景。通过实际应用的 FinalizeBlock、治理 EndBlock、tally、消息路由、缓存写入和 Commit 验证；每个实例继续提交到高度 24，检查 H+1 暂停、原普通计划激活、暂停到期与状态审计。
- `TestPQCAuthSignedGovernanceSubmissionVoteAndRollback`：两个子场景实际签署并 CheckTx/Finalize 提交提案、押金和投票交易，等投票结束后由治理执行。检查提案状态、消息写入的取消或回滚、退还押金、两笔手续费与 sequence，以及后续区块/状态审计。

前一个测试只预置投票期结束的提案和有效投票，并不预置执行结果；后一个覆盖真实提交/押金/投票路径。测试链初始参数、短投票期和短治理延迟为隔离夹具，不是在公共链上发提案。

| 同高度顺序 | 没有普通 pending | 已有普通 pending |
| --- | --- | --- |
| 同一提案先 emergency-only 暂停，再完整恢复 active | 提案通过，新暂停被取消 | 第二条消息拒绝，整个提案参数写入回滚 |
| 两个提案先暂停，再完整恢复 active | 两个通过，暂停取消 | 暂停通过、后一个失败，暂停与原普通计划保留 |
| 两个提案先完整恢复 active，再暂停 | 两个通过，暂停 H+1 生效 | 先取消可取消的普通计划，再暂停 H+1 生效 |
| 同一提案先暂停，再提交非法参数 | 整个提案写入回滚 | 整个提案写入回滚，原普通计划保留 |
| 上述失败提案之后再执行合法暂停提案 | 后一个提案正常成功 | 后一个正常成功，原普通计划激活高度不变 |

多提案测试特意倒序插入提案，断言实际到期队列按相同到期时间下的 ID 顺序处理。失败提案不会回滚之前另一个已成功提案，也不会污染后一个提案的执行。

同块差异按现有协议记录：无普通计划时紧急更新使用 `Pending` bundle，可被同块有权限的完整更新取消；与普通计划重叠时使用 `PendingEmergency`，同块完整更新明确拒绝。没有为了使两个结果表面一致而修改协议。不可逆 numeric cutoff 的取消限制仍由既有 Keeper 回归覆盖，本轮这组顺序测试使用 REQUIRED，不携带 numeric cutoff。

## 共享额度饱和与恢复排队

`TestPQCAuthBoundedMixedBudgetAndRecovery` 保留默认 750 gas、每笔 16 次、每块 400 次。隔离夹具设置区块 gas 上限 600,000,000、字节上限 10,000,000，恢复延迟缩短为 4 块；这不表示查询了当前主网参数。

每块提供 200 笔真实原生 ML-DSA 转账、200 笔真实经典加 PQCAuth 转账、一笔恢复或取消恢复、一笔无关经典转账，共 402 个候选。噪声和普通转账声明 500,000 gas，避免测试在到达 PQC 次数预算之前就被声明 gas 上限截断。全部候选先按 sequence 通过真实 CheckTx，再执行 PrepareProposal、ProcessProposal、FinalizeBlock 和 Commit。

| 轮次 | 候选中的恢复操作位置 | 实际纳入 | 结果 |
| --- | --- | --- | --- |
| 0、1、2 | 400 笔噪声之后 | 每块 401 笔 | 恢复被推迟；末尾独立普通转账继续执行 |
| 3 | 恢复排第一 | 400 笔 | 恢复占 2 次预算，398 笔噪声及普通转账成功 |
| 4 | 取消恢复在噪声之后 | 401 笔 | 取消被推迟；普通转账成功 |
| 5 | 取消恢复排第一 | 401 笔 | 取消占 1 次预算，399 笔噪声及普通转账成功 |

单轮六块共纳入 2,405 笔交易，全部 code=0，每块状态审计一致。之后继续提交空块并用旧 signing factor 成功转账，确认取消恢复生效。上述数量不包含建链、充值、注册及最后验证交易。

这里由测试显式提供候选顺序，不是测得网络会自动给予恢复优先级。3 块和 1 块是选定场景的等待时间，不是等待上限；持续排序靠后的恢复可能继续被挤占。现有实现没有恢复预留额度。本轮不调整价格、容量或排序政策，也不根据测试手续费推算真实攻击成本。

## 无效签名与模拟请求

`TestPQCAuthBoundedInvalidAdmission` 在正确经典私钥签署的交易中放入错误 PQC 因子签名，分别执行 300 次 CheckTx NEW 和 300 次 RECHECK；每次断言具体的 `invalid PQC signature at signer index 0`，避免只在外层经典签名处失败。

另执行 100 次正常交易 Simulate。检查此前所有请求后余额与 sequence 未改变，再将错误交易送入 FinalizeBlock，确认拒绝且余额/sequence 不变；随后真实有效交易成功提交，空块和状态审计通过。Simulate 按既有规则跳过密码学验证，成功不表示无效签名可以广播成功。

这是直接应用接口的顺序有界调用，同一错误交易会实际进入应用重复处理。没有模拟 CometBFT 的重复缓存、真实 recheck 队列、RPC/P2P 网络并发或无限入池流量，不据此宣称入口 DoS 已解决。

## 执行结果与资源

Go 1.26.10，离线缓存依赖，`GOMAXPROCS=2`、`GOFLAGS=-p=2`。本机约 62 GiB 内存；没有启动或替换公共节点、操作真实钱包或修改网络权限。

- `scripts/test-release-candidate.sh` 成功：14 个包，767 个测试及子测试通过事件，0 个失败。默认跳过的 3 项链模拟另行显式启用并全部通过，不能把两组计数相加称为独立场景数。
- 7 项发布工具 Python 测试、906 个固定 IBC 源文件检查通过。
- `go vet ./...` 成功。四个新增测试入口加入必跑门禁，未匹配或跳过会失败。
- 编译应用测试程序后，以上四个入口连续 `-test.count=3` 重跑全部通过。该测试进程耗时 13.30 秒、峰值 RSS 260,980 KiB（约 255 MiB）、进程 swaps=0；此测量不含编译器，也不是发布版 dorad 或生产数据库的 RSS。
- 三轮重复中的 18 个负载块：每块 FinalizeBlock+Commit 约 102–155 ms，402 次候选 CheckTx 合计约 93–138 ms。该机器、内存测试状态和并行后台工作下的观察值，不是最低硬件性能保证或吞吐 SLA。

最初测试夹具修正过 InitGenesis 派生的 network ID、注册 policy 的延迟规范化读取和错误文本断言；未修改生产代码来使测试通过。

## 审计材料与复跑

源码及说明绝对路径：

- `/root/Documents/Codex/2026-10-31/new-chat/Doravota/app/pqcauth_governance_execution_test.go`
- `/root/Documents/Codex/2026-10-31/new-chat/Doravota/app/pqcauth_bounded_load_test.go`
- `/root/Documents/Codex/2026-10-31/new-chat/Doravota/docs/PQCAUTH-GOVERNANCE-LOAD-TESTS-20261102.md`

本机原始证据（临时目录不随 Git 提交）：

- `/tmp/pqcauth-governance-load-gate-20261102.log`
- `/tmp/pqcauth-governance-load-gate-20261102/unit.jsonl`
- `/tmp/pqcauth-governance-load-gate-20261102/simulations.jsonl`
- `/tmp/pqcauth-governance-load-vet-20261102.log`（成功命令空日志）
- `/tmp/pqcauth-governance-load-repeat-20261102.log`
- `/tmp/pqcauth-governance-load-resource-20261102.log`

SHA-256：

```text
c398ae58bae3b5c40f9e63e81a8becf012196cd52d2860faed905659f45b3d91  unit.jsonl
7b26a9ba7c6116ca99a349ddeb6c74c1127bbb917ac2f035c426d046a2db2311  simulations.jsonl
54936ecfc317faf3cad450c344a8f9d12f2d8a32c5d2c96a2f8073940ded380f  pqcauth-governance-load-repeat-20261102.log
045cb75946c21201f50be5967828815a7681e2d2497486ca1a64885db3a01826  pqcauth-governance-load-resource-20261102.log
```

在仓库根目录用 Go 1.26.10 复跑：

```sh
export GOMAXPROCS=2
export GOFLAGS=-p=2
go test ./app -run '^TestPQCAuth(Bounded|GovernanceEndBlockOrderingAndRollback|SignedGovernanceSubmissionVoteAndRollback)' -count=3 -v -timeout=120s
RESULTS_DIR=/tmp/pqcauth-governance-load-rerun bash scripts/test-release-candidate.sh
go vet ./...
```

本机离线执行显式使用 `/tmp/doravota-go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin`，并设置 `GOTOOLCHAIN=local`、`GOPROXY=off`、`GOMODCACHE=/tmp/doravota-go-mod`、`GOCACHE=/tmp/doravota-go-build`，没有降低仓库工具链要求。

## 尚未完成的发布验收

本轮是应用内集成和有界容量回归，不是最终产物发布批准。最低目标硬件、最大 signer 与最大交易体组合的持续负载、实际 RPC/P2P 入池及 recheck 并发、生产数据库规模、跨机器故障，仍需单独验收。最终冻结产物还需完成真实快照升级、中断恢复及公共测试网生命周期/IBC。旧候选的快照记录不能替代新最终产物的这些验收。
