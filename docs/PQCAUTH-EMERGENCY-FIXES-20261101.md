# PQCAuth 紧急治理与恢复修复记录

后续更正：本文件记录 `23dfcf8` 的历史实现。该版本自动识别紧急请求存在 GOV-02 取消/续期歧义，已改为显式 `MsgUpdateParams.emergency_only`，见 [GOV-02 修复记录](PQCAUTH-GOV02-FIXES-20261101.md)。下文的自动识别语义不再是当前 API，725 个通过事件属于该轮历史结果。

日期：2026-11-01。审计基线：`8a8b6892a7458f4cfe752332a2b5fe3835fe54ae`。分支：`feature/pqcauth-sdk-keyring`。审计范围为该基线到包含本文件的提交，包括 750 gas 对齐、GOV-01 和 OBS-REC-01；未发布版本、部署节点或发送公共交易。

本次修复让已排队的注册截止计划不再阻塞纯紧急更新，并允许全面暂停期间由受保护的独立付款人支付单条恢复交易。默认授权和证明验签价格采用用户确认的最新 750 gas，不恢复旧的 250,000。全仓发布门禁、静态检查和本地编译通过；这是可交付复审的实现，不是主网发布批准。

## GOV-01 的复现与修复

旧代码的真实 MsgServer 复现确认：H=100 排队 cutoff=111、activation=110 后，H=101…109 的紧急请求无法通过；更远的 cutoff 会使紧急更新重新等待完整安全延迟。复现使用最新 750 默认价，不以旧 gas 为前提。

新增 `Params.pending_emergency`（protobuf 字段 20）和 `EmergencySchedule`，只保存紧急模式、生效高度和到期高度。当已有不同的非紧急参数计划等待生效时，纯紧急请求单独安排在 H+1；原有完整参数计划仍保留。

实现入口：

- `x/pqcauth/keeper/emergency_schedule.go`：识别纯紧急请求，建立独立调度，同步原计划中的紧急字段。
- `x/pqcauth/keeper/msg_server.go`：authority、参数和不可变字段检查之后，进入独立调度分支；原截止锁定和限制性更新延迟保留。
- `x/pqcauth/types/params.go`：验证内部调度、按高度应用、自动到期；治理请求不得注入内部调度或自行指定到期高度。
- `proto/doravota/pqcauth/v1/state.proto`、`types/state.pb.go`：新增状态编码，原字段编号不变。
- `x/pqcauth/keeper/export.go`：携带未完成调度的状态继续拒绝零高度导出。

纯紧急请求的非紧急字段可以完整复制 active 或完整复制 pending。前一种写法中 cutoff=0 不表示撤销已承诺的截止高度；后一种写法也不会提前激活 pending 中的 REQUIRED、预算缩减或其他限制。只有紧急字段被改动。

例：H=100 排队 cutoff=111、REQUIRED、较低预算，原 activation=110；H=101 请求暂停，则暂停在 102 生效，另外三项仍在 110 生效。H=109 请求暂停时，两种调度在 110 同时生效。截止高度值和原 activation 均不后移。

暂停有效期从其自身 H+1 生效高度计算，受不可变的最大持续高度限制。原 pending 中的紧急组件同步为这次明确请求的模式及到期高度；若在原计划生效前已到期，则同步为 NORMAL，避免旧计划重新打开已经到期的暂停。解除暂停同样只改紧急状态，不取消非紧急计划。

### 保留的限制

- 已承诺的 cutoff 仍不能通过普通参数更新删除或更改。
- 该快速分支只接受纯紧急操作，不接受借暂停附带任意新参数值。
- 独立紧急调度尚未到 H+1 时，同一块中再提交混合非紧急更新会被拒绝，避免覆盖刚排队的紧急动作。应先执行紧急更新，H+1 后重新查询再构造其他更新。
- 无其他非紧急计划等待时，原有紧急更新和普通计划取消语义保留。
- 不增加账户扫描、授权索引或升级历史回填。

## OBS-REC-01 的修复与认证边界

`ante/structure.go` 的全面暂停例外从单条 `MsgCancelRecovery` 扩展到单条顶层 `MsgRecoverKey` 或 `MsgCancelRecovery`。其用途是让受保护的独立付款人可以携带必须的 PQC Extension。

这里只放行结构层的暂停门槛，未跳过 SDK 账户验签、owner 经典签名、恢复签名、新密钥 PoP、付款人 PQC 授权、DIRECT 约束或验签预算。受保护付款人的恢复样例仍计三次 PQC 校验；自付或普通付款人样例计两次。普通受保护转账、批量消息和间接生命周期执行没有新增例外。

真实签名应用回归包含正常状态、全面暂停、受保护付款人、普通付款人和 owner 自付；缺少付款人因子、错误付款人因子、错误恢复因子、错误新 key PoP、错误 owner 经典签名均在 CheckTx 和 FinalizeBlock 中拒绝。失败不改变账户余额或 sequence，后续空块和状态审计正常。

这项支持位于链上执行路径，不代表单签 CLI 新增了多签名者协作能力；外部构造器仍须生成完整认证交易。

## 最新 gas 和容量边界

授权签名与生命周期证明的默认价及下限均引用固定 SDK 的 ML-DSA-65 基准 750。750 是每次密码学验签的计费值，不是交易总 gas。经典验签、交易字节、存储和业务执行继续计费，已有显式较高链上参数不会自动改写。详细测量、交易样例及兼容说明见 [验签 gas 对齐说明](PQCAUTH-GAS-ALIGNMENT-20261101.md)。

共享次数预算仍为每笔 16、每块 400，原生 ML-DSA 仍计入。统一价格没有解决有效交易挤占 PQC 额度的经济性和公平性问题；本次未擅自增加容量或删除原生计数。普通无关交易保留既有按签名者跳过的选择规则。

## 本轮验证

使用 Go 1.26.10，`GOMAXPROCS=2`、`GOFLAGS=-p=2`，不停止或修改本机已有节点。

| 检查 | 结果及范围 |
| --- | --- |
| `scripts/test-release-candidate.sh` | 全仓 14 个测试包通过，725 个测试及子测试通过事件；无失败 |
| 显式链模拟 | 默认跳过的 3 项另行启用，全部通过 |
| 发布工具和 IBC 源快照 | 7 项 Python 测试通过；906 个源文件检查通过 |
| `go vet ./...` | 通过 |
| 本地 `go build ./cmd/dorad` | 通过，实际工具链 Go 1.26.10；非正式发布产物 |
| GOV-01 回归 | 两种暂停 × 近/远 cutoff × active/pending 请求 × H=101…109，共 72 个组合通过 |
| 调度边界 | 暂停到期早于、等于、晚于原计划激活；逐块 Normalize 与跳高度读取一致 |
| 编码和导出导入 | protobuf、JSON genesis、H=101/102/109/110/122 导出导入一致，非法调度拒绝 |
| 恢复真实签名 | 9 个应用内案例通过；包含 5 个预期失败路径 |

发布门禁已强制要求本轮关键测试执行，不能用 skip 或未匹配测试名通过。初轮门禁曾因新 genesis 测试把 `BinaryCodec` 当作 JSON codec 而编译失败；测试已改用具体 codec 接口，最终完整门禁重新通过，失败记录仍保留。

实际日志路径：

- `/tmp/pqcauth-gov01-review.log`：修复前真实 keeper/app 复现，运行于 750 默认价工作区。
- `/tmp/pqcauth-emergency-gate-release.log`：最终发布门禁摘要。
- `/tmp/pqcauth-emergency-gate-release/unit.jsonl`：725 个通过事件及恢复交易结果。
- `/tmp/pqcauth-emergency-gate-release/simulations.jsonl`：3 项显式链模拟。
- `/tmp/pqcauth-emergency-vet.log`、`/tmp/pqcauth-emergency-build.log`：成功命令的空输出日志。
- `/tmp/pqcauth-emergency-gate/unit.jsonl`：初轮测试编译失败记录，不作为通过证据。

构建检查产物为 `/tmp/pqcauth-emergency-check-dorad`，SHA-256 为 `109d30f0eca6a1f6506f23c1234da818c8f3538e4b44ad12d1946401e7e6f6e9`。它从提交前工作区构建，build info 标记 `vcs.modified=true`，只用于编译核验；不得作为已冻结发布二进制或快照演练证据。

复跑命令，在仓库根目录执行：

```sh
export GOTOOLCHAIN=go1.26.10
export GOMODCACHE=/tmp/doravota-go-mod
export GOCACHE=/tmp/doravota-go-build
export GOMAXPROCS=2
export GOFLAGS=-p=2
PYTHONDONTWRITEBYTECODE=1 RESULTS_DIR=/tmp/pqcauth-emergency-rerun bash scripts/test-release-candidate.sh
go vet ./...
```

`state.pb.go` 使用固定依赖 `github.com/cosmos/gogoproto@v1.7.2` 的 `protoc-gen-gocosmos` 从 `state.proto` 重新生成，未手改 wire 实现。编码回归覆盖旧状态省略新增字段和新调度 round-trip。

## 复审与发布要求

请优先审查纯紧急请求识别是否足够窄、同高度生效和到期顺序、无法取消 cutoff 或提前激活限制、恢复付款人的完整认证及预算计数。新调度改变共识执行并增加持久化字段，不能旧新二进制混跑或单节点滚动替换来改变行为。

支持的生产入口仍为尚未部署 PQCAuth 的 v1.0.1；历史实验库不得视为自动迁移承诺。最终代码独立复审后，需要干净的同一正式候选产物重新完成多验证人、真实快照升级/中断恢复、最低硬件混合负载以及公共测试网生命周期和 IBC 验收。本轮应用内测试不替代这些验收，也未重新做全仓依赖漏洞扫描或物理 Ledger 测试。
