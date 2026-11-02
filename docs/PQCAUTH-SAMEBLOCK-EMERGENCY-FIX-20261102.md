# PQCAuth 同块紧急保护修复记录

日期：2026-11-02 UTC。基线：`59dddd8dc25c289f969b2b9d6a9b2d18eab072ef`，分支 `feature/pqcauth-sdk-keyring`。对应 Claude 第七轮复审 G-1：没有普通待生效计划时，同块后续完整更新可以取消或替换刚排队的紧急暂停。

本次按用户确认统一保护规则，不再将这种差异仅作为操作边界记录。750 gas、验签预算、密码学、提案原子回滚和不可逆注册截止规则均不改。

## 根因与最小修复

`x/pqcauth/keeper/emergency_schedule.go` 原来只有 `current.Pending != nil` 分支设置 `PendingEmergency`，而完整更新的 H+1 保护依据这个标记。没有普通计划时，暂停虽写入新的 `Pending`，同块完整请求却能成功覆盖它。

现在把设置 `PendingEmergency` 移至两条分支的共同出口、`SetParams` 之前。没有普通计划时，普通 bundle 与紧急调度都在 H+1 激活，符合现有参数校验；有普通计划时，原普通内容与激活高度仍保持。没有新增 protobuf 字段、数据库前缀、迁移扫描或每块遍历。

这是共识行为变更，即使源码改动很小，也不能让旧新二进制混跑。仍按既定 v1.0.1 到 PQCAuth 候选的协调升级流程验收。该改动保护新执行的显式紧急请求，不追溯为旧实验数据库里已经排队且缺少标记的状态补写标记；旧实验状态不是受支持的生产迁移入口。

## 治理操作规则

| 顺序 | 新行为 |
| --- | --- |
| 不同提案，同块先 emergency-only 后完整更新 | 前者成功，后者明确报错并为 FAILED；前者的暂停 H+1 正常生效 |
| 同一提案，先 emergency-only 后完整更新 | 后者拒绝，整个提案回滚，暂停也不保存 |
| 同块先完整更新后 emergency-only | 两者可以成功；紧急状态 H+1 生效，原普通计划不提前、不后移 |
| H+1 紧急状态生效后完整更新 | 不再被同块保护拦截，仍需通过权限、参数及截止承诺校验 |
| 同块后续显式 emergency-only | 允许明确切换、续期或解除；按有权限消息的顺序处理 |

紧急暂停应独立提案执行，不能与完整参数修改批量放入同一提案。这个要求保留治理的原子性，不采用“暂停部分提交、其他消息失败”的特殊事务逻辑。

因 H+1 保护而失败的普通提案不会自动重试。操作人员应等待暂停生效，重新查询 active/pending、expiry 与实际参数，若仍需要修改则重新发起新提案，经过正常治理流程。文中的 H+1 可执行是链上校验边界，不承诺真实新提案能在一块内完成投票。

## 原探针复核

使用 Claude 的 `/root/claude-pqcauth-audit-20261031/claude_probe_same_block_emergency_test.go` 原文件，通过 Go overlay 加载，未修改断言、未把复现失败改成预期成功。

- 基线两个场景均违反“暂停不得丢失”的断言：完整请求返回成功，H=101 为 NORMAL。
- 修复后两个场景通过：完整请求返回 `wait for the H+1 emergency activation`，H=101 为 PAUSE_PQC_TRANSACTIONS。

基线日志：`/tmp/pqcauth-round7-review.aiiieW/probe.log`。
修复日志：`/tmp/pqcauth-sameblock-claude-probe-fixed-20261102.log`。

## 新增及更新回归

- `keeper/emergency_sameblock_test.go`：12 个组合覆盖三种 emergency mode、有无普通计划、取消式/收紧式完整更新。断言拒绝不写状态、实际响应、H+1 清理标记及恢复完整更新、到期不复活、直接读取与逐高度规范化一致。
- 同文件另外 6 个组合覆盖同块显式切换、续期及解除；带不可逆 cutoff 时保持原截止和普通激活高度，H+1 后也不能借完整更新撤销 cutoff。
- `app/pqcauth_governance_execution_test.go`：更新原 20 个顺序场景为新协议断言，仍运行实际 tally、治理 EndBlock、FinalizeBlock、Commit，失败提案到高度 24 仍不重试。同一提案失败保持原子回滚，不同提案成功写入不被后一个失败回滚。
- 同文件新增 4 个场景：两种暂停 × 普通收紧/暂停的先后顺序。先暂停时普通提案失败，H+1 新提案能成功收紧并保留暂停原 expiry；先收紧时两者成功且保留原激活高度。新提案用已通过投票的夹具进入真实 EndBlock，不声称一块内完成真实治理投票。
- 真实签名提交/押金/投票的两个场景保留：同提案先暂停后完整更新，现在都必须 FAILED，余额、押金退还、序号、整包回滚与后续出块断言不删除。
- `x/pqcauth/emergency_genesis_test.go`：导出、JSON 编解码、重新 InitGenesis 覆盖有无普通计划两种状态，包括标记与 bundle 同高度激活、到期及未来规范化。
- `scripts/test-release-candidate.sh`：新 Keeper 与应用入口均列为必跑测试。既有 GOV-01/GOV-02、cutoff、gas、恢复付款人、选择器、750 gas 有界负载等回归继续执行。

## 验证结果

本机离线依赖，Go 1.26.10，`GOMAXPROCS=2`、`GOFLAGS=-p=2`：

- 全仓发布门禁成功：14 个包，794 个测试及子测试通过事件，0 失败。
- 默认跳过的 3 项链模拟另行显式启用后全部通过；没有把 skip 当通过。
- 7 项 Python 发布工具测试、906 个固定 IBC 源文件校验通过。
- `go vet ./...` 与本地 `go build ./cmd/dorad` 成功。

开发构建路径为 `/tmp/dorad-pqcauth-sameblock-20261102`，仅用于验证可编译，不是冻结的正式发布产物。此次未执行新的多节点快照升级、物理硬件持续负载或公共测试网操作；本地门禁不代表这些发布验收已完成。

## 审计路径与复跑

修复记录绝对路径：
`/root/Documents/Codex/2026-10-31/new-chat/Doravota/docs/PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md`

生产修改绝对路径：
`/root/Documents/Codex/2026-10-31/new-chat/Doravota/x/pqcauth/keeper/emergency_schedule.go`

原始日志位于本机临时目录，不随 Git 提交：

- `/tmp/pqcauth-sameblock-targeted-20261102.log`
- `/tmp/pqcauth-sameblock-export-20261102.log`
- `/tmp/pqcauth-sameblock-gate-20261102.log`
- `/tmp/pqcauth-sameblock-gate-20261102/unit.jsonl`
- `/tmp/pqcauth-sameblock-gate-20261102/simulations.jsonl`
- `/tmp/pqcauth-sameblock-vet-20261102.log`、`/tmp/pqcauth-sameblock-build-20261102.log`（成功命令空日志）

SHA-256：

```text
18a38c0781a4e7eeb60738489c21f918cd20b3bfac50bbfbd5a7332821155527  pqcauth-sameblock-claude-probe-fixed-20261102.log
318129987d09df62e10503f58799f09269d43812e16f9d36e896c583dc078ca7  unit.jsonl
e889ffbbf2444ddf7d4944c914fa5ed48b26867748501a69331b5534cfc2888e  simulations.jsonl
```

仓库根目录使用 Go 1.26.10 复跑：

```sh
export GOMAXPROCS=2
export GOFLAGS=-p=2
go test ./x/pqcauth/keeper -run '^TestEmergencyOnly' -count=1 -v
go test ./app -run '^TestPQCAuth(Governance|SignedGovernance)' -count=1 -v
go test ./x/pqcauth -run '^TestIndependentEmergencyExportImport$' -count=1 -v
RESULTS_DIR=/tmp/pqcauth-sameblock-rerun bash scripts/test-release-candidate.sh
go vet ./...
```

本机离线环境使用缓存编译器 `/tmp/doravota-go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin`、`GOTOOLCHAIN=local`、`GOPROXY=off`、`GOMODCACHE=/tmp/doravota-go-mod`、`GOCACHE=/tmp/doravota-go-build`，未修改依赖或工具链要求。
