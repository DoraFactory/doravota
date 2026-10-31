# PQCAuth 第一阶段审计交接

记录日期：2026-10-31 UTC。用途：供 Claude 或其他独立审计者复核当前实现，不是发布批准或无漏洞声明。

后续修复：本文主体保留 `d309931` 审计基准的历史状态。P2-A/P2-B 及 F1/F2/F3 的后续处理见 [审计修复记录](PQCAUTH-AUDIT-FIXES-20261031.md)。复核修复时必须同时检查当前工作区，不能把本节之后的“未修复”历史描述当作最新状态，也不能把旧漏洞复现测试的 PASS 当作修复回归。

复审更新：Claude 已确认 `a2de29d` 的五项发现均已处理，完整结论见 [独立审计及复审报告](PQCAUTH-CLAUDE-AUDIT-20261031.md)。恢复命令提示及运维流程的后续收尾和验证范围见修复记录；真实快照升级及公共测试网验收仍未完成。

## 1. 当前结论与审计对象

当前状态是“第一阶段精简实现及本地验证完成，可以交独立审计”，不是“已经确认没有问题”。最近复核仍有两项已复现、尚未修复的 P2 参数下限问题，见第 5 节。正式升级的真实快照、最低配置及公共测试网验收也未完成。

- 仓库：DoraFactory/Doravota。
- 分支：`feature/pqcauth-sdk-keyring`。
- 基础 HEAD：`72a4d2bd8aad6986cb8c0af96a937cc160ea5065`。
- 本机工作区：`/root/Documents/Codex/2026-10-31/new-chat/Doravota`。
- **审计目标是包含本交接文档及第一阶段精简实现的提交，不是上述基础 HEAD。** 用户已要求将完整实现提交并推送至同名 GitHub 分支；这不授权发布版本、部署或操作线上链。
- 候选升级名称：`v1.1.0`；候选程序版本为 `v1.1.0-dev`。这项工作不属于已发布的 v1.0.1 修复。

审计时先 fetch 并确认包含本文件的交接提交，记录实际 `git rev-parse HEAD`；不要停留在上述基础提交。再运行 `git status --short`、`git diff --stat`、`git diff` 和 `git ls-files --others --exclude-standard`，检查交接后是否又有工作区改动。单独的 `git diff` 不包含未跟踪文件；本文本身不能替代对应版本的源码。本机临时日志和 overlay 复现材料不随源码提交，见第 5、6 节。

首次记录时以下文件尚未跟踪，本次交接提交将一并纳入版本控制，审计时不能遗漏：

```text
app/pqcauth_phase1_test.go
app/pqcauth_review_regression_test.go
docs/PQCAUTH-ROLLOUT-PLAN.md
scripts/candidate-prerelease.py
x/pqcauth/ante/indirect_test.go
x/pqcauth/keeper/export.go
x/pqcauth/keeper/export_test.go
x/pqcauth/keeper/lifecycle_boundary_test.go
```

本交接文档也是本次新增文件。若审计环境有额外工作区改动，不能重置或覆盖。

## 2. 第一阶段的安全承诺与非目标

用户明确选择分阶段上线：第一阶段只做核心直接签名和密钥生命周期安全；第二阶段再设计全面委托安全。完整决策见 [分阶段计划](PQCAUTH-ROLLOUT-PLAN.md)。

第一阶段实现：

- 对采用 PQCAuth 的受保护账户，普通直接交易需要经典签名及 ML-DSA-65 授权；注册、恢复等生命周期操作使用各自的证明规则，不能笼统视为普通转账。
- 授权绑定网络域、链、账户、序号、消息、费用和策略版本，采用规范编码及重放保护。
- 支持注册、签名密钥轮换、恢复密钥轮换、撤销、保护设置、延迟恢复、取消恢复。
- PQC 签名因子、恢复因子、经典密钥应独立。CLI 对可检查的本地密钥派生关系进行限制；硬件或 watch-only 场景有明确确认边界。这不是链上可证明三者独立的机制。
- 恢复机制替换 PQC 签名因子，仍需经典签名，不提供“经典私钥丢失后恢复整个账户”的能力。
- 原生 SDK ML-DSA 账户不再注册本模块；组合/多签账户不能注册。OPTIONAL 下保留原生 SDK 多签兼容；REQUIRED 对不支持的组合账户拒绝，不因所有叶子都是 ML-DSA 就自动支持。
- 不更换共识签名或 IBC 轻客户端算法；Keplr 的传统签名兼容与新模块的完整 PQC 客户端支持是两件事。

委托语义是本阶段有意保留的边界：

- 既有及新增 Authz、Feegrant 保持 SDK 原有语义，注册和恢复不会自动撤销它们。
- 被授权人不必因授权方启用 PQC 而启用 PQC；实际直接签名者仍遵守自身账户策略。
- 所以这不是“授权方所有资产支出都需要授权方 PQC 签名”的保证。被授权人可能继续执行授权范围内的操作，Feegrant 也可继续代付。
- 七种账户密钥生命周期消息不能通过 Authz、治理、group 等间接执行绕过专用认证；消息服务器还检查 Ante 对确切消息建立的认证标记，不能只信任容器过滤。

第二阶段的授权展示、批量撤销、账户级委托限制以及可能的反向索引，不应被默认为本次必须实现的功能。但任何超出上述约定边界的绕过仍需报告。

## 3. 本轮精简与升级路径

已移除 PQC 专属 Feegrant 反向索引、历史回填、到期索引清理、Feegrant 消息包装、Ante 委托预测/约束，以及注册前清空委托的要求。恢复使用原生 SDK Feegrant，不删除原授权记录。

对应删除包括 `app/pqcauth_feegrant_module.go`、`x/pqcauth/ante/authz.go`、`x/pqcauth/keeper/feegrant_{audit,index,msg_server}.go`、`x/pqcauth/types/feegrant_index.go` 及其专属测试。间接生命周期安全测试移至/保留于 `ante/indirect_test.go`，不是取消这层安全边界。

升级入口位于 `app/pqcauth_upgrade.go`：

1. 必须已完成 v1.0.0 Wasm retirement，且 v1.0.1 签名规则已经激活。
2. 源版本表中不能已有 PQCAuth，其他模块版本必须符合候选程序预期。
3. 新增 PQC store，执行模块初始化，首发必须为 OPTIONAL。
4. 网络域设置为 `sha256("doravota/pqcauth/upgrade/v1.1.0/" + chainID)`。同 chain ID 分叉的域隔离需要另行明确，不能假定此派生自动区分所有分叉。
5. 不扫描或改写已有账户、银行、Authz、Feegrant 集合，不创建授权索引。

内部模块版本为 **3**。旧实验性 PQC 数据库版本 1/2 不允许直接切换至本版；没有承诺旧开发链自动迁移。前置状态不匹配时的拒绝是有意的启动/升级防护，需要在发布前排除配置错误，不能等升级高度才发现。

BeginBlock 做参数规范化，不做全链授权/密钥集合清理。密钥历史清理按账户进行并计 gas，默认每角色保留 16 条终态历史；当前及待生效密钥有保护规则。需要重点核查清理不会删除仍被有效策略引用的密钥。

上一轮保留的修复包括：撤销旧密钥前正确处理已生效策略；零高度导出拒绝无法安全重置的 PQC 账户状态或高度参数；CI 对预发布候选的判断跟随 PR 目标。旧自定义 Feegrant 索引的过期修复已被“删除索引”取代，不应继续按旧架构审计。

## 4. 验签预算、gas 与模拟

以下是 `x/pqcauth/types/params.go` 当前默认值，不代表生产压测已经证明其最优性：

| 项目 | 默认值 | 约束/含义 |
| --- | --- | --- |
| PQC 授权签名验签 gas | 250,000 | 固定下限同值，上限 10,000,000 |
| 生命周期证明验签 gas | 250,000 | 固定下限同值，上限 10,000,000 |
| 每笔验签预算 | 16 次 | 绝对上限 64；下限问题见第 5 节 |
| 每块验签预算 | 400 次 | 绝对上限 4,096；不得低于每笔配置 |
| PQC 签名者数量 | 8 | 绝对上限 32 |
| PQC 授权扩展大小 | 64 KiB | 绝对上限 256 KiB；下限问题见第 5 节 |
| 每角色终态密钥保留量 | 16 | 绝对上限 64；另有当前/待生效引用保护 |
| 恢复延迟、治理安全延迟、紧急状态最长持续期 | 各 17,280 块 | 单位是块，不是固定小时数 |

默认模式为 OPTIONAL / OPEN / NORMAL。治理参数生效高度、紧急状态到期，以及 CheckTx、提案检查、执行、模拟所见高度必须一致。

预算是确定性的验签次数限制，不是毫秒计时器，也不是付更多 gas 就能绕过的额度。计数应覆盖 PQC 扩展、生命周期证明、原生 SDK ML-DSA 及支持的多签叶子；非法交易不能污染后续交易的元数据或预算。

典型单账户流程的 PQCAuth 密码学 gas：受保护转账 250,000；注册、签名密钥轮换、恢复各 500,000。多签名者或额外证明会增加成本；上述值不含经典签名、交易字节、存储访问及业务消息执行。

原生 SDK ML-DSA 验签另走 SDK gas 路径，当前默认成本为 750（`DefaultSigVerifyCostMlDsa65`），不能与模块 250,000 混为一谈。两类成本及预算组合应以最低支持硬件重新校准。

CLI `--gas auto` 构建正确尺寸的 PQC 签名/恢复占位数据并走 SDK 模拟；模拟跳过实际密码学验证，但计入预计验签 gas，并由 SDK 统计其他费用。`--gas-adjustment` 是客户端余量，示例中的 1.5 不是模块强制规则。费用和 gas 在签名前绑定，离线签名后不能随意改动。

重点入口：`types/gas.go`、`ante/gas.go`、`ante/verify.go`、`ante/lifecycle.go`、`client/cli/broadcast.go`、`client/cli/recovery.go`。

## 5. 已知未修复问题

以下 P2 为当前复核定级，独立审计者可以调整。两项都需要合法治理/authority 修改参数，默认值不触发；已复现的是 PQC 操作可用性受损，不是无权限攻击者直接让整条链 halt。

### P2-A：授权扩展大小允许配置到不可用值

- 校验位置：`x/pqcauth/types/params.go:188`；拒绝位置：`x/pqcauth/ante/structure.go:199`。行号可能随修改变化。
- `MaxPqcAuthBytes = 1` 可以通过 `ValidateGovernanceUpdate`，也被实际 `MsgServer.UpdateParams` 接受。
- 参数激活后，合法受保护转账及 `MsgSetProtection{Enabled:false}` 都报 `pqcauth extension exceeds size limit`。账户不能靠正常自助关闭保护逃离这个配置，需要治理修复配置。
- 复现中普通未保护转账和空块仍可推进。
- 修复方向：下限至少容纳支持的合法单签授权结构，并验证字段最大编码长度等边界；不能简单凭经验选一个数。尚未实施。

### P2-B：验签预算允许低于核心生命周期最低需求

- 校验位置：`x/pqcauth/types/params.go:199` 起；计数位置：`x/pqcauth/ante/budget.go` 的 `lifecyclePQCVerificationCount`。
- 每笔/每块均设为 1 时，参数合法且可以激活。
- 合法签名密钥轮换需要当前授权与新密钥证明，共 2 次，被拒绝：`transaction requests 2 PQC verifications, limit is 1`。
- 从计数代码可见，注册和恢复本身也各需要 2 次。独立复核应补充这两条实际交易验证；当前复现测试直接执行的是轮换。
- 复现中单次验签的受保护转账、普通转账及空块仍正常。
- 修复方向：一般单账户生命周期至少需要 2 次额度，并分析额外签名者/费用支付者场景。显式紧急暂停应与错误配置导致的永久不可用区分。尚未实施。

### 复现证据与方法

本机目录 `/tmp/doravota-security-review.u1Okxo/` 含 `review_test.go`、`overlay.json`、`repro.log`。它使用 Go overlay 引入临时 `app/security_review_overlay_test.go`，没有把修复或测试偷偷提交进源码。

```bash
GOMAXPROCS=2 GOCACHE=/tmp/doravota-go-build \
GOMODCACHE=/tmp/doravota-go-mod GOPROXY=off GOSUMDB=off \
go test -p 2 -overlay /tmp/doravota-security-review.u1Okxo/overlay.json \
  ./app -run '^TestSecurityReview' -count=1 -v
```

`TestSecurityReviewGovernanceCanDisableCoreOperations` 两个子测试 PASS 表示上述问题成功复现，**不表示问题已经修复**。测试用缩短为 2 块的治理延迟，以正确 authority 调用实际参数处理器并推进到激活高度，不是一次真实公共链治理投票。

跨机器时需要附上该测试源码并重建 overlay 的绝对路径，或自行在隔离工作副本添加等价测试。复现流程：使用 `app/pqcauth_review_regression_test.go` 的 `reviewEnroll` 注册账户 → 确认受保护转账成功 → 通过参数处理器设置上述值 → 激活 → 检查合法业务拒绝及普通出块仍成功。

同目录的 `TestSecurityReviewMalformedProposalsKeepProgress` 对 500 个确定性截断/变异/随机字节案例执行提案路径，没有逃逸 panic，Prepare 输出可由 Process 接受，后续合法交易、空块和状态审计通过。变异输入可能仍合法，因此测试并非要求每个变异都拒绝。

## 6. 已完成验证及证据边界

以下是本工作区此前完成的验证记录，本次交接整理没有重新跑全套。详细上下文见 [集成说明](PQCAUTH-INTEGRATION.md) 和 [分阶段计划](PQCAUTH-ROLLOUT-PLAN.md)。

- 发布候选脚本：561 个通过的 Go 测试/子测试事件，14 个包通过，无失败；不能解释成 561 个独立安全性质。
- 显式启用的 `TestAppStateDeterminism`、`TestAppImportExport`、`TestAppSimulationAfterImport` 通过，使用 Seed 42、10 块、BlockSize 5、Commit。模块没有 PQC weighted operations，通用随机模拟不能代替专用测试。
- 发布工具 7 项 Python 测试、固定 IBC 源码 906 文件及两处预期补丁检查、v1.0.1 IBC Amino 兼容回归通过。
- `go vet -p 2 ./...`、候选编译及 `git diff --check` 通过。
- ML-DSA 验证及扩展解析各做 20 秒 fuzz，无失败；不是长期模糊测试。
- 升级属性测试预置 1,000 条 Feegrant，对账户、银行、Authz、Feegrant store（包括缓存分支）设置访问即失败守卫。升级成功且授权保持、PQC store 只初始化参数。这证明该路径不扫描这些 store，不是磁盘迁移耗时基准。
- 四验证人隔离合成网演练：92 笔成功交易、6 次预期拒绝；覆盖注册、离线签名、两种轮换、恢复取消、恢复等待期间重启、恢复生效后旧因子拒绝、注册/恢复后的委托与代付、超出保留上限的密钥清理及重启。
- 演练包含 40 笔混合负载，期间一个验证人离线两轮，各检查点四节点 AppHash 一致。采用缩短恢复期及测试预算，不是默认参数容量测试、持续吞吐测试或真实快照升级。测试节点已停止，未操作公共链或已有钱包。

证据位置：

```text
build/test-results-phase1/                         Go 测试结果（通常不随 Git 分发）
/tmp/doravota-phase1.yoZGn3/full-tests.log
/tmp/doravota-phase1.yoZGn3/vet.log
/tmp/doravota-phase1.yoZGn3/fuzz-crypto.log
/tmp/doravota-phase1.yoZGn3/fuzz-extension.log
/tmp/doravota-phase1.yoZGn3/lifecycle-retry.log
/tmp/doravota-phase1.yoZGn3/four-validator-lifecycle-retry/evidence/result.json
/tmp/doravota-security-review.u1Okxo/repro.log
```

首次实节点演练因 socket 权限未能启动；开放权限后的独立重试通过。不能把首次失败隐藏为通过。证据目录是本机临时文件，不是公开链接；另机审计需另附所需日志。不要直接打包整个节点 home、keyring 或钱包目录，即使演练使用的是测试密钥。

复跑入口（从仓库根目录运行，需预装依赖；离线缓存路径仅适用于本机）：

```bash
env GOMAXPROCS=2 GOFLAGS='-p=2' GOCACHE=/tmp/doravota-go-build \
  GOMODCACHE=/tmp/doravota-go-mod GOPROXY=off GOSUMDB=off \
  PYTHONDONTWRITEBYTECODE=1 RESULTS_DIR=build/test-results-audit \
  bash scripts/test-release-candidate.sh
```

实节点演练入口为 `scripts/rehearse-pqcauth-lifecycle.py`，请先读脚本/帮助，使用新建的隔离工作目录和未占用端口，不指向生产节点 home。`scripts/rehearse-pqcauth-from-v101.py` 是顺序升级入口；旧轮次结果不能直接作为当前精简源码的最终升级验收。

## 7. 建议审计顺序与代码入口

1. **认证与编码**：`app/ante.go`、`x/pqcauth/ante/{structure,verify,lifecycle,registration,indirect}.go`、`types/{canonical_tx,signing,messages,policy}.go`、`crypto/mldsa65.go`。核查重放、签名字段遗漏、消息/费用篡改、双因子边界及畸形输入。
2. **生命周期不可绕过**：`internal/execution/authorization.go`、`keeper/msg_server.go`、`ante/indirect_test.go`。核查所有消息入口、嵌套容器和确切消息认证，不仅是 CLI 正常路径。
3. **预算与共识确定性**：`app/proposal.go`、`ante/{budget,decoder,gas}.go`、`types/params.go`，以及 `app/pqcauth_{budget_poisoning,proposal_boundary}_test.go`。核查 H/H+1、缓存、公钥元数据、原生多签叶子计数、无效交易之后状态、Prepare/Process 一致性、gas 溢出与 panic 边界。
4. **恢复、清理、导出**：`keeper/{keeper,key_history,export,audit,invariants}.go`、`keeper/lifecycle_boundary_test.go`、`keeper/export_test.go`、`app/pqcauth_review_regression_test.go`。核查待生效恢复重启、取消与轮换竞态、历史引用、零高度与普通高度导出。
5. **升级和出块**：`app/pqcauth_upgrade.go`、`app/app.go`、`app/wasmarchive/`、`x/pqcauth/{module,genesis}.go`、`app/pqcauth_phase1_test.go`。核查版本守卫、store loader、迁移和首次提交、无全量扫描、普通交易兼容、错误参数是否影响普通出块。
6. **客户端**：`x/pqcauth/client/` 和 `client/cli/`。核查 SDK keyring、独立因子检查的适用范围、模拟占位、离线 bundle、费用冻结、恢复签名及错误提示。
7. **发布门禁**：`.github/workflows/bridge-ci.yml`、`scripts/candidate-prerelease.py`、`scripts/test-release-candidate.sh`、`scripts/rehearse-pqcauth-lifecycle.py`，核查门禁实际验证的是否是最终交付产物。

审计不应仅依据已有测试名断言安全。请给每项发现提供严重度、前提、影响、路径/行号、最小复现与修复建议，区分“已复现缺陷”“待证实风险”“本阶段有意非目标”。

## 8. 上线前仍需完成

- 修复并回归两项已知参数下限问题；独立检查相邻参数是否还有同类可用性风险。
- 冻结最终源码和产物，记录提交/源码快照与二进制校验值，随后重跑验证，避免测试产物与发布产物不一致。
- 最新真实快照、最低支持配置、多验证人实际 v1.0.1 → v1.1.0 升级，测升级块和首次提交耗时、峰值内存及磁盘；事先约定可接受停顿阈值。
- 迁移/提交期间中断恢复、重启后继续出块及 AppHash 一致。现有内存测试和合成新链不足以覆盖这些条件。
- 公共测试网核心生命周期、普通与混合签名 IBC 往返、重启验收。此前 v1.0.1 Keplr 往返测试只支持该版本兼容性，不能替代当前 PQC 候选验收。
- 用目标硬件校准 250,000 gas、原生 ML-DSA gas 及 400 次/块预算，测试持续负载、无效交易、mempool recheck 和最低配置验证人，不以短时测试保证不会长时间卡块。
- 协调验证人使用同一审核产物，核对前置升级、计划名称、高度及配置；首发保持 OPTIONAL。发布、治理提案、线上二进制替换需要单独批准。

目前在已检查范围内未复现新的直接签名绕过、未授权密钥管理或普通交易导致的确定性链 halt；这不是不存在此类问题的证明。

## 9. 可直接给 Claude 的任务

> 请先阅读本交接文档及分阶段计划，确认已拉取包含本文件和第一阶段精简实现的交接提交，记录实际提交哈希，并检查是否另有未提交修改。独立复核两项尚未修复的 P2，重点检查签名认证、密钥恢复、资源有界性、共识确定性、升级停顿及 halt 风险。既有 Authz/Feegrant 保留属于第一阶段明确边界，不要擅自恢复第二阶段的授权索引或迁移。先提交带路径/行号、触发前提和复现方法的审计报告；不要自动部署、广播交易、提交治理或修改现有钱包。不能复现的风险请明确标注，测试通过不能写成无漏洞保证。
