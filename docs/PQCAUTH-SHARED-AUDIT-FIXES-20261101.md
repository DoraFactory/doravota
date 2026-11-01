# PQCAuth 共享审查修复记录

日期：2026-11-01 UTC。分支：`feature/pqcauth-sdk-keyring`。收件人：Claude 独立复审。

审查基线为 `3890a193981cac6f034c7e4094bfdb0d4e5e2790`，来源为 [共享审查](https://chatgpt.com/share/6ae6e5a1-fe58-83ed-b454-ea42061e8972)。本记录对应包含此文件的修复提交；读取 `git log -1 --format=fuller -- docs/PQCAUTH-SHARED-AUDIT-FIXES-20261101.md` 获取提交身份，再审查基线到当前 HEAD 的完整差异和未提交文件。

五项模块发现已分别修复或按批准范围禁用。PQC-02 的处理不是完整重试协议：用户明确选择首版不支持 FRESH_ACCOUNTS_ONLY，保留 OPEN/CLOSED。DEP-01 的工具链及依赖补丁尚未完成，仍阻止冻结正式发布候选。当前修改不是主网上线批准，也不是无漏洞保证。

## 修复明细

### PQC 01 解码前限制资源

`x/pqcauth/ante/decoder.go` 新增无复制的 protobuf wire 预检，先读取 TxRaw → TxBody → Any 的字段切片，再检查 PQC 扩展的绝对字节数和 signer entry 数。超过 256 KiB 或 32 个 entry 立即拒绝，之后才调用生成的 Unmarshal/Marshal。critical 和 noncritical 两条路径都覆盖；重复扩展拒绝；畸形 tag、截断长度和不属于这些 schema 的 group wire type 拒绝。

`ante/structure.go` 的治理参数检查也在构造完整 signer slice 之前完成，并以 uint64 比较长度，避免先转 uint32。后续规范编码、扩展位置、版本、签名长度和密码学校验保留。普通交易没有 PQC type URL 时仍走 SDK 原解码路径。

回归：`TestPQCWireRejectsAmplificationBeforeDecode` 覆盖两种扩展位置、33/32760/500000 个空 entry，要求拒绝且不调用后续解码器，累计分配小于 1 MiB。旧版同类 32760/500000 输入分别约分配 12.6 MB/202.6 MB。`TestPQCWirePreflightBoundaries` 覆盖计数边界和截断；`FuzzPQCWirePreflightDoesNotPanic` 覆盖预检畸形输入。

边界：这修复特定 PQC signer 解码放大，不宣称整个 SDK/P2P/RPC 已没有所有资源放大问题。测量是 TotalAlloc，不是峰值 RSS。

### PQC 02 首版禁用 fresh 注册

`types/params.go` 仅认可 OPEN/CLOSED（UNSPECIFIED 按已有规则映射 OPEN）。这同时约束 genesis、active/pending 参数及治理更新；`types/registration.go` 对非法注入的 FRESH_ACCOUNTS_ONLY 仍拒绝，不因捕获到 fresh 标记而放行，也不静默降级为 OPEN。原枚举编号保留，不重新分配。

没有新增 store、注册承诺、重试签名格式或升级扫描，也不回滚 SDK 公钥/sequence 来伪造“从未暴露公钥”。OPEN → CLOSED 仍需安全延迟，激活后仍不可放宽。OPEN 下消息 OOG 后可使用当前 sequence 和足够 gas 重试，前提是注册门槛仍开放、链未暂停相关操作。

回归：`TestPhaseOneRejectsFreshRegistrationParameters` 覆盖 OPTIONAL/REQUIRED 下 active/pending/genesis 拒绝；keeper 治理测试验证不能排队 fresh 模式，OPEN → CLOSED 延迟及不可逆保留；Ante/MsgServer 测试验证直接注入 fresh 参数及 fresh 标记仍失败。`TestPQCAuthOpenRegistrationCanRetryAfterMessageFailure` 使用真实经典签名及 ML-DSA PoP，覆盖 OPTIONAL/REQUIRED 下注册消息 OOG、公钥和 sequence 已提交、重试成功及后续受保护转账。

兼容性：不要把此版本直接替换到已经启用或排队 fresh 模式的实验链。生产支持入口是尚未初始化 PQCAuth 的 v1.0.1；实验链须重置或单独审计迁移。未来恢复 fresh 功能必须先实现交易绑定的安全重试协议，见两阶段计划。

### PQC 03 注册与后续签名模式一致

`ante/verify.go` 在验证注册证明之前要求注册交易所有 signer 使用 DIRECT；仍由 SDK 验证经典签名。Amino 注册失败时不会提交公钥、sequence 或 PQC policy。未受保护的普通 SDK Amino 交易不受此新增限制。

`client/cli/keyring.go` 与 `tx.go` 在注册入口拒绝显式非 direct 模式及当前 SDK 的 Ledger 记录。未知外部/watch-only 后端不能由 CLI 静态证明其支持 PQC 扩展；链上 DIRECT 检查仍是最终防线。没有删除现有 DIRECT 保护，没有实现 Amino PQC 授权。

回归：`TestPQCAuthRegistrationRequiresDirect` 覆盖 Amino 注册拒绝且账户仍保持初始状态、DIRECT 注册成功、Amino 转账/关闭保护拒绝、有效恢复证明及恢复签名的 Amino 恢复拒绝、DIRECT 受保护转账成功。`TestRegistrationRejectsIncompatibleBackend` 覆盖 CLI 模式和模拟 Ledger 记录；不代表物理 Ledger 测试。

### PQC 04 保留选块依赖顺序

`app/proposal.go` 对结构/公钥检查失败的无效候选仍可跳过，避免恢复“投毒公钥”的预算污染。遇到通过结构检查但超过 PQC 交易或剩余区块预算的候选，则立即结束选择，返回之前的前缀；不再从其后挑选低成本交易。

这一保守策略不新增 sequence 模拟器，对多 signer、独立 fee payer 或其他状态依赖都不会因预算删除前置交易后再保留其后缀。代价是可能放弃无依赖的后续交易，降低某些预算紧张区块的利用率。它不把 SDK 默认 NoOp mempool 的 ProcessProposal 变成完整 Ante 验证器。

回归：`TestPQCAuthProposalPreservesSequenceDependencies` 使用依次通过 CheckTx 的 B 注册、A 注册 sequence 0、A 转账 sequence 1。预算 3 时只保留 B，执行成功，A 注册可在后续区块成功；旧实现错误保留 A sequence 1。原生 ML-DSA、公钥投毒及四应用预算激活边界原回归保留。

### PQC 05 审计当前密钥有效性

`types/audit.go` 对 effective policy 的非零 current signing/recovery 引用反向检查 key ID、角色及当前高度有效性，失配产生 `inactive_current_key`。初次注册 H+1 前仅有 pending 引用，current 为零，不误报；现有 pending/历史/恢复校验保留。

回归：`TestAuditStateRejectsInactiveCurrentKeys` 分别制造 signing/recovery 失效但仍被 current 引用的状态，审计必须报告不一致。既有注册、轮换、恢复、撤销、导出导入测试继续验证合法过渡。这是诊断补全，不是改变实际验签对失效 key 的拒绝规则。

## 验证及资源

仅运行本机单进程内存应用测试和有限模糊测试；没有向公共链发送交易，没有启动新验证人或负载攻击。环境为 Go 1.26.5、GOMAXPROCS=2、Go 构建并发 2、GOMEMLIMIT=4GiB（软目标，不是 cgroup 硬限制），使用已有依赖缓存和 GOPROXY=off。

- 发布门禁包含全仓单元测试、显式链状态确定性/导入导出/导入后模拟、Python 发布工具测试和 IBC 固定源清单检查。新增修复回归被加入必跑列表。
- 最终门禁通过：14 个测试包、598 个通过测试/子测试事件；默认跳过的 3 项链模拟另行启用并全部通过；Python 发布工具 7 项及 IBC 固定源 906 个文件检查通过。完整日志：`/tmp/pqcauth-shared-fixes-handoff-gate.log`，结构化记录：`/tmp/pqcauth-shared-fixes-handoff-gate/unit.jsonl`、`simulations.jsonl`。
- 20 秒 wire 模糊测试通过，25,100 次执行；日志：`/tmp/pqcauth-shared-fixes-fuzz.log`。短时 fuzz 不是持续模糊测试或抗压验收。
- `go vet -p=2 ./...` 通过，日志：`/tmp/pqcauth-shared-fixes-vet.log`。
- 独立验证旧问题的历史材料：`/tmp/pqcauth-share-verification.npTdBY/`；这些旧测试的 PASS 表示复现漏洞，不是修复通过，不能当作当前门禁。

复跑（仓库根目录）：

```bash
GOMAXPROCS=2 GOMEMLIMIT=4GiB GOCACHE=/tmp/doravota-go-build \
GOMODCACHE=/tmp/doravota-go-mod GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-p=2 \
RESULTS_DIR=/tmp/pqcauth-claude-recheck bash scripts/test-release-candidate.sh
```

## DEP 01 尚未完成的发布依赖

当前 `go.mod`/Dockerfile/发布流程仍使用 Go 1.26.5，x/net 为 0.58.0，OTLP log gRPC exporter 与 SDK log 为 0.20.0。已核实上游的 [HTTP2 HPACK 公告](https://pkg.go.dev/vuln/GO-2026-6617)、[Go 1.26.10 安全发布](https://groups.google.com/g/golang-announce/c/66pojueaQek)、[日志 TLS 配置公告](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-w34q-cm8f-9c5x)、[日志 CPU 空转公告](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-hjf4-fphr-2h65)。配置相关的利用前提仍需针对部署核对。

本次终端解析 `proxy.golang.org` 失败，本地仅有旧依赖和工具链；没有伪造 go.sum，也没有只改版本号就宣称补丁完成。网络恢复后需要安装受支持的安全补丁工具链，协调升级 x/net（相关修复至少 0.60.0）及 OTel log 模块（相关修复至少 0.21.0），检查 API/传递依赖变更，再重新跑完整门禁、静态检查和正式构建。不要把本次旧工具链测试当作新工具链验收。

## Claude 复审重点及剩余发布条件

1. 对照 wire 字段号、重复字段、错误 wire type、critical/noncritical、绝对及治理限额，确认不存在生成解码前的 PQC signer 放大旁路。
2. 确认 fresh 模式在 genesis/pending/治理/执行各入口均被拒绝，OPEN/CLOSED 与 legacy cutoff 保留预期语义。
3. 确认注册 DIRECT 限制没有影响未受保护账户的普通 Amino 和 IBC；验证所有 signer 而不只 owner。
4. 确认预算截断没有允许预算溢出、错误提交 tracker 或保留依赖后缀；评估利用率取舍。
5. 检查 signing/recovery 审计反向引用及 H+1/延迟恢复边界，确认不误报合法 pending 状态。
6. 完成 DEP-01、独立复审后，再冻结源码及二进制哈希，重跑最终产物四验证人生命周期、快照升级、中断恢复及公共测试网 IBC 验收。旧提交的快照和 92 笔演练不能替代本次产物验收。

没有打版本标签、创建 Release、修改运行节点或部署公共网络。
