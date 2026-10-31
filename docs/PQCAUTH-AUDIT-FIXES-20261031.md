# PQCAuth 独立审计后的修复记录

日期：2026-10-31。基于 `feature/pqcauth-sdk-keyring` 的 `d3099314cbb14ff7c5a10e167e1c1b0e780ffe12`，对应 Claude 的 P2-A、P2-B、F1、F2、F3。原始独立报告保留不改；本记录描述后续工作区修改，不代表已经通过独立复审或正式上线验收。

## 修复内容

### P2-A 授权扩展容量

`x/pqcauth/types/capacity.go` 用生成的 protobuf `Size()` 计算签名条目及外层开销，再乘以 `MaxPqcSigners`。包括完整 ML-DSA-65 签名、SDK bech32 解码最大输入长度 1023、最大宽度的索引/密钥 ID/策略版本和长度前缀，不凭经验设置常数。

`Params.Validate` 对当前和待生效参数都应用下限；治理和 genesis 同样不能接受 1 字节或低于容量的配置。结构测试验证 2、8、32 条最大宽度记录恰好放入下限，小一字节则拒绝；类型测试还包含单条编码边界。结构测试不是这些合成地址/索引能够通过真实账户验签的声明。

### P2-B 和 F3 最低功能与预算组合

- `MaxPqcSigners` 最低 2，保证受保护发送人与独立受保护付款人。
- 每笔有效验签预算最低 3，可容纳注册/恢复的两次证明加付款人授权，或轮换的旧因子、新证明与付款人授权。
- 每笔预算不能小于配置的 PQC 签名者上限，每块预算不能小于每笔预算。
- 默认参数保持 8 个签名者、64 KiB、每笔 16 次、每块 400 次不变。预算字段 0 仍按已有兼容规则解释为默认值，而不是允许零次。
- 原生 ML-DSA 多签同样受预算限制。实测最低配置下 2-of-2、3-of-3 成功，4-of-4 明确超预算拒绝；默认预算下 7-of-7 成功。最低配置不承诺支持任意数量叶子的多签。治理缩减预算前仍需审查既有多签和业务组合。

最低配置的完整 App 测试使用真实经典/PQC 签名执行注册、轮换、恢复和恢复后转账，费用均由另一个受保护账户支付，并验证保护关闭可执行、状态审计一致。治理处理器测试确认非法请求不写待生效状态，合法最低参数激活后正常转账及关闭/开启保护仍成功。

原来以 1 次预算构造的提案边界测试改用合法下限，仍检查超预算拒绝、恶意公钥污染、四应用激活边界，以及 Prepare/Process 一致性，没有删掉原来的拒绝检查。

### F2 当前区块 gas 容量预检

治理修改验签单价或每笔预算时，检查：

```text
max(signature_verification_gas, proof_verification_gas) × tx_verification_budget
    < 当前有限的 consensus.block.max_gas
```

使用除法比较避免溢出，`-1` 视为无限区块 gas。没有把报告中的主网 600,000,000 写入生产逻辑；它只作为回归测试数值。

这是保守的密码学容量预检，不是完整交易 gas 估算：未包括原生 SDK 签名、交易字节、存储和业务执行，也没有承诺仅多留 1 gas 就足以执行交易。真实交易仍受 SDK gas/字节和 PQC 次数共同约束。共识/auth 参数之后可以独立修改，自定义 genesis 也需要单独检查容量；本次未给其他模块增加治理钩子。

不在 BeginBlock 根据动态 gas 上限报错，避免“其他模块降低 gas 上限 → PQC 参数归一化失败 → 整链 halt”。取消待生效策略、只改变紧急模式等不改验签容量的操作不被此预检阻塞。测试覆盖有限/无限/零 gas、拒绝后状态不变、紧急治理，以及区块 gas 随后缩小时参数归一化仍成功。

### F1 委托风险提示

注册和 `set-protection true` 在 stderr 输出运行时警告，不仅是 `--help`。明确说明：Authz/Feegrant 注册后、恢复后仍有效；被授权人被攻破可以使用授权范围内的资产或手续费额度，不代表整个账户所有资产都可被动用。

警告提供 SDK 的 `query authz grants-by-granter` 和 `query feegrant grants-by-granter` 查询入口，要求用户检查正确链及全部分页。明确标注“未查询、未撤销”，不把离线生成、RPC 失败或部分分页当成“没有委托”。stderr 不污染 unsigned transaction / bundle 的 stdout。

本次没有实现自动查询列出所有授权：它不是交易验签安全前置条件，也不能用无限分页/扫描阻塞注册。完整授权展示仍属第二阶段；不新增索引、链上扫描、强制撤销或被授权人 PQC 门槛。

## 代码入口与测试

- 参数：`x/pqcauth/types/{params,capacity}.go`、`types/capacity_test.go`。
- 治理：`x/pqcauth/keeper/msg_server.go`、`keeper/capacity_test.go`。
- 结构边界：`x/pqcauth/ante/capacity_test.go`。
- 实际交易与多签：`app/pqcauth_capacity_test.go`。
- CLI：`x/pqcauth/client/cli/{tx,delegation_warning}.go`、`delegation_warning_test.go`。
- 必测门禁：`scripts/test-release-candidate.sh`。
- 四验证人脚本：`scripts/rehearse-pqcauth-lifecycle.py` 的隔离网参数改为 4 个 PQC 签名者、每笔/每块 4 次，满足新参数关系。不是生产默认值变化。

完整测试及模拟日志目录：`build/test-results-audit-fixes/`。以下结果均来自本次修复后的工作区。

## 验证状态

本地验证完成，结果如下：

- `scripts/test-release-candidate.sh` 通过：14 个测试包、582 个测试/子测试通过，无失败；另行显式启用的 3 项链模拟全部通过。7 项 Python 工具测试通过；906 个固定版本 IBC 文件及允许补丁检查通过。
- 当前代码构建成功；`go vet -p=2 ./x/pqcauth/... ./app/...` 和 `git diff --check` 通过。
- 原安全审查 overlay 的 500 个畸形提案用例通过；随后合法转账、提交、空块和状态审计仍成功。日志：`/tmp/doravota-audit-fixes.RVEimp/malformed-proposals.log`。
- 授权扩展与密码学 fuzz 各设置 20 秒，均通过，分别执行 101,342 次和 2,031 次。日志：上述临时目录下的 `fuzz-extension.log`、`fuzz-crypto.log`。短时 fuzz 不代表穷尽所有输入。
- 四验证人隔离网演练通过：92 笔交易成功、6 项非法操作按预期拒绝；覆盖注册、离线签名、轮换、恢复等待期重启、恢复后交易、委托兼容、单节点离线期间混合交易、历史记录增长及再次重启。最终高度 112 的四节点 AppHash 一致，测试节点已停止。

四验证人证据：`/tmp/doravota-audit-fixes.RVEimp/four-validator/evidence/result.json`；最终一致性：同目录 `history-restart-agreement.json`。这是合成隔离网，不是主网快照升级耗时测试，也没有测试公共 IBC 对手链或实体 Ledger。

演练二进制：`/tmp/doravota-audit-fixes.RVEimp/dorad`；SHA-256：`e96689e7ad06acf1239087c8a921ba29eaae2dc3b3347f90216dbeb1209476d6`。

本记录随修复代码一并提交，具体提交以 Git 历史为准。Claude 原始报告保持不变，SHA-256 仍为 `3bf03061e45a4b03d1947d7077ed476531985ce48f7bb426484c69be22cff69f`。

## 兼容和上线边界

这些修改面向尚未在公共链激活的 v1.1.0 候选，支持入口仍是没有 PQC store 的已完成 v1.0.1 升级状态。默认初始化满足新约束，没有增加账户、Authz、Feegrant 集合扫描。

已经运行旧实验性 PQC 候选且使用了新下限之外参数的开发链，不能直接热替换本二进制；需重建隔离网或单独审查状态迁移。新的参数校验不是对旧实验数据库的无条件兼容承诺。

尚需：独立复审本次修复；最终源码/二进制冻结；真实快照、最低硬件、实际升级高度与首次提交耗时及中断恢复；公共测试网生命周期和 IBC 往返。未发布版本、广播公共链交易、修改已有钱包或部署生产节点。
