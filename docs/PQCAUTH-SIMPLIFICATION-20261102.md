# PQCAuth 参数与验签额度精简记录

日期：2026-11-02。基线：`a63c69a8912efb5a342dc7a408898f9e1598e07f`。
分支：`feature/pqcauth-sdk-keyring`。本轮按用户确认实施精简；不是生产发布批准。

## 结论与边界

删除每笔 16 / 每块 400 的独立验签次数额度，以及预算装饰器、预算 tracker、
自定义 Prepare/ProcessProposal 过滤、签名者依赖屏蔽和 fresh 注册捕获标记。
恢复 SDK 默认 proposal；保留 BaseApp 的 canonical decoder、启用的区块 gas meter、
SDK 签名数检查、交易字节计费和每次密码学操作前的 gas 扣除。

原来的次数限制是额外保守资源阀，不是 SDK 要求，也不是容量 benchmark 得出的值。
SDK tx_sig_limit 本身可治理，因此“最多永远只有 7 个签名，16 永远碰不到”不成立。
现在用真实 17 叶原生 ML-DSA 多签、显式提高的 SDK 上限和足够 gas 验证不再有额外
16 次门槛。该交易仍承担公钥写入、字节、验签等成本，不能把 750 当整笔 gas。

删除次数额度不等于网络自适应容量、无拒绝服务风险或保证恢复优先入块。
有限 max_gas/max_bytes 的实际配置、最低硬件、有效/无效 admission、recheck、
跨节点传播和最坏交易形态仍需验收。SDK 默认 NoOp ProcessProposal 不执行完整 Ante；
它接受一个 proposal 不证明其内每笔交易有效。FinalizeBlock 仍独立验签并拒绝错误输入。
默认新开发链 genesis 可以是 max_gas=-1；上线必须核实实际有限资源参数，不能凭默认值保证容量。

## 最终参数分类

| 类别 | 字段／规则 | 本轮设置 |
| --- | --- | --- |
| 可治理 | enforcement_mode | 默认 OPTIONAL；另支持 REQUIRED_FOR_REGISTERED；拒绝 DISABLED、REQUIRED |
| 可治理 | verification_gas | 合并为一个字段，默认/下限 750，上限 10,000,000；授权、证明、恢复签名逐次扣除 |
| 可治理 | emergency_mode | NORMAL、PAUSE_NEW_KEYS、PAUSE_PQC_TRANSACTIONS |
| 启动后不可变 | network_id | 签名网络域，长度 16–64 字节 |
| 启动后不可变 | governance_safety_delay_blocks | 17,280 块 |
| 启动后不可变 | recovery_delay_blocks | 107,520 块，约 7 天 |
| 启动后不可变 | max_emergency_duration_blocks | 46,080 块，约 72 小时 |
| 常量 | 算法 | ML-DSA-65，不再存 allowed_algorithms 列表 |
| 常量 | extension 结构限制 | 8 条、64 KiB；独立 raw-wire 预检仍为 32 条、256 KiB |
| 常量 | 历史保留 | 每角色 16 条 terminal 记录；current/pending 继续固定保留，key ID 不回退 |
| 删除 | 注册模式／cutoff | 注册常开，应急暂停除外；删除 CLOSED/FRESH 状态与截止调度 |
| 删除 | 两个次数额度 | 不再给 native ML-DSA 和 PQCAuth 增加并行额度 |
| 服务端状态 | pending / pending_activation_height / pending_emergency / emergency_expires_height | 不可由治理请求直接注入 |

8 条/64 KiB 是固定结构防线，不是 SDK 原生签名数限制的复制品；若未来提高 SDK
tx_sig_limit，它们不会自动扩大。原先将这两项变成可治理且与预算联动，增加了配置复杂度；
现在删除治理字段而保留固定检查，不把解码前的内存防御也一起删掉。

价格更新只保留一个小型治理合理性检查：三次验签价格必须小于当前有限块 gas，
以给两证明和独立受保护 payer 留下可能空间；它不限制交易验签次数，也不证明剩余
空间足够所有业务成本。应急和取消不受这个检查阻塞；不向 BeginBlock 增加失败检查。
价格上涨/更强 enforcement 等待安全延迟；降价遵循已有 H+1 普通更新规则。

紧急调度保留既有显式意图与同块保护，没有再次重写已审计的调度协议。
完整取消不续期，emergency_only 保留普通计划，暂停到期不复活。
紧急暂停应独立提案；同一提案后续消息失败会回滚前面的暂停。
被拒的普通治理提案不会自动重试。

## 编码和升级兼容性

- Params reserved：3,4,5,6,7,8,9,16,18,19；新 verification_gas 使用 21。
- ScheduledParams reserved：2,3,4,5,6,7,8,11,12,13；新 verification_gas 使用 14。
- QueryParamsResponse 删除并 reserved 原字段 4（effective_registration_mode）。
- 被移除的字段名称同时 reserved。DISABLED/REQUIRED 保留枚举编号但验证拒绝。
- 模块版本提高到 4，启动边界拒绝旧实验 PQC 模块版本 1/2/3。
- reserved 不是迁移。旧双价格 wire 不会静默变成新默认价；缺少新价格的状态校验失败。
  支持的生产入口仍为未激活 PQCAuth 的 v1.0.1。旧实验数据库不能混跑/热替换。
- 未改 VERSION、密码算法实现、签名域、DIRECT、生命周期精确授权、经典/PQC 双因子。
  未打标签、创建 Release、广播公共交易、修改线上节点或使用真实钱包。

state/query pb.go 用 pinned gogoproto v1.7.2 的 protoc-gen-gocosmos 重新生成，
proto import 来源为当前 go.mod 缓存中的 SDK v0.55.0 / cosmos-proto v1.0.0-beta.5。
`plugins=grpc,paths=source_relative`；没有手改生成的解码分支冒充生成结果。

## 测试替换而非隐藏失败

预算 tracker/公钥发现缓存随功能删除，专属 poisoning、参数激活额度过滤、fresh marker
测试退休。与它们无关的 SDK 新账户模拟、原生嵌套多签 gas floor、严格解码、真实
签名失败、恢复付款人、委托、生命周期授权、治理原子回滚及重启导出断言继续必跑。

- 原 minimum-budget 生命周期改为无额外额度的受保护 payer 注册/轮换/恢复回归。
- 原截断/独立交易选择改为 SDK gas/byte policy 和全部顺序依赖交易可执行。
- 混合流量测试每块 402 笔（400 笔 native/hybrid + 恢复或取消 + 普通交易），两块均执行；
  使用 600M gas、10MB 字节设置，证明大于原 400 验签额度时恢复不因旧额度被省略。
- 固定 extension 上限检查覆盖 8/9 条、最大宽度字段和 64KiB 超限；raw-wire 防分配放大继续必跑。
- 调度矩阵用真实可治理价格上涨替代已删除的预算缩减，仍覆盖原紧急/普通交错属性。
- 新增 descriptor reserved 回归及旧价格 wire 拒绝回归，模块版本边界增加 version 3 拒绝。
- 发布 gate 同步新测试名，不继续要求已删除功能的成功路径。

## 本机实际执行证据

Go 1.26.10，离线依赖缓存，GOMAXPROCS=2、GOFLAGS=-p=2。
最终全仓 gate：14 个包、773 个测试/子测试通过事件，0 失败；另启用的三项链模拟通过。
发布工具 7 项 Python 测试、906 个固定 IBC 源文件校验通过。
`go vet ./...`、开发二进制构建通过；app/Ante/keeper/types 重点回归 race 检查通过。
不把测试事件数量等同于交易数量或安全证明。

密码学微基准（-cpu=1、三轮、共享主机，未绑固定物理核）中 256-byte 消息：
SDK 80.7–84.2 微秒；PQCAuth 77.6–84.4 微秒。64KiB 消息样本另记录在日志中。
这些结果支持同量级计价，不标定最坏块容量或宣称全链成本恰好相等。

真实应用层 5,000 笔、每笔 7 个 PQC signer：

| 操作 | 总时间 |
| --- | ---: |
| 首次 CheckTx(New) | 8.655 秒 |
| 空块后 Recheck，第 1 轮 | 1.697 秒 |
| 第 2 轮 | 1.814 秒 |
| 第 3 轮 | 1.645 秒 |

全部调用返回成功；样本交易 25,687 bytes，首笔 gasUsed=586,770，recheck 保持相同。
最后取样执行首笔交易时仍独立验证。这里是直接 ABCI 应用调用，不是实际 5,000-entry CometBFT
mempool、多节点出块或最低硬件验收；不能用这些数值承诺区块时间。

原始本机证据目录：`/tmp/pqcauth-simplify.qFvtC8/`：

- `gate-final.log`、`gate-final/unit.jsonl`、`gate-final/simulations.jsonl`
- `vet-final.log`、`race.log`、`crypto-benchmark.log`、`recheck-5000.log`
- `fixture-prepare.log`、`fixture-sign.log`（10 笔合成负载生成，不是节点验收）
- `load-smoke.log`（四节点尝试失败的原始错误）

临时证据没有随 Git 提交；读不到该环境时应复跑，不能仅凭本文复核原始日志。

开发构建：`/tmp/pqcauth-simplify.qFvtC8/dorad`；SHA-256：
`08be69d5aea979d31ac258f7c79e27aca30a3e41a41cdbb03481d8c3749004fe`。
这是工作树开发二进制，不是带正式版本身份的冻结产物。

## 四节点与发布待办

本机四节点脚本在创建 localhost socket 时被沙箱拒绝：PermissionError / Operation not permitted。
节点尚未启动，四节点生命周期、5,000 笔容量及快照升级在本轮本机均未完成。
没有绕过沙箱、尝试更换端口规避限制或操作现有公共节点。

新增 `scripts/rehearse-pqcauth-capacity.py` 和 opt-in Go fixture；仅接受 pqc-isolated- 链，
固定公开测试密钥、合成余额、localhost 四验证人、新目录，退出只停止自己启动的进程。
先无负载采样，再临时停止三个测试节点填满 5,000 笔池，恢复法定人数后观测清空过程。
记录 CheckTx 回执、块内成功码/数量、AppHash、RSS、延迟；主动停止 quorum 的区间不当作正常块延迟。
600M gas / 22,020,096 bytes / 5s 是显式实验设置，不冒充本轮查询的主网参数。
每笔 declared gas=3M；它是一个固定形态负载，不是穷尽最坏填块测试。

AMD64 CI 增加 classic/hybrid/native 各 5,000 笔实验，保留原 packaged lifecycle 和
顺序升级门禁。延迟是否超 baseline 15% 写入结果供审查，不把共享 runner 数据作为
最低硬件认证；功能失败会失败退出。脚本生成阶段已离线跑通，实际网络部分待 CI 验证。
CI 结果须按本次提交独立核对，不能借用基线绿色状态。
本轮推送尝试未成功：shell 无法解析 github.com；GitHub 连接器能读取并确认远端仍为
基线 a63c69a，但写入被会话的 approval=never 权限拦截。因此新 CI 尚未启动，
当前交付为本地提交，不能称已推送或 CI 已通过。

冻结前还需要：独立审查本次删除面；真实四节点容量结果；最低目标硬件的最坏 body、
无效 admission/recheck、混合拥堵中的恢复延迟；同一最终二进制真实快照升级/中断重启；
公共测试网生命周期与 IBC。当前只交付待审代码，不宣称已可生产发布。

复跑：

```sh
bash scripts/test-release-candidate.sh
PQC_RECHECK_COUNT=5000 GOMAXPROCS=2 go test ./app -run '^TestPQCAuthRecheckBoundedSevenSigners$' -count=1 -v
go test -c -o /tmp/pqcauth-load.test ./app
python3 scripts/rehearse-pqcauth-capacity.py --binary /path/to/candidate-dorad \
  --fixture-binary /tmp/pqcauth-load.test --work-dir /tmp/new-pqc-isolated-run \
  --kind hybrid --count 5000
```
