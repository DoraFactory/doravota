# v1.0.1 IBC Amino 修复：升级接入与远程验证补充报告

日期：2026-10-28（北京时间）。状态：未提交、未推送的开发候选，可交独立审查；不是主网发布批准。

## 本次完成内容

在第一阶段 A 方案上补齐 v1.0.1 升级接入、提前启动防护、重启路径、发布版本信息、运维说明和远程四验证人升级演练。
没有改用新的 IBC 上游版本，没有加入 PQCAuth，没有改线上浏览器或提交主网提案。
所有本次编译、Go/Python 验收和节点运行均在远程执行；本地仅编辑、阅读和归档证据。

- 分支：`fix/v1.0.0-ibc-amino-compat`
- 基线：v1.0.0 / `1a2b30927a7799d4cd6890a3fb3fa80d25613fa2`
- 本地：`/Users/bun/.codex/worktrees/vota-ibc-amino-compat/doravota`
- 远程源码：`amaci-testnet-operator:/root/vota-ibc-amino-upgrade-20261028/src`
- 远程日志：`/root/vota-ibc-amino-upgrade-20261028/evidence`
- 四节点原始演练：`/root/vota-ibc-amino-upgrade-20261028/rehearsal/run2`
- 第一阶段报告和证据保留于 [IMPLEMENTATION-REPORT.md](IMPLEMENTATION-REPORT.md)，其中未接入 handler 的描述已由本报告更新。

## 对 Claude 审查意见的处理

| 审查项 | 本次处理 / 边界 |
|---|---|
| 缺少升级 handler | 注册 `v1.0.1`，原样返回模块版本表，不调用 RunMigrations、不增加 store |
| 新二进制提前运行就改变验签 | 在 BaseApp 构建前检查已提交 upgrade store；只允许正确的 H-1 升级边界或已激活状态；PreBlock 再检查激活 |
| 版本和 Cosmovisor 目录不一致 | VERSION、CLI 默认值、Docker 默认值、计划名统一 v1.0.1；发布 build-info 从 VERSION 生成计划名 |
| 历史重放 | 明确必须使用历史二进制；未实现按高度切换历史验签规则，不声称新二进制可重放旧历史 |
| 客户端显式 false | 文档明确旧 CLI/Amino 签名需要更新；浏览器补 false 的 workaround 不应上线 |
| 多验证人升级及重启 | 远程四验证人治理升级、提前启动拒绝、升级后转账及重启已通过，详见下文 |
| PQCAuth 后续回归 | 本次未改另一个工作分支。其未来发布必须带上本补丁和 v1.0.1 激活兼容性并重新测试 |
| 主网快照 / 真钱包 / 三链实际 IBC | 仍待验收；不能用本次隔离链及 CheckTx 结果代替 |
| 提交 / 正式发布 | 本轮没有 commit、push、tag、Release、部署或主网操作 |

## 代码实现

### 签名修复保持 A 方案范围

`third_party/ibc-go` 仍只有两个上游文件改变：删除 transfer MsgTransfer.use_aliasing 的
`amino.dont_omitempty` 标记、重新生成 tx.pb.go 的描述信息。906 个文件的快照完整性再次通过。
false 在 Amino 签名字节中省略；true、Direct、Protobuf 字段编号、路由及存储布局保持原补丁约定。

### 升级与启动边界

代码：`app/upgrades/amino/boundary.go`、`app/app.go`。

1. handler 名称为 v1.0.1，要求已有 v1.0.0 的 Wasm archive 激活标记；返回原模块版本表。
   SDK 正常记录升级完成、清除计划并更新协议版本元数据。无应用模块迁移或新 store。
2. 启动前只读打开已提交 upgrade IAVL 树，核对根哈希与 CommitInfo；不信任单独的本地 upgrade-info 文件。
3. 旧状态只有同时满足“链上 v1.0.1 计划、数据库高度 H-1、正确本地 halt 信息、未 skip”才放行。
   提前启动、伪造本地文件、错误计划/高度、缺少文件或跳过升级都会拒绝。
4. 升级后凭已提交的 v1.0.1 完成记录允许重启；不依赖本地 halt 文件长期存在。
5. 全新链 InitGenesis 在现有 upgrade store 写应用命名空间标记，允许从新规则开始及重启。
   此标记不由现有链的升级 handler 写入；不是旧链重放捷径。
6. PreBlock 在执行模块前检查是否已激活，或者正位于对应计划高度；执行后确认升级完成。

**“不做迁移”不等于“数据库一个字节都不变”：** x/upgrade 的正常计划/完成/协议元数据会更新；
全新链初始化有上述标记。现有链不迁移 IBC/Wasm 数据，也不改其存储布局。
本二进制不是历史规则分段实现。旧链重放仍需旧版本，Cosmovisor 不会自动替用户重建历史版本序列。

### 发布及维护

- 新增 [验证人说明](../VALIDATOR-1.0.1.md)：暂存路径、校验、协调切换、重启、恢复与客户端兼容边界。
- CHANGELOG 独立增加 v1.0.1 节，保留 v1.0.0 历史信息和历史 handler 名称。
- release workflow 使用动态计划名；开发分支加入 CI push 触发条件。
- release candidate gate 要求升级生命周期和四个 Amino 专用测试实际执行，遗漏/skip 会失败。
- 未运行 GitHub Actions。本地 workflow 修改与远程运行相同测试入口，不等于 GitHub CI 已通过。

## 远程实际执行结果

Go 1.26.5 / Linux amd64。构建测试容器限制 4 CPU / 10 GiB，四验证人容器限制 4 CPU / 8 GiB，
节点容器 `--network none`，四节点使用容器内 loopback 独立端口，测试链 ID 为 `isolated-amino-v101-rehearsal`。
只生成隔离测试密钥与创世测试币，没有使用主网资金。原验证人和 relayer 未停止或修改。

| 验证 | 结果 | 证据 |
|---|---|---|
| 原版签名字节固定向量 | 通过 | [baseline-golden.log](evidence/upgrade/baseline-golden.log) |
| 原版运行修复回归 | 按预期失败，退出码 1 | [baseline-negative-control.log](evidence/upgrade/baseline-negative-control.log) |
| 修复后的验签/描述信息回归 | 通过；含省略 false、显式 true、旧显式 false 拒绝、篡改拒绝、Direct/bank 固定向量 | [compatibility.log](evidence/upgrade/compatibility.log) |
| 启动边界 12 用例与实际 UpgradeKeeper 生命周期 | 通过；检查前后整个测试数据库未被 preflight 写入，handler 前后模块版本表一致 | [activation.log](evidence/upgrade/activation.log) |
| 根模块 go test ./... | 通过 | [root-tests.log](evidence/upgrade/root-tests.log) |
| 上游 transfer 子包 | 通过 | [transfer-tests.log](evidence/upgrade/transfer-tests.log) |
| go vet ./... | 通过 | [vet.log](evidence/upgrade/vet.log) |
| CGO_ENABLED=0 Linux amd64 构建 | 通过 | [build.log](evidence/upgrade/build.log) |
| 发布测试入口及必执行用例 | 通过，包含 4 个发布工具 Python 测试与全部必需 Go 用例 | [release-gates.log](evidence/upgrade/release-gates.log) |
| 显式模拟：确定性 / 导入导出 / 导入后模拟 | 通过；Enabled=true，Seed=42，NumBlocks=10，BlockSize=5，Commit=true | [simulations.jsonl](evidence/upgrade/release-gates/simulations.jsonl) |
| IBC 源码快照完整性 | 通过，906 文件仅指定两个文件改动 | [source-integrity.log](evidence/upgrade/source-integrity.log) |
| 四节点治理升级与重启 | 通过 | [result.json](evidence/upgrade/rehearsal/result.json) |

命令入口：`scripts/test-ibc-amino-review.sh`、`scripts/test-release-candidate.sh`、
`scripts/rehearse-amino-upgrade.py`。退出码见 [status.tsv](evidence/upgrade/status.tsv)
和 [release-gates.exit](evidence/upgrade/release-gates.exit)。

### 四验证人实际流程与交易

1. 校验正式 v1.0.0 二进制 SHA-256 后，用它启动全新四验证人隔离链，等待四节点同步。
2. 升级前普通转账成功。
3. 提交 v1.0.1 软件升级提案，四验证人投赞成票，治理通过，升级高度 **85**。
4. 高度到达前停止旧节点，向 node0 放入提前伪造的本地升级文件，启动新二进制被拒绝。
   移除该文件并恢复旧节点运行；[early-start.log](evidence/upgrade/rehearsal/early-start.log)。
5. 四节点均在正式升级高度生成 halt 文件，停止旧进程，切换新二进制。到高度 **89**，四节点 `catching_up=false`。
6. 升级后普通转账成功。固定高度 **87** 四节点 AppHash 一致：
   `0252F64418BDEFC31040DCA012E9CAC1A5942746C6177D8EC6B815180D8B49AB`。
7. 停止四节点，移走全部本地 upgrade-info.json，再用新二进制重启。到高度 **94** 四节点均同步；
   固定高度 **92** AppHash 一致：`6BC16A1B19912F327F50B90213DA25F371C68E865F5E56E518A33E7A393EB98C`。
8. 演练结束停止隔离节点，容器自动移除，证据保留。

这些是隔离链交易，没有公网浏览器链接；下列链接指向保存的 RPC 交易原始回执，code 均为 0：

| 操作 | 交易 hash / 回执 |
|---|---|
| 升级前转账 7 peaka | [A8C4500B84019E219FAE6E7CB5B5ABB92D279929CE60719929C0CE5C87672927](evidence/upgrade/rehearsal/tx-A8C4500B84019E219FAE6E7CB5B5ABB92D279929CE60719929C0CE5C87672927.json) |
| 提交升级提案 | [A624A8E85A63B965429BF1E8C852BCE593835F05B6EBA43305D4481BB3FD8FDC](evidence/upgrade/rehearsal/tx-A624A8E85A63B965429BF1E8C852BCE593835F05B6EBA43305D4481BB3FD8FDC.json) |
| 升级后转账 7 peaka | [F268552063585E6D865624852A2D8D82BFB4269DE860F533760C0474A2A10D46](evidence/upgrade/rehearsal/tx-F268552063585E6D865624852A2D8D82BFB4269DE860F533760C0474A2A10D46.json) |

四笔投票回执也在同一 evidence 目录，哈希列表见 result.json。
这是脚本控制的旧/新进程切换，**没有验收生产 Cosmovisor/systemd 自动切换**。
链是新建隔离状态，**不是主网快照**。普通转账和升级成功也不证明实际 IBC 数据包已到账。

## 失败 → 修正 → 复测

- 第一轮：IsActive 在 SDK cacheMergeIterator 正常遍历结束后读 Error()，造成“invalid cacheMergeIterator”。
  按 SDK GetDoneHeight 的正常结束行为处理为“没有完成记录”，修复后此处通过。原日志保留于 `evidence/upgrade/attempt-1/`。
- 第二轮：生命周期测试只设置旧式 BlockHeight，没有设置新版 HeaderInfo.Height；SDK 完成高度读成 0。
  补齐测试上下文 HeaderInfo 后生命周期、根模块、发布入口全部通过；原日志在 `attempt-2/`。
- 四节点首次脚本在解析 gov 模块账户时未处理 SDK 新版 account.value 包装，停在提交提案前。
  修正脚本后 run2 完整通过。run1 原始临时节点保留于远程；没有修改链代码来绕过此问题。

## 候选产物

- 新二进制：`/root/vota-ibc-amino-upgrade-20261028/src/build/dorad-amino-review`
- 版本：`v1.0.1`；提交标识：`v1.0.0-plus-uncommitted-amino-upgrade`，明确不是已提交的正式构建。
- SHA-256：`cab41596bbd4da16b24c09ad7280831bef15fb3be8a3e3f59fbd34c27bae8103`
- 演练使用的正式旧二进制 SHA-256：`5c741ca406ee2ecb811dd62d83e9a446fee051e2947522525c2560a0a7ce968a`
- [binary-version.txt](evidence/upgrade/binary-version.txt)、[binary-modules.txt](evidence/upgrade/binary-modules.txt)、[binary.sha256](evidence/upgrade/binary.sha256)。
- [源码指纹清单](evidence/upgrade/source-manifest.sha256)：远程最终源码中 984 个 Go/proto/依赖/脚本/workflow/版本文件的 SHA-256，排除 build 和证据目录。

## 尚未完成的发布条件

1. 当前最终代码的主网真实快照升级、归档状态及真实 feegrant/IBC 状态核对。
2. 公共测试网升级，以及真实 Keplr 软件钱包、Keplr+Ledger 的 IBC 发送。
3. Osmosis、Cosmos Hub、Noble 的双向到账、回执、超时退款；Skip Swap 完整路由。
4. PQCAuth 分支集成本修复并验证不会回退新规则；浏览器实际部署包确认不包含补 false workaround。
5. 正式 commit、GitHub CI、固定提交正式构建、SHA-256、Release 和治理提案；本轮均未执行。
6. 生产 supervisor/Cosmovisor 配置验收、state sync、ARM64、race、压力测试仍不在本轮通过范围。

没有重跑上游完整仓库/独立子模块的 make format/lint/test-unit/proto-all；具体限制沿用第一阶段说明。
此前 A 方案的官方 proto-builder 再生成通过记录保留；本轮未修改这两个上游文件，未重复运行生成器。
