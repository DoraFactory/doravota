# v1.0.0 IBC Amino 兼容修复：A 方案实现报告

日期：2026-10-28（北京时间）

> 本文保留第一阶段 A 方案的原始实现与证据。后续已补充 v1.0.1 升级接入、启动防护及演练；当前状态以 [UPGRADE-REPORT.md](UPGRADE-REPORT.md) 为准。下文“未增加 handler”等描述仅指第一阶段，不能作为当前分支状态。

## 结论与审查范围

A 方案已实现，远程回归测试和 Linux/amd64 构建通过。
本轮交付的是可审查的代码与测试证据，不是可直接安装到主网的升级包。
未增加升级 handler、激活高度或历史验签规则分段；新规则在运行该候选二进制时立即生效。
正式部署必须另行完成协调升级设计及演练，不能仅替换 RPC 或滚动替换验证人。

未修改转账路由、IBC 状态、存储键、迁移逻辑或 use_aliasing=true 的功能。
没有合入 PQCAuth，也没有改浏览器或部署线上服务。本轮未使用钱包、未广播交易。

## 代码位置和基线

- 分支：`fix/v1.0.0-ibc-amino-compat`
- 基线标签：`v1.0.0`
- 基线提交：`1a2b30927a7799d4cd6890a3fb3fa80d25613fa2`
- 本地代码：`/Users/bun/.codex/worktrees/vota-ibc-amino-compat/doravota`
- 远程机器：`amaci-testnet-operator`
- 远程源码：`/root/vota-ibc-amino-compat-20261028/src`
- 远程原始证据：`/root/vota-ibc-amino-compat-20261028/evidence`
- 当前为未提交工作区修改，未 push、未发布 tag/release。不要仅用 `git diff` 查看已有文件：新增文件也在本次审查范围内。

原 v1.0.0 的 go.mod 虽然 require v11.2.0，但实际 replace 固定到
`github.com/cosmos/ibc-go/v11 v11.0.0-20260929073332-7b1838a13bc4`。
本次保留这一提交作为源代码基线，没有切换到最新 main 或正式 v11.2.0。

## 实现内容

### 1. 唯一的上游逻辑修改

文件：`third_party/ibc-go/proto/ibc/applications/transfer/v1/tx.proto`

```diff
-  bool use_aliasing = 10 [(amino.dont_omitempty) = true];
+  bool use_aliasing = 10;
```

SDK 0.55 的 Amino 签名处理器读取 Protobuf 描述信息。去掉该选项后：

- false 在 Amino 签名 JSON 中省略，与当前 Keplr 普通 IBC 消息的格式一致；
- true 仍输出并参与签名，不能被省略或篡改；
- 字段编号仍是 10，Protobuf 消息编码及 Direct 签名字节保持一致。

### 2. 真正重新生成描述信息

重新生成 `third_party/ibc-go/modules/apps/transfer/types/tx.pb.go`，不是手工改 Go JSON tag。
与基线相比，该文件只有 gzip FileDescriptorProto 字节数组不同。
描述信息测试会解压原版与新版，确认只有 use_aliasing 的 dont_omitempty 选项移除，其他描述完全相同。

远程使用官方 `ghcr.io/cosmos/proto-builder:0.18.1` 再生成并逐字节比较通过。
镜像 digest：`sha256:d7fb3bcfa865b3c4f85afd25af5be1fc9fafe77f7dab7313a726fb8cc5c5947a`。
`scripts/regenerate-ibc-amino.sh` 默认只比较，显式传 `--write` 才更新生成文件。

### 3. 可复核的依赖固定方式

根 go.mod 改为 `replace github.com/cosmos/ibc-go/v11 => ./third_party/ibc-go`。
根 CHANGELOG 的 Unreleased 节同步记录签名兼容边界与不得直接部署的限制。
本地目录是原 Go 模块分发包的快照，共 906 个文件、约 9.5 MiB。
仅省略上游 docs 目录及 PNG 图片，保留许可证、NOTICE、Go/proto 源码、测试和构建脚本。
上游独立 Go 子模块原本就不在该 Go 模块分发包内。

这是为了无需未发布的远程 fork、无需修改机器的共享 Go module cache 就能构建。
新增文件较多不代表大范围修改：审核重点是 [upstream.patch](upstream.patch)，其中仅含上述两个文件。
[upstream-manifest.json](upstream-manifest.json) 保存全部基线文件及两个修改文件的 SHA-256。
`scripts/verify-ibc-amino-snapshot.py` 检查文件集合、全部哈希和精确修改范围。
未来可在审查后改用固定提交的维护 fork；不能不经测试改回上游依赖。

## 验证环境与执行记录

用户要求远程后，确认本地无剩余测试/构建进程，全部验收测试在远程重新执行。
此前本地初步记录单独放在 `evidence/local-initial/`，不作为本报告的远程验收依据。

远程使用独立临时容器 `golang:1.26.5-bookworm`，Go 1.26.5、linux/amd64，
限制 4 CPU、10 GiB 内存，GOMAXPROCS=4、Go 构建并发 -p 2。
开始时约 100 GiB 可用磁盘、56 GiB 可用内存；结束时约 95 GiB 可用磁盘。
原验证人和 relayer 进程检查仍在运行；没有删除生产数据或停止服务。
测试容器使用 --rm，结束后自动移除，保留源码、日志和审查二进制。

| 检查 | 实际结果 | 证据 |
|---|---|---|
| 原版依赖的签名字节基线 | 4 个固定向量通过：Direct false/true、Amino true、bank Amino | [baseline-golden.log](evidence/remote/baseline-golden.log) |
| 原版依赖运行新兼容回归 | 按预期失败：false 未省略，钱包省略 false 的签名失败，旧显式 false 签名仍被原版接受 | [baseline-negative-control.log](evidence/remote/baseline-negative-control.log) |
| 修复后的专用回归 | 4 个顶层测试、13 个子用例通过 | [compatibility.log](evidence/remote/compatibility.log) |
| 根模块 go test ./... | 通过；未显式启用的可选模拟不计作已完成 | [root-tests.log](evidence/remote/root-tests.log) |
| 上游 transfer 全部子包 | 通过，含 keeper、types、simulation、v2 | [transfer-tests.log](evidence/remote/transfer-tests.log) |
| 根模块 go vet ./... | 通过 | [vet.log](evidence/remote/vet.log) |
| Linux/amd64，CGO_ENABLED=0 构建 | 通过 | [build.log](evidence/remote/build.log) |
| 源码快照哈希与范围检查 | 通过，906 文件中恰好两个补丁文件 | [source-integrity.log](evidence/remote/source-integrity.log) |
| 官方 proto-builder 再生成 | 通过，生成文件字节一致 | [proto-regeneration.log](evidence/remote/proto-regeneration.log) |
| 对固定基线的 buf breaking | 通过；不等于验签规则没有共识影响 | [proto-breaking.log](evidence/remote/proto-breaking.log) |

各 Go 命令的退出码见 [status.tsv](evidence/remote/status.tsv)。
baseline-negative-control 的退出码 1 是预期的负向对照，其他列出的 Go 检查退出码均为 0。
完整命令见 `scripts/test-ibc-amino-review.sh`。

### 专用回归具体覆盖

`app/ibc_amino_compat_test.go` 使用应用真实的 MakeEncodingConfig、TxConfig、TxEncoder/Decoder 和 CheckTx/AnteHandler：

1. 描述信息只移除指定选项，字段和其他定义不变。
2. Amino false 省略，true 保留；两者均能通过消息 ValidateBasic，并保持 Protobuf 往返值。
3. Direct false/true、Amino true、普通 bank Amino 的签名字节与原版固定向量逐字节一致。
4. 模拟 Keplr 格式（未包含 false）的签名通过真实 CheckTx。
5. 显式 true 的 Amino 签名通过真实 CheckTx。
6. 旧版显式 false 的 Amino 签名被拒绝，记录升级兼容边界。
7. true 未纳入签名则拒绝；签完 false 后把消息改为 true 也拒绝。
8. Direct false/true 均通过真实 CheckTx。

测试仅使用公开、确定性的测试私钥，没有读取生产钱包。
CheckTx 测试没有建立对端通道，因此证明的是验签和预检，不是实际 IBC 数据包到账。
上游 transfer keeper/v2 测试属于测试环境，不能替代真实主网或测试网对端验收。

### 遇到的问题及修正

- 早期 CheckTx 测试草稿曾直接签链端产生的 JSON，不能独立代表 Keplr 省略 false 的行为。
  已改为在钱包侧显式省略该字段，并在原依赖上确认该用例失败、修复依赖上通过。
- 官方 proto-builder 镜像没有 bash，首次再生成校验失败；保留
  [失败日志](evidence/remote/proto-regeneration-initial-failure.log)。
  再生成脚本改为 POSIX sh 后，使用同一官方镜像复测通过。
- buf breaking 首次直接比较两个挂载目录时遇到路径上下文错误；改为分别构建同一 proto
  的描述镜像再比较，通过。初始错误保留在 `evidence/remote/proto-breaking-initial-failure.log`。

## 构建产物

- 远程二进制：`/root/vota-ibc-amino-compat-20261028/src/build/dorad-amino-review`
- 注入版本：`v1.0.1-amino-review`，仅用于区分审查产物，不代表已决定或发布 v1.0.1。
- 构建提交标识明确为 `v1.0.0-plus-uncommitted-amino-fix`，不冒充已提交的 release。
- SHA-256：`3bd15aec3cda83598f902ae9f856662265b1abbb9b8eeb9dd4afe4150632035c`
- 构建依赖证据：[binary-modules.txt](evidence/remote/binary-modules.txt)。

VERSION 和已有 v1.0.0 升级配置保持基线，本轮没有创建新升级计划。
不要把普通默认构建标识或上述审查版本当作生产发布信息。

## 兼容性边界与未完成项

- 这是共识验签规则变更，不是仅 RPC 展示修正。所有参与共识的节点必须协调切换。
- 旧 CLI 或其他客户端若仍签显式 false，升级后必须更新并重新签名。
  升级前签好但尚未执行的这类交易也不能保证升级后可用。
- 旧浏览器“强行补 false”的补丁与本方案冲突，不应上线。
- 没有禁止 true，也未删除字段。未来上游更新必须保持当前决定的签名契约。
- 尚未实现：升级 handler/激活边界、历史重放策略、正式版本号与发布流程。
- 尚未完成：真实 Keplr 软件钱包、Keplr+Ledger 真机、多验证人升级高度前后演练、真实快照、
  Osmosis/Cosmos Hub 双向 IBC 及退款验收、Skip Swap 完整路由验证。
- 未运行上游完整仓库的 make format/lint/test-unit/proto-all 套件及独立 simapp/e2e 模块。
  本轮采用固定模块分发包、根模块测试/vet/build、transfer 子包测试、定向 proto 再生成及描述信息比较。
  未运行 ARM64、race 或硬件钱包测试，不声称它们通过。

## 建议 Claude 审查顺序

1. 看 `upstream.patch` 和 `go.mod`，确认基线与两文件修改范围。
2. 检查源码清单和再生成脚本，确认构建实际使用修改后的描述信息。
3. 看回归测试和远程负向对照，尤其是旧显式 false 签名被拒绝这一边界。
4. 核查 Direct/true 固定向量、实际 CheckTx 验签结果及字段篡改测试。
5. 确认本分支只交付核心修复；在推进生产前单独审查激活高度和历史重放设计。
