# PQCAuth 第四轮修复与复审交接

日期：2026-11-01 UTC。分支：`feature/pqcauth-sdk-keyring`。交付对象：Claude 及独立审计者。

比较基线：`c2927448af4e41ed811822d5a3374f1466a4672d`。实现提交：`b26badc38c85d6785789ce45a4fe130095c3a24e`；构建冒烟端口隔离提交：`e10e9851ce144e264c046fc9515684f642e9a545`。本轮最终交接提交只更新文档。作者、提交者均为 `vegebuncsj <csj1071285741@gmail.com>`。

本轮修复共享复审的 PQC-04-R1、Claude 的选块前缀阻塞问题，并实际升级 DEP-01 所列工具链和依赖。代码可交复审，但不是正式发布批准。没有推送版本标签、创建 Release、升级公共链或修改现有运行节点。

## 选块依赖修复

位置：`app/proposal.go`。

- 超过每笔或剩余区块 PQC 预算时，跳过该候选并把实际 SDK signer 放入局部阻塞集合，不再立即返回整个前缀。
- 候选与阻塞集合相交时跳过，并把它的全部 signer 加入集合。这样 A 被跳过、随后 A+B 被跳过时，B 的下一笔也会被跳过；与这些账户无关的交易继续参与选择。
- SDK `GetSigners()` 从消息及独立 fee payer 推导签名者。不能改用 PQC extension 中自行声明的地址；fee granter 不因代付授权自动成为 signer。
- 当前治理限额下 Inspect 失败时，Prepare 在绝对上限 256 KiB / 32 entries 内再检查一次。只有绝对结构/公钥检查通过，才将其当作参数限额导致的遗漏并传播依赖。两次检查均不写入 tracker；被跳过的候选绝不提交发现的公钥。
- ProcessProposal 始终使用提案高度的真实参数，检查失败或预算超限直接 REJECT，不执行放宽限额的重试。区块硬预算没有增大，经典/PQC 验签没有删除。

这不是完整 Ante 重放，也不是所有跨账户消息依赖的分析器。比如被省略的充值影响另一个账户的余额，仍可能导致后续消息失败。SDK 本身的 gas/byte 选择策略仍然适用；这次修复只移除 PQC 层新增的整体截断。绝对结构预检不是密码学认证，不保证任意恶意 proposer 提供的伪造候选合法。无法据此承诺所有 mempool 排序下的公平性。

原生 ML-DSA 验签 gas floor 保持 SDK 的 750；单笔总费用还包含交易大小和状态执行。没有把审查中的“每天约 3,000 DORA”估算写成实测结论，也没有擅自改变全网收费参数。

## 真实签名回归

新增 `app/pqcauth_selection_test.go`，不是占位签名或抽取函数替身。

1. `TestPQCAuthProposalBudgetKeepsIndependentTransactions`：原生 ML-DSA 候选依次耗尽预算；后续普通独立交易仍执行。分别覆盖共同消息 signer、独立手续费付款人及传递阻塞。所有候选先依次通过真实 CheckTx。
2. `TestPQCAuthProposalParameterActivationDependencies`：三个已充值并实际注册的账户共同签名，在 H-1 依次通过 CheckTx；治理消息服务器安排参数在 H 激活。覆盖仅 signer 限额收紧、同时 byte/signer 限额收紧，以及第三个 signer 为共同发送者或独立 payer 的四种组合。旧高度选择全部候选，新高度拒绝未过滤提案；Prepare 只保留无关转账，Process/Finalize/Commit 成功。随后空块和状态审计正常，被省略账户可用原序号重签成功。此处是内存真实应用测试，不是公共链治理提案。
3. `TestPQCAuthProposalParameterLimitDoesNotPoisonKeys`：候选先被治理限额拒绝，但绝对上限重试发现公钥不匹配；不得污染 signer 阻塞集合或已知公钥缓存，后续合法原生交易仍执行。保留原公钥投毒回归。

测试辅助函数完整生成 DIRECT 经典/原生签名和 PQC 授权，显式控制将来的 sequence。参数激活测试的 byte 场景同时降低 signer 上限，以保持参数组合合法；不是声称合法签名必然能单独触发任意 byte 下限。

旧行为对照：仅用 Go overlay 将 `app/proposal.go` 替换为 `c292744` 原文件，新增前两项测试的六个子场景全部按预期失败。其余代码及补丁依赖不变；这证明回归能区分旧选块行为，不是旧提交全仓测试。

## 工具链与依赖补丁

- `go.mod` 和 Dockerfile：Go 1.26.5 → 1.26.10；实际使用下载的 Go 1.26.10 编译和测试。CI 根据 go.mod 选择同版本。
- x/net：0.58.0 → 0.62.0。0.60.0 已修复原 HTTP/2 问题，但当前数据库另有 10 月 27 日 HTML 问题，因此最终使用 0.62.0。
- OTel log、SDK log、OTLP log exporters、stdout log：0.20.0 → 0.21.0；核心/trace/metric 和关联 exporters 更新到匹配的 1.45.0。
- 实际编译发现旧 otelslog 不兼容新的 log API，同步升级 `contrib/bridges/otelslog` 至 0.20.0、`contrib/otelconf` 至 0.25.0 及所需传递依赖；没有手工伪造 go.sum。
- 新扫描命中的 Pion DTLS/STUN 传递依赖分别从 3.1.2 更新至 3.1.4 / 3.1.5，transport/v4 随之更新至 4.0.2。其余 MVS 变化以 go.mod/go.sum diff 为准；go mod tidy 清除了旧的未使用 checksum。
- 构建脚本新增实际二进制的 `go version -m` 记录，CI/发布产物列表保留 `.buildinfo.txt`，不再只依据 workflow 声明的 Go 版本判断实际产物。
- 构建冒烟测试关闭不需要的 API/gRPC 服务，并让 ABCI 绑定回环临时端口，避免与现有节点占用端口冲突。没有修改节点启动默认行为。

官方依据：[Go 安全版本](https://go.dev/doc/devel/release)、[HTTP/2](https://pkg.go.dev/vuln/GO-2026-6617)、[x/net HTML 分配](https://pkg.go.dev/vuln/GO-2026-6860)、[x/net HTML 渲染](https://pkg.go.dev/vuln/GO-2026-6866)、[OTel TLS](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-w34q-cm8f-9c5x)、[OTel CPU](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-hjf4-fphr-2h65)、[STUN](https://pkg.go.dev/vuln/GO-2026-6163)、[DTLS](https://pkg.go.dev/vuln/GO-2026-6165)。

## 已完成验证及证据

环境：Go 1.26.10、GOMAXPROCS=2、GOFLAGS=-p=2、GOMEMLIMIT=4GiB。后者是软目标而非硬上限。源码 symbol 扫描实际约 94 秒，峰值 RSS 7,643,420 KiB；正式构建另外使用 systemd scope 的 2 核、8 GiB、禁用 swap 硬限制。没有停止或重启本机已有节点。

- 最终门禁：14 个包、607 个通过测试/子测试事件；默认跳过的 3 项模拟另行显式启用，全部通过；7 项 Python 测试、906 个固定 IBC 源文件检查通过。
- `go vet ./...` 通过；`go mod verify` 返回 all modules verified。
- wire fuzz 在新工具链/依赖下运行 20 秒，通过 101,106 次执行；不等于长期负载或进程 OOM 验收。
- `govulncheck v1.9.0` 实际完成全仓 package 和 source symbol 扫描，数据库更新时间为 2026-10-27。JSON 输出的进程 exit 0 不是“零漏洞”的保证；残余项如下。
- 另以产物相同的 `CGO_ENABLED=0`、`-tags=netgo,osusergo` 完成全仓 source symbol 扫描，约 92 秒、峰值 RSS 7,599,664 KiB；采用 2 核/10 GiB scope 硬限制，残余项与普通 source 扫描一致。

绝对证据路径：

```text
/tmp/pqcauth-round4-gate-final.log
/tmp/pqcauth-round4-gate-final/unit.jsonl
/tmp/pqcauth-round4-gate-final/simulations.jsonl
/tmp/pqcauth-round4-old-behavior.log
/tmp/pqcauth-round4-old-overlay.json
/tmp/pqcauth-round4-vet.log
/tmp/pqcauth-round4-mod-verify.log
/tmp/pqcauth-round4-fuzz.log
/tmp/pqcauth-round4-vuln-package-final.json
/tmp/pqcauth-round4-vuln-symbol.json
/tmp/pqcauth-round4-vuln-symbol.stderr
/tmp/pqcauth-round4-build-final.log
/tmp/pqcauth-round4-vuln-binary.json
/tmp/pqcauth-round4-vuln-release-source.json
/tmp/pqcauth-round4-vuln-release-source.stderr
/tmp/pqcauth-round4-lifecycle.log
```

早期日志 `pqcauth-round4-selection.log` 是 OTel 组件未同步时的编译失败。首次 `pqcauth-round4-gate.log` 在执行中更新了脚本，模拟阶段读取发生 EOF；脚本语法复核及稳定文件重跑后的 `gate-final` 才是最终门禁，不混用这些结果。

首次构建完成编译，但冒烟测试与本机既有 gRPC 的 9090 端口冲突；`build-final` 是隔离端口后完整通过的构建。未停止既有服务。

复跑门禁时在仓库根目录设置 `GOTOOLCHAIN=go1.26.10 GOMAXPROCS=2 GOMEMLIMIT=4GiB GOFLAGS=-p=2`，执行 `bash scripts/test-release-candidate.sh`、`go vet ./...`、`go mod verify`。本机复用 `GOCACHE=/tmp/doravota-go-build GOMODCACHE=/tmp/doravota-go-mod`；新环境需要下载依赖。

## 实际构建产物

按发布构建脚本生成的 Linux AMD64 开发候选，内嵌提交为 `e10e9851ce144e264c046fc9515684f642e9a545`，版本仍为 `v1.1.0-dev`，不是正式 v1.1.0 发布。

- 二进制：`/root/Documents/Codex/2026-10-31/new-chat/Doravota/release/dorad-v1.1.0-dev-linux-amd64`
- 二进制 SHA-256：`03ed39d02984f9872b968a99ad6b482ede6b37296a043b73695d8d07309d17d9`
- 打包文件：同目录 `dorad-v1.1.0-dev-linux-amd64.tar.gz`
- 打包文件 SHA-256：`8e28ef5170b5240e12656b1a508a78fa38972d5907b98e96e49613b32232cb0f`
- 实际 build info：同目录 `dorad-v1.1.0-dev-linux-amd64.buildinfo.txt`，确认 Go 1.26.10、x/net 0.62.0、OTel log 0.21.0、DTLS 3.1.4、STUN 3.1.5。

已将压缩包中的二进制流式解包计算 SHA-256，与上述裸二进制一致。产物保留在本机，不提交 Git，不创建 Release。构建脚本的静态链接、版本、CLI 生成及真实启动冒烟全部通过。ARM64 和 Docker 镜像构建需观察推送后 CI，不能提前列为本机通过。

对实际 stripped 二进制也执行了 `govulncheck -mode=binary`。v1.9.0 对这类缺少符号表的产物采用 module 级保守回退，输出包含通配符和不可据此证实存在的 package/symbol；因此不能把这些输出当作真实调用链。实际构建信息、source symbol 扫描及逐条代码核查必须一起看。

## 同一产物的四验证人演练

使用上述 SHA-256 对应的二进制执行 `scripts/rehearse-pqcauth-lifecycle.py --rounds 4`，限制整个进程组最多 2 核、7 GiB 内存、禁用 swap。节点仅绑定回环地址，使用独立合成 genesis 和测试密钥，不连接公共链。

结果为 PASS：98 条记录，其中 92 笔交易 code 0，6 笔按预期拒绝。覆盖注册、离线签名、两种密钥轮换、恢复/取消恢复、经典/原生/混合交易负载、委托行为、历史密钥处理和重启。最终记录的状态高度为 110，四节点 AppHash 都为 `79A5AC4D28092E2B5E9C73C474AC4924877D33DCEB1CF6AF6C90852886FA5412`。这是本轮新产物的新演练，不是复用历史 92 笔结果。

公开证据目录：`/tmp/pqcauth-round4-rehearsal.j0aGGt/network/evidence/`，重点文件 `result.json`、`binary.json`、`history-restart-agreement.json`。节点已全部由脚本停止；只交付 evidence，不传播旁边的 node home/keyring。演练不包含本轮主网快照迁移、公共 IBC 对手链或物理 Ledger。

## 扫描残余项与上线边界

- GO-2023-1821 / GO-2023-1881：SDK x/crisis 的 module 级告警，当前扫描没有对应 imported package 或符号调用命中。
- GO-2025-3442：CometBFT module 版本范围告警，扫描没有对应 package/symbol 命中。当前 v0.40.0 的 `blocksync/pool.go` 已有 base>height 及 peer 高度回退拒绝代码；本轮没有为此更换共识引擎，也没有执行恶意 blocksync 网络试验。
- **GO-2026-5932 仍未关闭**：完整 source 扫描有 10 条符号记录，来自 SDK 加密密钥导入/导出调用的 `openpgp/armor` 和 `errors`（包括初始化）。[上游公告](https://pkg.go.dev/vuln/GO-2026-5932) 将该包所有版本标为弃用且无已知修复版。本轮没有 fork SDK 或替换密钥备份编码，不能宣称依赖扫描零命中。这不是已确认的 PQCAuth 签名绕过，但密钥文件处理的兼容替换/风险接受需要单独审计。

原 DEP-01 指定的补丁版本已落实，不能据此把所有依赖风险标成关闭。主网 v1.0.1 是否另发补丁、能否滚动升级，需要核实真实二进制和服务暴露，并做新旧执行兼容验证；本分支提交不构成主网部署授权。

本轮没有调整签名域、算法、FRESH 注册禁用决定、委托安全范围或升级 store 迁移。审计通过后仍需对最终产物做受支持主网快照升级、中断恢复、最低物理硬件和公共测试网生命周期/IBC 验收。历史快照演练不能替代新依赖产物的验收。
