# PQCAuth 治理更新意图修复记录

日期：2026-11-01。基线：`23dfcf89cc8ebe356b2c87bf3147a1c5bf145706`。分支：`feature/pqcauth-sdk-keyring`。本次解决 GOV-02：暂停有效期间，取消普通待生效限制被误判为紧急续期。750 gas 默认价、签名与恢复认证、16/400 次数预算均不改变。

## 复现和根因

在固定基线上，通过临时 Go overlay 运行真实 Keeper、MsgServer、protobuf codec 和挂载的 IAVL 内存存储，6 个场景中，NORMAL 两个对照正确取消；两种暂停 × 是否排队 CLOSED 的四个场景均返回成功，却仍在 H=110 激活 REQUIRED/CLOSED。测试的取消期望明确失败，而非把观察到错误行为的 PASS 当作修复证据。

基线日志：`/tmp/pqcauth-gov02-review.XfWf4n/result.log`。该测试不执行链上治理投票或密码学路径；`setupKeeper` 的 account keeper 为仓库测试替身，调度、参数校验、编码和存储使用真实实现。默认验签价为 750。

原因是旧 `isOverlappingEmergencyUpdate` 依据参数相似度和“模式不是 NORMAL”推断意图。同一个完整请求既可能表示取消普通计划，也可能表示只续期暂停，无法安全区分。此次删除该自动分类，不用修改无关参数绕过它。

## 显式请求语义

给现有 `MsgUpdateParams` 增加 `bool emergency_only = 3`；未设置等同 false，不新增消息服务或持久化字段。

| 请求 | 语义 | 对普通计划的影响 |
| --- | --- | --- |
| `emergency_only` 省略或 false，恢复当前普通参数并保持当前紧急模式 | 完整更新，取消可取消的 pending bundle | 清除普通计划，保留当前暂停及原到期高度；回执 activation 为 0 |
| false，提交新的普通参数 | 完整替换 | 仍按限制性变化计算安全延迟，numeric cutoff 约束不变 |
| true，暂停、解除暂停或重复同一暂停模式 | 仅调整紧急状态；重复同一暂停明确表示续期 | H+1 生效，保留原普通字段和原 activation |

完整更新保持当前暂停时，服务器将当前到期高度带入比较和保存，而不是把请求中按规定清空的到期字段当成续期。普通替换若在暂停到期之后才生效，其未来紧急组件为 NORMAL，不延长或重新打开暂停。

完整更新仍允许明确改变紧急模式，它按完整 bundle 的延迟和替换语义处理；这不是 emergency-only 快速路径。需要保持其他计划并快速暂停时，必须使用 true。

## 保留的安全约束

- authority 和所有原有参数/不可变字段检查在分流之前执行。
- true 请求的非紧急字段必须完整匹配 active 或完整匹配 pending；不允许夹带 gas、预算、注册模式、截止高度或其他任意新值。
- true 携带 active cutoff=0 只用作比较基准，原 pending 非零 cutoff 保留；false 企图取消或更改已承诺 cutoff 仍拒绝。
- true 不提前、取消或后移原普通限制。普通明确替换则按完整更新规则重新计算自己的生效高度。
- 显式独立紧急动作尚未到 H+1 时，完整参数请求仍明确报错；H+1 后重新查询即可提交普通取消或替换。
- 当前暂停的普通取消不续期。显式续期重新从 H+1 计算受限期限，普通请求不能自行指定 expiry。
- 未改变 GOV-01 的独立生效、到期顺序或 OBS-REC-01 的认证要求。

## 响应和客户端

`MsgUpdateParamsResponse` 新增 `Params resulting_params = 2`，返回实际保存的完整状态，包括普通 pending、高度、独立紧急 pending 和到期信息。客户端应检查它或查询链上状态，不能只把成功或单一 `activation_height` 当作普通计划已取消的证明。

治理 JSON 中 `emergency_only` 是消息顶层字段，与 `authority`、`params` 并列，不放入 Params。构造参数请求时仍须清空查询状态中的 `pending`、`pending_activation_height`、`pending_emergency`、`emergency_expires_height`，保持不可变字段，按目标意图选择 active 或 pending 的普通字段。不能把完整回执直接当下一笔参数请求。

没有增加专用交互式 CLI；现有通用治理消息 JSON 使用更新后的 protobuf codec 表达该布尔字段。测试覆盖请求 protobuf/JSON 往返、旧消息缺省 false、完整/紧急请求签名字节不同，以及响应中两个调度的 protobuf/JSON 往返。

旧客户端若只会发送缺省字段，得到完整更新语义，不再自动获得“保留普通计划”的紧急快捷行为。前一候选里按自动识别构造的治理提案必须重审；需要快速保留计划的提案显式补 true。旧二进制不理解新字段，不能在旧节点上试用该意图或让新旧程序混跑。

## 文件和回归

- `proto/doravota/pqcauth/v1/tx.proto`、`x/pqcauth/types/tx.pb.go`：请求意图与实际状态响应。使用固定 gogoproto v1.7.2 的 gocosmos 插件重新生成，未手改 wire 编解码。
- `keeper/emergency_schedule.go`：只校验显式请求的非紧急字段，不再猜测意图；无其他计划时也支持显式紧急操作。
- `keeper/msg_server.go`：按消息字段分流，完整更新保持当前暂停的 expiry，所有成功分支返回实际状态。
- `keeper/emergency_intent_test.go`：6 个原始取消回归、两种显式续期及其后取消、夹带字段拒绝、不可逆截止、普通替换及到期边界。
- `types/emergency_intent_test.go`：意图和响应编码、签名字节绑定。
- 原 GOV-01 的 72 个组合和导出导入测试只调整为显式 true，请求成功、原截止和原激活高度等安全断言保留。
- `scripts/test-release-candidate.sh`：新增关键用例必须执行，不允许通过未匹配或 skip 冒充通过。

Go 1.26.10，`GOMAXPROCS=2`、`GOFLAGS=-p=2`：最终发布门禁通过，14 个测试包、741 个测试及子测试通过事件，无失败。默认跳过的三项链模拟另行启用后全部通过；7 项发布工具 Python 测试和 906 个固定 IBC 源文件检查通过。`go vet ./...` 和本地 `go build ./cmd/dorad` 通过。

日志与复跑：

- `/tmp/pqcauth-gov02-gate-final.log`：最终门禁摘要。
- `/tmp/pqcauth-gov02-gate-final/unit.jsonl`：741 个通过事件及关键用例。
- `/tmp/pqcauth-gov02-gate-final/simulations.jsonl`：3 项显式链模拟。
- `/tmp/pqcauth-gov02-vet.log`、`/tmp/pqcauth-gov02-build.log`：成功命令的空日志。
- `/tmp/pqcauth-gov02-first.log`：初次实现后尚未把旧紧急用例改为显式 true 时的失败记录，非通过证据。

仓库根目录复跑：

```sh
export GOTOOLCHAIN=go1.26.10
export GOMODCACHE=/tmp/doravota-go-mod
export GOCACHE=/tmp/doravota-go-build
export GOMAXPROCS=2
export GOFLAGS=-p=2
PYTHONDONTWRITEBYTECODE=1 RESULTS_DIR=/tmp/pqcauth-gov02-rerun bash scripts/test-release-candidate.sh
go vet ./...
```

本机实际离线执行使用缓存工具链的绝对路径、`GOTOOLCHAIN=local`、`GOPROXY=off`；缓存中的实际 Go 版本为 1.26.10，没有降低仓库要求。初次工具链启动遇到关闭校验数据库时的自动工具链验证错误后，改用该缓存编译器直接执行；未改网络策略或依赖版本。

## 复审和发布边界

审计范围为 `23dfcf89cc8ebe356b2c87bf3147a1c5bf145706..HEAD`，重点复核默认完整更新与显式紧急更新、同块拒绝、原暂停到期不变、numeric cutoff 不可逆，以及响应与保存状态一致性。

本轮不修改 750 gas、共享预算、密码学或节点部署。741 个通过事件是本轮本地门禁结果，不替代真实治理投票网络、最终产物的多验证人/快照中断恢复或最低硬件持续负载验收。共享 400 次额度竞争和 admission 流量仍是已记录的容量边界。本次属于共识行为调整，独立复审后再冻结正式候选；没有发布标签或公共链操作。
