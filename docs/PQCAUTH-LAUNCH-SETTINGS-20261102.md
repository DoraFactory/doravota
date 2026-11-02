# PQCAuth 首版启动设置与验证记录

日期：2026-11-02。基线：`26d15bb9adabca372cfff6e11fa8cf4e8ed98bb6`。
分支：`feature/pqcauth-sdk-keyring`。按用户确认保持小范围修改，不新增调度机制。

## 确认的设置

| 项目 | 首版设置 |
| --- | --- |
| 恢复等待期 | 107,520 块，按 5.62–5.63 秒/块估算约 7 天 |
| 单次紧急暂停/续期上限 | 46,080 块，约 72 小时 |
| 治理安全延迟 | 保持 17,280 块，约 27 小时 |
| 注册 | 仅 OPEN；拒绝 CLOSED、FRESH 和非零 cutoff |
| 全局 REQUIRED | 继续禁用；OPTIONAL 默认值与 REQUIRED_FOR_REGISTERED 保持原规则 |
| 授权/证明验签 gas | 保持各 750 |
| 每笔/每块验签额度 | 保持 16 / 400，未自动提高到 4,096 |

时间是区块数的估算，不是墙钟保证。未来改变出块速度时应同步复核三个延迟。
OPEN 不代表取消应急措施：PAUSE_NEW_KEYS 和 PAUSE_PQC_TRANSACTIONS 均保留，
显式 emergency_only、同块保护、到期和普通限制安全延迟均未改动。
恢复仍需经典签名；旧签名密钥在恢复生效前仍有效，恢复不是冻结账户或被盗密钥的万能补救。
应有恢复通知与取消指引；暂停到期自动解除，运维须在到期前完成修补或合法续期。

## 代码范围与兼容性

- `types/params.go` 修改两个默认延迟，并在共享参数校验拒绝非 OPEN 模式及非零 cutoff。
  覆盖 active、pending、genesis 和治理入口；`registration.go` 额外拒绝注入的非零 cutoff。
- 保留 protobuf 字段和枚举编号，没有把 CLOSED/FRESH 静默映射为 OPEN。
  历史 UNSPECIFIED 零值仍按原规则兼容为 OPEN。
- 显式存储的合法旧延迟不会被默认值变化自动重写；RecoveryDelayBlocks=0 的原有
  fallback 规则现在使用 107,520。旧实验链的 CLOSED/cutoff/REQUIRED 状态不支持直接热替换，
  需要单独审查迁移。受支持的生产入口仍是未初始化 PQCAuth 的 v1.0.1 状态。
- 真实应用升级回归断言升级后写入 OPEN、零 cutoff 和三个新/保留延迟。
- 原 CLOSED/cutoff 成功路径改为拒绝且不写状态的回归。紧急调度测试改用仍受支持的
  预算缩减/REQUIRED_FOR_REGISTERED 作为普通待生效限制，保留取消、续期、同块顺序、
  到期、导出导入和不提前激活的断言；没有为了禁用配置而移除这些调度安全检查。
- 补入 Claude ROUND9 的真实签名 stale recovery 回归：SetProtection 与旧 policy 签名的
  RecoverKey 均先通过 New；前者提交后，首次 Recheck 因 pending policy 拒绝后者；
  强制送到 FinalizeBlock 也拒绝，余额、sequence、policy 不变。后续人工重复 Recheck
  只用于说明信任边界，不冒充真实 mempool 会保留已被剔除的交易。
- `VerifyKeyProof` 注释明确：策略变化至少 pending 一块且每次提交后执行 recheck。
  若改变该前提或开启 unordered，必须重新审查。没有改密码学、签名域或 gas。

## 本机实际验证

使用 Go 1.26.10、本机已有离线依赖缓存，GOMAXPROCS=2、GOFLAGS=-p=2。
按云环境资源隔离要求，四验证人演练另用 nice 10、CPU 2/3 affinity 和独立 localhost 端口；
未操作现有公共节点、钱包或链上参数。

| 检查 | 结果 |
| --- | --- |
| `scripts/test-release-candidate.sh`，最终源码重跑 | 14 个包、831 个测试/子测试通过事件，0 失败 |
| 三项显式链模拟 | 全部通过 |
| 发布工具 Python 测试 / 固定 IBC 源码检查 | 7 项 / 906 个文件通过 |
| `go vet ./...`、`go build ./cmd/dorad` | 通过 |
| app/keeper/types 新增重点回归与普通取消回归，`-race` | 通过 |
| 四验证人隔离生命周期，`--rounds 8` | PASS；132 笔 code 0，6 笔预期拒绝 |
| 历史清理及重启后的四节点一致性 | 高度 127，四节点 AppHash 相同 |

最终一致的 AppHash：
`C03A4BF764BF997836F506098743E32CB642585EF57A6997077549E46BC6EBF7`。

演练二进制：`/tmp/pqcauth-launch-settings.h4Fw1h/dorad`。
SHA-256：`ee3ce51cafccbc79697a577b502c821c7e88e932f6e39b7402b8011c3c0c91d6`。
这是工作树开发构建，不是已冻结的 v1.1.0 发布产物。

原始证据（本机临时文件，不随 Git 提交）：

- `/tmp/pqcauth-launch-settings.h4Fw1h/gate-final.log`
- `/tmp/pqcauth-launch-settings.h4Fw1h/gate-final/unit.jsonl`
- `/tmp/pqcauth-launch-settings.h4Fw1h/gate-final/simulations.jsonl`
- `/tmp/pqcauth-launch-settings.h4Fw1h/vet.log`
- `/tmp/pqcauth-launch-settings.h4Fw1h/race.log`
- `/tmp/pqcauth-launch-settings.h4Fw1h/four-validator/evidence/result.json`
- `/tmp/pqcauth-launch-settings.h4Fw1h/four-validator/evidence/history-restart-agreement.json`
- `/tmp/pqcauth-launch-settings.h4Fw1h/four-validator/evidence/test-only-params.json`

演练为加速功能验证使用 recovery_delay_blocks=12、max_pqc_signers=4、
每笔/块预算=4；750 gas、OPEN、46,080 紧急上限仍在测试配置中。
没有等待真实 7 天，也没有把这个小预算演练称为默认 400 或 5,000 笔容量验收。
107,520 恢复边界、46,080 暂停到期与启动不可变性另有自动化高度边界测试。

## 未完成与发布边界

5,000 笔七 signer 四验证人压测、400/1,000/2,000/4,096 对照、最低目标硬件验证仍未执行。
不能据本轮功能结果宣称额度公平性、满池 recheck 或公网延迟已验收。
本轮没有重新跑真实主网快照升级、公共测试网/IBC 或物理钱包验收。
不改 VERSION、不打标签、不创建 Release、不部署公共网络。
完成剩余容量与最终产物验收后再决定冻结；GitHub CI 状态以本次提交关联的运行结果为准。
