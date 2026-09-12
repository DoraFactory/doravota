# SDK 0.53 桥接版修复记录（2026-09-11）

基于 sdk-053-bridge / 6d03e3b 的本地修改，未提交或推送。此次处理前次审查中的四项代码/构建/测试问题，不代表主网升级已放行。

## 修改

1. 空 IAVL 根的只读兼容视图始终启用，不再依赖 upgrade-info.json 存在或保持桥接计划名。只恢复数据库里确实存在的空值，缺失键仍缺失，损坏值不被改写。桥接边界原有旧根验证保留。另修复二进制版本号包含 `/` 字节时的键识别错误。
2. ICA controller 改为单层 NewIBCMiddleware，保留外部 callbacks 层及 ICS4 wrapper 接线。
3. 发布流程从 go.mod 读取 Go 版本，在对应架构的 Alpine/musl 容器构建。WasmVM 版本与模块依赖核对，两个原生静态库使用已对照官方 v3.0.7 checksums.txt 的固定 SHA-256；下载失败或哈希不符直接失败。发布步骤增加产物 version/init 冒烟检查和静态加载器检查。原始 AMD/ARM 产物命名保持兼容。
4. 模拟应用使用独立 home/cache 并注册 VM Cleanup；同一个 seed 的重复确定性测试使用相同 chain ID；随机 seed 来源改为命令行 Seed 参数，便于复现。发布流程显式执行三个模拟并检查三个测试均为 PASS，避免 Go 命令成功但模拟 SKIP 被误认为通过。
5. 修正前次保存的独立链上证明验证工具的构建标签，防止依赖旧 SDK 的证据工具被桥接版本 go test ./... 自动编译。

## 本地验证

- 空树专项测试通过：无计划文件、替换计划、真实 GoLevelDB 空树、连续提交后重新加载、不伪造缺失根、损坏根报错、包含分隔符字节的版本号。
- 普通全仓库测试通过（最终日志见同目录 fixes-2026-09-11/full-tests.log）。
- 显式模拟：Seed=42、NumBlocks=10、BlockSize=5、Commit=true。TestAppStateDeterminism、TestAppImportExport、TestAppSimulationAfterImport 均明确 PASS。确定性测试执行三个派生 seed，每个重复五次。
- 扩大至 100 块的随机模拟遇到上游“empty validator set”跳过条件，不计为 100 块验证通过；不是本次已证明的共识分歧，也不能代替长时间验证。
- 本机 dorad 构建成功，version 输出 sdk-v0.53-bridge。
- 发布脚本 bash 语法、workflow YAML 解析和 git diff --check 通过。

## 仍需验证

本机没有可用 Docker 服务，Linux AMD64/ARM64 容器构建和产物冒烟流程尚未实际执行，必须在 CI 完成。构建镜像使用明确 Go 版本标签，但未锁定镜像 digest。

ICA 修改通过编译和模拟，不意味着实际旧 ICA 握手/回调已覆盖。主网快照升级、升级后实际进程重启、旧通道（尤其 channel-16 ICS-721）、源版本/费用移除前置保护及故障恢复演练仍按升级方案推进。空树测试中的连续重新加载不等同于完整节点跨进程主网恢复测试。

本次没有运行链上迁移、修改主网或广播交易。
