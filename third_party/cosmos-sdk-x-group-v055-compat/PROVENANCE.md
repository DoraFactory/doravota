# 来源与维护边界

来源：Cosmos SDK v0.53.6，commit `82fcb05cebaea6504f088ac590017d180c6da149`，按 Go module 校验和固定（见主项目 go.sum 的旧基线及 sdk-055-evidence/baseline-go.sum）。Apache-2.0；LICENSE 随包保留。维护责任：Dora Vota；具体发布评审负责人待指定。

本兼容包不代表上游 SDK 0.55 对旧模块的维护承诺。安全修复需逐项审核和移植。

group 保留 module name、protobuf 类型和字段号、store layout、consensus version 2。当前复用 pqc-auth 固定提交 a291420502485931e5e4662e65e4d4fda9892b01 的兼容适配；本轮未整合该分支。上游 _test.go / 测试辅助文件未随裁剪副本纳入，不能将主项目测试视为完整上游覆盖；发布前必须补齐 group 业务和边界验证。退出条件：采用经评审、保持既有状态兼容的受维护实现。

源码差异审核：除 import 迁移外，还移除了 SDK 0.55 已无对应 group API 的 depinject provider，裁剪 simsx 的 WeightedOperationsX 及配套工厂，保留旧 WeightedOperations 所需的 SharedState（atomic group ID）。这些属于应用接线/模拟器适配，不能笼统称为仅改 import；未改 Keeper 业务、key layout 或 protobuf 定义。完整修改及遗漏文件见 upstream-diff.patch / upstream-files.json。
