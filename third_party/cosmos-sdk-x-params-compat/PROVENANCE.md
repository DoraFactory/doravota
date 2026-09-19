# 来源与维护边界

来源：Cosmos SDK v0.53.6，commit `82fcb05cebaea6504f088ac590017d180c6da149`，按 Go module 校验和固定（见主项目 go.sum 的旧基线及 sdk-055-evidence/baseline-go.sum）。Apache-2.0；LICENSE 随包保留。维护责任：Dora Vota；具体发布评审负责人待指定。

本兼容包不代表上游 SDK 0.55 对旧模块的维护承诺。安全修复需逐项审核和移植。

types/paramset.go 是 Wasmd 历史参数声明的最小兼容层，没有 Keeper 或存储。types/proposal 的五个文件直接复制自 SDK v0.53.6，原始内容未修改，只用于保留历史 ParameterChangeProposal 的 Amino/Any 解码。执行入口返回明确错误，不运行旧参数修改。退出条件：Wasmd 移除历史类型依赖；历史提案解码须继续保留到明确的数据兼容边界。
