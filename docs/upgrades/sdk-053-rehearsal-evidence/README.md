# 本轮升级证据索引

仅包含候选源码哈希、公开交易、状态摘要和测试日志，不包含私钥或助记词。

- `final-binary.sha256`、`final-version.txt`：实际运行包。
- `candidate-source-manifest.json`、`source-match-verified.json`：未提交源码身份，已核对远端文件。
- `final-four-node-consistency.json`：最终四节点同高度一致性。
- `boundary-stores.summary.json`、`semantic-checks.json`：H−1/H 原始存储与语义核对。
- `final-migration-replay.json`、`migration-crash-recovery.json`：最终包升级重放与中断恢复。
- `missing-plan-cold-cache-restart.json`、`all-four-restarted.json`、`recovery-archive.sha256`：恢复验证。
- `bridge-*-result.json`、`ica-*.json`、`ibc-*.json`：真实交易及跨链断言。
- `final-unit-tests.log`、`final-simulation-results.json`、`review5-final-build.log`：最终源码测试/构建。

完整逐 key 差异、冷备份和节点日志保留在测试服务器工作根，不在 Git 中放置大数据库副本。
