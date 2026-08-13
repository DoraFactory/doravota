# PQCAuth Review问题修复

### 1. 修复 Key ID 终身配额导致的账户永久锁死

原来的 `max_keys_per_account` 实际上是终身累计配额。Signing Key 和 Recovery Key 每次轮换都会消耗新的 Key ID；当配额耗尽后，普通轮换和恢复都会失败，最终可能导致账户永久无法操作。

调整：

- Key ID 保持单调递增，但不再通过终身创建数量限制账户。
- 当前生效和等待生效的 Key Record 永远不会被历史压缩删除。
- Signing 和 Recovery 两种角色分别保留最近 16 条完整终态历史记录。
- 完整历史记录总上限可配置，默认硬上限为 64 条。
- 更早的历史记录写入确定性的、按角色区分的哈希累加器，保留可验证的历史承诺。
- Recovery Key 多次轮换不会挤掉当前 Signing Key，反之亦然。
- Genesis、导出、查询和 invariant 检查均支持压缩后的历史状态。

### 2. 强制 Signing Key 与 Recovery Key 相互独立

为避免两个角色使用同一把 ML-DSA 私钥、从而让“恢复密钥”失去第二安全边界，注册流程现在要求：

- 首次注册必须同时提供 Signing Key 和 Recovery Key。
- 两把公钥必须不同，且都必须是受支持的 ML-DSA-65 密钥。
- 账户注册后必须进入 `self_enforced` 状态。
- 两把密钥都按 H+1 规则生效。
- 后续 Signing Key 轮换、Recovery Key 轮换和账户恢复都会检查角色间密钥不得重复。
- Genesis 校验同样执行这一约束，防止通过初始化状态绕过。


### 3. 为 Signing Key 状态损坏提供受控恢复出口

此前，如果账户策略指向的当前 Signing Key 缺失、被撤销或不可用，Ante 会先返回 `ErrInconsistentState`，导致 `MsgRecoverKey` 也无法执行。此时即使用户仍持有 Recovery Key，也无法恢复账户。

现在增加了一个严格受限的恢复路径：

- 仅允许唯一、顶层的 `MsgRecoverKey` 使用该路径。
- 仍然要求经典 Cosmos 账户签名。
- 必须提供有效的 Recovery Key 签名。
- 新 Signing Key 必须提交有效的 PoP（Proof of Possession）。
- 不允许通过 `authz`、`group`、`wasm` 或其他嵌套执行方式进入该路径。
- 其他交易继续 fail-closed，不会因为恢复出口而放宽认证。


### 4. 为高风险治理参数增加不可绕过的安全延迟

原实现中，治理可以让所有参数在 H+1 生效。这意味着一次治理操作可能很快完成以下限制：

- 将 enforcement mode 切换为 `REQUIRED`。
- 设置注册 cutoff。
- 移除正在使用的算法。
- 提高验证 gas。
- 降低交易大小、签名人数量等上限。

虽然不直接破坏共识，却可能大面积冻结用户交易。现在新增了两项 Genesis 固定的安全边界：

- `governance_safety_delay_blocks`：限制性治理变更必须等待足够长的生效期。
- `max_emergency_duration_blocks`：紧急模式最多允许持续的区块数。

同时：

- 放宽限制的治理变更可以更快生效。
- 治理可以在限制性变更生效前，通过重新提交当前参数取消 pending 变更。
- 这两个安全边界不能通过普通参数治理即时缩短。



### 5. 紧急模式自动过期，避免无限期冻结

此前，`PAUSE_NEW_KEYS` 或 `PAUSE_PQC_TRANSACTIONS` 一旦由治理开启，可能一直保持，直到治理再次解除。如果治理操作失误或治理系统暂时不可用，用户可能被长期冻结。

修复后：

- 紧急模式到期后自动恢复为 `NORMAL`。
- 治理不能任意设置或延长过期高度。
- 最大紧急持续时间由 Genesis 固定安全边界约束。
- `EffectiveParams` 和区块开始阶段会对过期状态进行一致化处理。



### 6. 暂停期间仍保留严格受控的 Recovery 路径

为了避免紧急模式本身锁死已经受保护的账户，现在：

- `PAUSE_NEW_KEYS` 和 `PAUSE_PQC_TRANSACTIONS` 下仍允许顶层、单一的账户恢复交易。
- 恢复交易仍必须满足经典签名、Recovery Key 签名、新 Key PoP 和防嵌套校验。
- 普通注册、普通轮换和普通 PQC 交易仍按紧急模式暂停。

这保证了紧急控制可以阻断风险交易，同时不会删除账户的最后恢复出口。



### 7. 修复 Cosmos SDK `simulate` / gas 自动估算兼容性

Cosmos SDK 的交易模拟通常使用高度 0，并携带空的 `SIGN_MODE_UNSPECIFIED` 签名占位符。如果完全按照 DeliverTx 的规则执行真实 ML-DSA 验证，钱包和 CLI 将无法在尚未生成最终签名时估算 gas。

现在的模拟规则为：

- 模拟高度映射到最新已提交区块的有效状态。
- 只接受精确的未签名占位形式，避免把任意伪签名当成模拟交易。
- 仍执行 extension 结构、策略、Key ID、公钥和签名长度、PQC required 等校验。
- 仍按配置扣除 PQC 验证 gas。
- 仅在严格模拟路径跳过实际密码学验证。
- CheckTx 和 DeliverTx 仍要求 `SIGN_MODE_DIRECT` 和真实的 ML-DSA 签名。