## x/sponsor-contract-tx 模块审计记录

### 范围

- 已审阅：`ante.go`、`sponsor_decorator.go`、`module.go`、`genesis.go`、`keeper/{keeper.go,msg_server.go,grpc_query.go,querier.go}`、`types/{keys.go,types.go,errors.go,events.go,codec.go}`、`app/ante.go`
- 目标：检查赞助交易逻辑的安全性、与标准扣费/验签流程的时序关系、与 Feegrant/Min-gas-price 的一致性，及全链接入正确性

### 结论概览

- `app/ante.go` 接入顺序总体合理：
  - 先执行赞助识别 `SponsorContractTxAnteDecorator`，再用 sponsor-aware 的扣费替换标准 `DeductFeeDecorator`，之后再执行公钥设置与签名验证
- 主要问题集中在赞助扣费路径与上下文标记的安全性、一致性，以及参数未被强制执行

---

### 严重问题（需优先修复）

- 赞助扣费分支绕过 min-gas-price / TxFeeChecker 校验

  - 表现：赞助路径直接 `SendCoinsFromAccountToModule` 到 `fee_collector`，未调用 `txFeeChecker`；可能以小于 required fee 的金额上链
  - 位置：`x/sponsor-contract-tx/sponsor_decorator.go` `handleSponsorFeePayment()` 扣费前无任何 `txFeeChecker` 校验
  - 建议：
    - 在 `SponsorAwareDeductFeeDecorator` 保存 `txFeeChecker`，在赞助扣费前先校验所需费用（含 min-gas-price）；不满足则报错
    - 或改造为用 Feegrant（由 Sponsor 预先 grant），从而复用标准 `DeductFeeDecorator` 的所有校验与扣费

- 多签/多 signer 事务只取第一个 signer，可能与 FeePayer 不一致

  - 表现：`Ante` 中以 `msg.GetSigners()[0]` 作为“用户”做资格与余额判断，忽略其他 signer
  - 建议：若 SDK 支持 `FeeTx.GetFeePayer()`，应以 FeePayer 为准；否则强制所有 `GetSigners()` 一致，不一致则不走赞助分支（或拒绝）

- 使用字符串作为 `context` 键，存在冲突风险

  - 表现：`"sponsor_contract_addr"/"sponsor_fee_amount"/"sponsor_user_addr"` 字符串键存取赞助上下文
  - 建议：使用私有、类型安全的 `context` 键与一个聚合结构体，避免键名冲突与类型断言风险

- 忽略配置的 `SponsorAddress`，实际从合约地址扣费

  - 表现：`MsgSetSponsor` 存了 `SponsorAddress`，但扣费固定从合约地址转出
  - 建议：扣费地址优先使用 `sponsor.SponsorAddress`（若存在且有效），否则再回退到合约地址；并在事件与日志中明确

- 模块参数未强制执行（`SponsorshipEnabled`/`MinContractAge`/`MaxSponsorsPerContract` 等）
  - 表现：`Params` 定义的开关与限制未在 `Ante` 中生效
  - 建议：在进入赞助逻辑前检查 `SponsorshipEnabled`；如有年龄/数量限制需求，在 `Ante` 或设置流程中强制校验

---

### 中风险 / 一致性问题

- 赞助与 Feegrant 的优先级未定义

  - 现逻辑：用户余额不足即尝试赞助，即使存在 Feegrant 也不会使用；需在设计上明确优先级，并在实现与文档中保持一致

- 事件重复与读路径事件噪声

  - `Ante` 与扣费处对同一赞助交易各发一次“赞助成功”事件，可造成重复
  - `GetSponsor`、`HasSponsor`、`GetParams` 等读方法大量发事件，放大会计事件噪声与节点日志压力
  - 建议：
    - 写路径事件保留；读路径事件酌情取消
    - 赞助成功事件在扣费最终成功处发一次即可

- 模拟/CheckTx/DeliverTx 的状态变更时机
  - 现逻辑在 `!simulate` 时处理扣费与更新“使用量”；CheckTx 阶段不会落盘，但会重复执行逻辑
  - 建议：仅在 DeliverTx 更新“使用量”；扣费跟随 SDK 标准路径（在 DeliverTx 落盘）

---

### 低风险 / 改进建议

- `validateSponsoredTransaction` 未约束所有消息 signer 与 FeePayer/选定用户一致

  - 建议：多消息时确保 signer 一致，或退回标准扣费路径

- 合约策略查询（policy check）

  - 逻辑使用独立 GasMeter 并回补至原上下文，合理；可在 simulate 模式下选择跳过以提升模拟速度（视产品策略）

- gRPC Gateway 路由尚未注册
  - 需要生成并注册 `*.pb.gw.go`，按需填充 `RegisterGRPCGatewayRoutes`

---

### 建议代码改动（示例片段）

- 类型化上下文键与聚合结构

```go
// 新增（任一 .go 文件的合适位置）：
type ctxKeySponsor struct{}

type SponsorCtx struct {
  SponsorPayer sdk.AccAddress
  User         sdk.AccAddress
  Fee          sdk.Coins
  ContractAddr sdk.AccAddress
}

// 写入：
ctx = ctx.WithValue(ctxKeySponsor{}, SponsorCtx{SponsorPayer: payer, User: userAddr, Fee: fee, ContractAddr: contractAccAddr})

// 读取：
if v := ctx.Value(ctxKeySponsor{}); v != nil {
  sc := v.(SponsorCtx)
  // ...
}
```

- 在 Ante 使用 `SponsorAddress` 与参数开关

```go
sponsor, found := sctd.keeper.GetSponsor(ctx, contractAddr)
if !found || !sponsor.IsSponsored { return next(ctx, tx, simulate) }
params := sctd.keeper.GetParams(ctx)
if !params.SponsorshipEnabled { return next(ctx, tx, simulate) }

payer := contractAccAddr
if sponsor.SponsorAddress != "" {
  if a, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress); err == nil { payer = a }
}
```

- 赞助扣费路径引入 `TxFeeChecker` 校验

```go
// 在 SponsorAwareDeductFeeDecorator 中保存 txFeeChecker 字段
// 并在 handleSponsorFeePayment 最前执行：
if safd.txFeeChecker != nil {
  requiredFee, err := safd.txFeeChecker(ctx, tx)
  if err != nil { return ctx, err }
  if !fee.IsAllGTE(requiredFee) {
    return ctx, sdkerrors.Wrapf(sdkerrors.ErrInsufficientFee, "got %s, require %s", fee, requiredFee)
  }
}
```

- 仅在 DeliverTx 更新用户赞助使用量

```go
if !simulate && !ctx.IsCheckTx() {
  if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), contractAddr.String(), fee); err != nil {
    return ctx, sdkerrors.Wrap(err, "failed to update user grant usage")
  }
}
```

- 多 signer 处理

```go
// 优先采用 FeeTx 的 FeePayer（如 SDK 版本支持）
// 否则校验所有 msg.GetSigners() 相同；不一致则不走赞助分支
```

---

### 集成检查清单

- `app/ante.go`
  - 顺序正确：赞助识别 -> sponsor-aware 扣费 -> SetPubKey/验签 -> 增加序号
- `app/app.go`
  - 注册 `sponsor` 的 KVStore：`keys[types.StoreKey]`
  - 初始化 keeper：`NewKeeper(appCodec, keys[types.StoreKey], app.WasmKeeper)`
  - `ModuleBasics` 包含 `sponsor.AppModuleBasic`；`ModuleManager` 与 `Configurator` 注册消息与查询服务
- `genesis`
  - 如需默认参数或初始 sponsor，确保 `genesis.json` 中包含相应条目

---

### 测试建议

- 单元测试
  - 赞助扣费路径与 `txFeeChecker` 校验：低于与高于 min-gas-price 分别断言
  - Feegrant 存在时的优先级选择
  - 多 signer 与 FeePayer 场景
  - `DeliverTx` 才更新使用量
- 集成测试
  - 合约策略查询超限（触发 gas 限制 panic）
  - 赞助人资金不足、用户资金充足/不足、参数开关关闭

---

### 摘要

- 关键修复：补齐赞助扣费路径对 `txFeeChecker` 的校验、采用类型化上下文键、尊重 `SponsorAddress`、执行参数开关、修正多 signer/FeePayer 处理、只在 DeliverTx 更新使用量，并精简读路径事件。
- `app/ante.go` 接入顺序正确；请确认 `app/app.go` 的 keeper/store 与接口注册完整。



## 再次Review之后的结论

与 README 对照后的结论
仍然存在的问题
最低 gas 单价/TxFeeChecker 校验绕过: README 未声明在赞助路径执行 min-gas-price 校验；实现中赞助扣费未调用 txFeeChecker，风险成立。
多签/多 signer 与 FeePayer 一致性: README 未定义，代码以第一个 signer 作为“用户”，风险成立。
使用字符串 context 键: README 未涉及实现细节，冲突风险仍在。
模块参数未被强制执行: README 展示了 sponsorship_enabled 等参数，但未说明在 Ante 生效；实现未检查，问题成立。
赞助与 Feegrant 优先级: README 未说明优先级，现实现会“赞助覆盖 feegrant”，需要明确策略。
gRPC Gateway 未注册: README 未提供网关注册，当前实现留空，属于待完善项。
设计选择（非严格漏洞，但建议澄清或优化）
扣费账户使用“合约地址”而非 sponsor_address: README 明确要求“给合约地址充值、由合约出资”，与实现一致。因此“忽略 SponsorAddress 扣费”不是功能漏洞，但字段命名容易引起误解。建议：
将 sponsor_address 在文档中明确为“注册者/管理员地址”（Access Control 用途），或重命名为 admin_address。
读路径事件较多: README 列出了 get_sponsor、query_sponsors 等查询事件，说明是设计选择。建议保留但评估性能影响。
与 README 一致、无问题
交易结构约束：只允许同一合约的 MsgExecuteContract，混入其他消息或多个合约即拒绝。代码与 README 一致。
策略查询加气限制：实现使用独立 GasMeter，并回补 gas；README 有“Gas Considerations”，一致。

建议（与 README 对齐的修复方向）
在赞助扣费路径执行 txFeeChecker 校验，保证 min-gas-price 与必需费额一致；或改走 Feegrant 以完全复用标准校验。
定义并文档化“Feegrant 与 Sponsor”的优先级；实现中按策略生效。
统一类型化 context 键，避免冲突；可用聚合结构体一次性传递赞助上下文。
在 Ante 生效 SponsorshipEnabled 等参数；如需要，补充合约年龄/上限相关逻辑或文档。
多 signer/FeePayer 策略：优先用 FeePayer，否则强制所有 signer 一致；在 README 的 Security Model 中补充说明。
保持在 DeliverTx 才更新“使用量”（可选优化，减少 CheckTx 重复计算）；README 可注明更新时机。
简短总结
README 没有否定之前指出的风险；关键风险（min-gas-price 校验、FeePayer/多签一致性、参数未生效、Feegrant 优先级）依然成立。
“由合约账户出资”与实现一致，需在文档中澄清 sponsor_address 语义，避免歧义。
读路径事件属于设计选择，可保留但要关注性能。