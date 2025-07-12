# x/sponso-contract-tx

> 存储专门用于 gas 赞助的合约账户。

整个 sponsor 流程逻辑如下：

🧩 支持 sponsor 的合约需要首先在这个 module 中进行注册，并标记为 IsSponsored 为 true（这相当于一个开关，如果后续这个合约不想 sponsor 了，可以标记为 false）

🧩 用户交易执行流程（执行 MsgExecuteContract）

- 用户构造了一笔 0 fee 的 MsgExecuteContract 交易
- AnteHandler 中调用 sponsor module 的 IsSponsored(contractAddr) 查询
- 如果合约地址标记为支持 sponsor：
  - 调用 ctx = ctx.WithFeePayer(contractAddr)
  - 后续 DeductFeeDecorator 从该合约地址扣除 gas
- 交易正常执行


目录结构大概是这种雏形：
x/sponsor-contract-tx/
├── keeper/
│   └── keeper.go            # 状态处理核心
├── types/
│   ├── keys.go              # store keys（prefix 定义）
│   ├── types.go             # Msg、结构体、接口、常量
│   ├── codec.go             # codec 注册
│   └── errors.go            # 自定义 error（sdkerrors）
├── msgs.go                  # protobuf 消息定义（或 amino Msg）
├── ante.go                  # SponsorAnteDecorator 实现
├── genesis.go               # 初始状态导入导出
├── module.go                # AppModule 实现
├── query.go（可选）         # 模块的 query handler（grpc 或 REST）


1. 一个tx中可能会包含多个交易，这些交易必须都是同一个合约，如果包含了其他非合约交易，就会存在被蹭取交易费，因为一笔batch消息的交易他们的手续费是不能拆开的，是一笔tx（那如何确保我们检查所有的msg的合约地址是同一个呢，这是个问题）
2. 我们这个sponsor module前置检查很简单，也和粗暴，因为链上是有合约做赞助的，所以我们必须防止有人来通过赞助合约蹭交易费用，我们必须确保一个tx中所有的batch是同一个赞助合约的，如果发现任何消息关联的合约地址不一样，那就拒绝（不管他们是不是都是赞助合约，因为一个交易肯定是由一个合约来赞助的），发现任何非合约消息，就直接拒绝。
也就是说，我们网络无法支持夹杂着赞助合约的batch交易，这会导致有人来蹭交易手续费。如果要用一个batch交易来发送赞助交易。这个batch消息必须属于同一个合约地址，这样就是安全的。 cosmsos原生是支持所有消息混合作为一个batch tx的，但是如果要夹杂一个sponsor tx，那就不行，因为赞助是对一个交易的赞助，不是一个更细粒度的消息。

所以以下场景会被拒绝：
1. 蹭其他操作的费用
```proto
❌ [
    MsgExecuteContract{Contract: "sponsored_contract"},
    MsgSend{},           // 试图蹭转账费用
    MsgDelegate{},       // 试图蹭质押费用
]
```
2. 多合约混合（即使都被赞助）
```proto
[
    MsgExecuteContract{Contract: "sponsored_contract_A"},
    MsgExecuteContract{Contract: "sponsored_contract_B"}, // 不同合约
]
```
3. 未赞助合约
```proto
[
    MsgExecuteContract{Contract: "unsponsored_contract"},
]
```

只有一种场景可以通过：
```proto
[
    MsgExecuteContract{Contract: "sponsored_contractA"},
    MsgExecuteContract{Contract: "sponsored_contractA"}, // 同一合约
    MsgExecuteContract{Contract: "sponsored_contractA"}, // 同一合约
]
```

保护sponsor：确保赞助费用只用于预期的合约操作
防止滥用：杜绝交易"搭便车"行为
透明可控：每个赞助交易都有明确的受益方
简单有效：规则简单明确，易于验证和执行


在sponsor ante中，我们需要在fee支持之前就判断这个用户是否符合我们的要求，最好能够判断是否符合wasm合约中的某个方法验证，如果验证不通过，则我们不会sponsor，此时我们就拒绝它，这个仅仅是局限于合约消息（当然这样直接写死可能不通用） 
这里可能需要考虑怎么设计policy，让这部分变得通用，直接一点，我们要求支持sponsor的合约必须要在合约中实现一个叫做policy的方法，这个方法会在我们sponsor ante中首先用于调用判断


1. 不是任何人都可以将合约传递到sposnor module中的，这样就乱套了，必须是合约的admin才可以上传合约地址到sponsor，因为他决定了合约是否支持sponsor（如果没有这个检查，那么任何人都可以设置任何合约地址为fee payer，这是非常危险的操作），所以sponsor module的合约注册需要有一个权限校验
2. 如果合约支持 sponsor → 使用 sponsor 功能（设置 fee payer 为合约地址）
如果合约不支持 sponsor → 让交易正常通过，使用原始的 fee payer
3. 重要的待解决的问题： 如果一个账户没有钱，那么这个账户无法发起交易，因为它在链上没有这个记录，这个非常坑！（所以我们需要把这个逻辑解决掉） ->>>> 这个是整个cosmos链的一种设计，因为交易需要有sequence机制，所以一个在链上没有记录的用户在链上是没有sequence记录的，也就无法处理sequence校验和自增，所以交易是没法发送的，但是我们不在链层面做改动，而是在业务层，比如我们有一个oracle服务，专门让用户在进行业务之前激活它的账户（给用户转账一笔极小的费用，比如1peaka），用户只需要点击一下激活，我们的oracle就自动发送钱给他，这样没有链上活动过的用户就在链上存在了，自然就可以用我们的sponsor module了