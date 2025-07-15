# x/sponsor-contract-tx

> 存储专门用于 gas 赞助的合约账户。

## Background

1. 我们需要在不了解grantee地址的情况下让先新用户能够免费使用我们的业务合约
    - cosmos的fee grant是需要先知道grantee是谁，才能设置fee grant（不符合需求）
2. 通过auth以及wasm模块增加合约的接口，让auth可以判断是否能否赞助，但是这种设计不利于我们未来与cosmos module保持版本同步（auth，wasm模块需要升级，以及这种官方模块修改的安全性是未知且要花费大量成本来验证）
3. 设计一个专门的sponsor来管理支持fee grant的合约
   - 我们不能通过fee grant去做sponsor合约（fee grant设计对于合约来说存在缺陷，合约作为granter会被滥用）
   - 我们可以设计一个专门用于合约sposnor的module，如果一个cosmos业务合约想sponsor其用户，可以在我们的module中进行注册就可以了(确保合约地址有足够的钱)

## Functions
专门用于`记录支持sponsor的合约`

- SetSponsor
  - Creator
  - ContractAddress
  - IsSponsored
- UpdateSponsor
  - Creator
  - ContractAddress
  - IsSponsored
- DeleteSponsor
  - Creator
  - ContractAddress


## Mechanism

> 主要的目的是为了让链级别知晓什么样的合约可以给用户代付gas fee

🧩 支持 sponsor 的合约需要首先在这个 module 中进行注册，并标记为 IsSponsored 为 true（这相当于一个开关，如果后续这个合约不想 sponsor 了，可以标记为 false）


🧩 用户交易执行流程（执行 MsgExecuteContract）

1. 用户构造了一笔想要被sponsor的 合约交易(MsgExecuteContract)
2. 交易在正式进入执行之前会通过一系列的check(Ante handler调用链)
3. 在sponsor module的AnteHandler校验中会检查当前这笔Tx是否符合sponsor条件
> 这里check tx需要考虑batch tx情况，一个tx可以包含多个Msg，所以需要检查所有Msg

（1）合约消息和普通交易混合的交易❌
```proto
 [
    MsgExecuteContract{Contract: "sponsored_contract"},
    MsgSend{},           // 试图蹭转账费用
    MsgDelegate{},       // 试图蹭质押费用
]
```
（2）多合约消息混合的交易❌  
- case1: 
```proto
[
    MsgExecuteContract{Contract: "sponsored_contract_A"}, // 合约A支持sponsor
    MsgExecuteContract{Contract: "sponsored_contract_B"}, // 合约B支持sponsor
]
```
- case2:
```proto
[
    MsgExecuteContract{Contract: "sponsored_contract_A"}, // 合约A支持sponsor
    MsgExecuteContract{Contract: "unsponsored_contract_B"}, // 合约B不支持sponsor
]
```
（3）未赞助合约❌
```proto
[
    MsgExecuteContract{Contract: "unsponsored_contract"},
]
```

（4）唯一可以通过✅：
```proto
[
    MsgExecuteContract{Contract: "sponsored_contractA"},
    MsgExecuteContract{Contract: "sponsored_contractA"}, // 同一合约
    MsgExecuteContract{Contract: "sponsored_contractA"}, // 同一合约
]
```

> 保护sponsor：确保赞助费用只用于其合约操作; 防止滥用：杜绝交易"搭便车"行为



4. 如果一个tx check通过，那么合约就可以sponsor这个用户的fee
  - 方案1（修改fee payer）：
    - 如果合约地址标记为支持 sponsor：
    - 调用 ctx = ctx.WithFeePayer(contractAddr)
    - 后续 DeductFeeDecorator 从该合约地址扣除 gas，合约地址是fee payer
    - 交易正常执行
  - 方案2（不修改fee payer）:
    - 如果合约地址标记为支持 sponsor：
    - 直接让合约地址向用户的地址转账
    - 让用户仍然是fee payer
> 方案1不可行，因为fee data有用户的签名，只是修改fee payer，在后续的fee签名校验中不会通过，这个就相当于去发了一笔交易，然后随便将fee payer修改为其他人地址，就会导致安全性问题，所以这个方案不行，除非是修改fee payer的同时修改整个fee的签名，但是这个签名过程是一个主动操作，合约地址无法去做。 这个原理其实类似eth，sui，aptos这种relayer来对fee data签名的方式，所以我们采用方案2
5. 当sponsor module的AnteHandler通过之后，用户就获得了合约地址转过去的钱，并且就是fee的token数量，接下来就和普通交易一样，用户是有钱的，而且可以支付。



## Attention


1. 我们这个sponsor module前置检查很简单，也和粗暴，因为链上是有合约做赞助的，所以我们必须防止有人来通过赞助合约蹭交易费用，我们必须确保一个tx中所有的batch是同一个赞助合约的，如果发现任何消息关联的合约地址不一样，那就拒绝（不管他们是不是都是赞助合约，因为一个交易肯定是由一个合约来赞助的），发现任何非合约消息，就直接拒绝。
也就是说，我们网络无法支持夹杂着除了当前赞助合约的batch交易，这会导致有人来蹭交易手续费。如果要用一个batch交易来发送赞助交易。这个batch消息必须属于同一个合约地址，这样就是安全的。 cosmsos原生是支持所有消息混合作为一个batch tx的，但是如果要夹杂一个其他合约的sponsor tx，那就不行，因为赞助是对一个交易的赞助，不是一个更细粒度的消息。  

2. 在sponsor ante中，我们需要在合约发送fee之前就判断这个用户是否符合我们的要求，最好能够判断是否符合wasm合约中的某个方法验证，如果验证不通过，则我们不会sponsor，此时我们就拒绝它，这个仅仅是局限于合约消息。
    > 我们的module会`要求所有需要sponsor的合约都实现一个policy()方法`，这个是强制的，如果没有policy就会被拒绝，只有合约policy方法返回是true才会通过
    > ‼️ 从module内部去查询contract其实会消耗gas

3. 不是任何人都可以将合约传递到sposnor module中的，这样就乱套了，必须是合约的admin才可以上传合约地址到sponsor，因为他决定了合约是否支持sponsor（如果没有这个检查，那么任何人都可以设置任何合约地址为fee payer，这是非常危险的操作），所以sponsor module的中的注册，删除，修改都需要有一个权限校验（校验交易的发起者必须是这个合约的admin）。
如果合约不支持 sponsor → 让交易正常通过，使用原始的 fee payer

4. `重要的问题`：  
如果一个账户没有钱，那么这个账户无法发起交易，因为它在链上没有这个记录，这个非常坑！（所以我们需要把这个逻辑解决掉） ->>>> 这个是整个cosmos链的一种设计，因为交易需要有sequence机制，所以一个在链上没有记录的用户在链上是没有sequence记录的，也就无法处理sequence校验和自增，所以交易是没法发送的。   
`解决方案`：
我们不在链层面做改动，而是在业务层，比如我们有一个oracle服务，专门让用户在进行业务之前激活它的账户（给用户转账一笔极小的费用，比如1peaka），用户只需要点击一下激活，我们的oracle就自动发送钱给他，这样没有链上活动过的用户就在链上存在了，自然就可以用我们的sponsor module了