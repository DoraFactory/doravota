# Dora Vota
The Dora Vota mainnet is an appchain built exclusively for the Dora community, supporting essential applications such as quadratic voting and MACI (Minimal Anti-collusion Infrastructure) for voting, public good funding, and governance.

## System Requirements
This system spec has been tested by many users and validators and found to be comfortable:

- support AMD, ARM, Apple M1 and M2, At least 8 cores
- 64GB RAM (A lot can be in swap)
- 1TB NVMe Storage
- 100MBPS bidirectional internet connection

You can run Dora Vota Node on lower-spec hardware for each component, but you may find that it is not highly performant or prone to crashing.

## Documentation
For the most up to date documentation please visit [docs.dorafactory.org](https://docs.dorafactory.org/docs/vota)

## Contributing
Anyone who encounters problems while running the Dora Vota node and using the `dorad` binary application can submit a PR to this repository to contribute your code. We warmly welcome valuable feedback from the community developers.


• 设计概览

  - 两阶段赞助（用户自付版）
      - ProbeTx（探测）：只在 DeliverTx 跑限气的 policyCheck；按实际消耗计费，当场从用户扣费；合格则签发短期一次性 Ticket。
      - ExecuteTx（执行）：Ante 检票命中后跳过昂贵检查；由 sponsor 支付整笔执行交易费，并将 Probe 的策略检查成本 probeCost 返还给用户。
  - CheckTx 永不执行昂贵检查，只做廉价门槛与去重；昂贵工作与真实扣费绑定在 DeliverTx，切断零成本 DoS。

  核心流程

  - ProbeTx（MsgProbeSponsorship）
      - CheckTx 门槛（只读）：
          - 形态：同一合约、单 signer、FeePayer 一致、条数/大小不过限。
          - 余额门槛：用户可用余额 ≥ S，S = MaxGasPerSponsorship × PolicyProbeGasPrice（链上参数，固定币种）。
          - 失败短缓存命中（同 contract,user,digest）→ 直接拒绝，不跑策略。
      - DeliverTx 执行：
          - 同 digest 已有有效 Ticket → already_have_ticket：直接返回票据信息；不跑策略、不刷新 TTL、不收费、不计数。
          - 否则在独立限气表中执行 policyCheck（Gas 上限 = MaxGasPerSponsorship），记录 gasUsedPolicy。
          - 计费与扣款：probeCost = ceil(min(gasUsedPolicy, MaxGasPerSponsorship) × PolicyProbeGasPrice)；立即从用户扣至 fee collector（与 tx gasLimit 无关）。
          - 结果：
              - Eligible=true：写 Ticket（contract,user,digest, expiry_height, gasUsedPolicy, probeCost）；交易成功。
              - Eligible=false：不写 Ticket，落“失败短缓存”；交易仍成功（用户为失败的策略检查付费）。
  - ExecuteTx（MsgExecuteContract）
      - Ante 检票：计算同口径 digest，命中未过期 Ticket → 一次性消费 Ticket → 跳过昂贵检查。
      - 赞助与返还：由 sponsor 支付整笔执行 tx 费；同时 sponsor→user 返还 Ticket.probeCost（仅返还策略检查成本；不返还 ProbeTx 自身的 tx fee）。
      - 余额检查：需覆盖“执行 tx 费 + 返还金额”；不足则 Ante 报错，回滚且不消费 Ticket（可重试）。
      - 无票：兼容期可回退旧路径；稳定后开启 RequirePolicyTicket=true，无票不走赞助（用户可自付）。

  并发与短路策略（按你的要求）

  - 唯一性：同一 (contract, user, digest) 同时最多 1 张未消费 Ticket。
  - 同 digest 重复 Probe：短路返回已有票据（already_have_ticket），不刷新 TTL、不收费、不计窗口。
  - 不同 digest：允许并行持有多个 Ticket（不限制总量）；配合短 TTL、失败短缓存与窗口限次抑制状态/流量膨胀。

  负载与去重护栏（无“每块硬顶”的前提）

  - 失败短缓存（NegativeProbeCacheBlocks）：对同 (contract,user,digest) 的策略失败结果缓存 N 块，命中直接拒绝，不再跑策略。
  - 窗口限次（MaxProbesPerUserWindow / ProbeWindowBlocks）：仅在“实际执行了 policyCheck”时计数；命中已有票据/失败缓存/前置门槛拒绝不计数。
  - Ticket 短 TTL（PolicyTicketTTLBlocks）：缩短悬挂时间与状态体量；鼓励 Probe→Execute 同块或短期完成。
  - （可选）节点本地 QoS：mempool/打包优先级让 ExecuteTx 高于 ProbeTx，保障业务交易不被探测挤占。

  链上参数（共识，全局默认 + 合约级可覆盖）

  - MaxGasPerSponsorship（已存在）：策略检查 Gas 上限。
  - PolicyProbeGasPrice：策略检查单价（整数，单位 peaka/gas）；actualCost= min(gasUsedPolicy, MaxGasPerSponsorship) × 单价。
  - PolicyTicketTTLBlocks：Ticket 有效块数（建议 20–30；范围 [1, 1000]）。
  - NegativeProbeCacheBlocks：失败短缓存 TTL（默认 3；范围 [0, 32]；0 关闭）。
  - MaxProbesPerUserWindow / ProbeWindowBlocks：滑动窗口限次（Max 建议 2–3；Window ≈ Ticket TTL；Max∈[0,10]，0 关闭；Window∈[0,500]）。

  存储与键

  - Ticket：ticket/{contract}/{user}/{digest} → {expiry_height, gas_used_policy, probe_cost, consumed?}
  - 失败短缓存：negprobe/{contract}/{user}/{digest} → {until_height, reason?}
  - 窗口计数：probe_window/{contract}/{user} → {window_start_height, count}（仅“实际跑策略”时 +1）

  事件与可观测

  - Probe：policy_probe_run(gas_used_policy, policy_price_per_gas, probe_cost, contract, user)；policy_ticket_issued(contract,user,digest,expiry,probe_cost)；
    policy_probe_denied(reason)；policy_probe_denied_cached(ttl_left)；already_have_ticket(contract,user,digest,expiry,probe_cost)。
  - Execute：sponsored_transaction(contract,user,sponsor,fee_amount)；policy_ticket_reimbursed(amount,contract,user)；sponsorship_skipped(reason)。

  关键实现要点

  - digest 规范：用全部 MsgExecuteContract 原始 JSON bytes（签名顺序、字节不重编码）+ 合约地址做 sha256；Probe 与 Execute 一致。
  - 余额门槛：S=MaxGasPerSponsorship×PolicyProbeGasPrice；CheckTx/DeliverTx 两侧都要校验，避免“先跑后扣不到”的白跑。
  - 计费一致：全程整数运算，必要处向上取整；仅按策略实际 gas 结算，与用户 tx gasLimit 无关。
  - GC：对 Ticket 与负缓存做每块小步 GC，避免状态膨胀。