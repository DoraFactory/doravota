# PQCAuth rollout plan

Scope: the v1.1.0 candidate on `feature/pqcauth-sdk-keyring`, upgrading from
pre-PQCAuth v1.0.1. This plan is not release or deployment approval. The
[module README](../x/pqcauth/README.md) is the source for current parameters,
commands and supported behavior.

## Phase one: direct account authentication

PQCAuth adds a registered ML-DSA-65 factor to an existing classical account.
Protected transactions require both factors. Registration, key rotation,
revocation, protection changes and delayed recovery have dedicated authorization.
Signatures bind the network, chain, account, sequence, transaction intent, fees,
keys and policy version.

Phase-one boundaries:

- Registration is open unless paused; no CLOSED/FRESH mode or numeric cutoff.
- Enforcement supports OPTIONAL and REQUIRED_FOR_REGISTERED, not global REQUIRED.
- Registration and PQC-protected transactions require DIRECT for all signers.
  Composite accounts and the SDK's Amino-only Ledger backend cannot enroll.
- Existing Authz/Feegrant retain SDK semantics. Enrollment/recovery does not revoke
  them or require the owner's fresh PQC signature for every delegated action.
  Lifecycle messages cannot execute through delegated/nested routes.
- No delegation index or full account/grant scan runs during module initialization.
- Verification costs 750 gas by default, in addition to SDK signature, byte,
  storage and execution costs. There is no separate 16/transaction or 400/block
  verification quota. SDK limits and fixed extension/wire caps remain.
- Consensus keys and IBC light-client algorithms do not change.
- Module version 4 does not automatically migrate experimental PQC states 1–3.

## Candidate and acceptance sequence

1. Review and freeze exact source, version, toolchain and dependency identity.
   Build a candidate without prematurely publishing a release tag; record its
   SHA-256 and embedded build information.
2. Run mandatory regressions and explicit simulations, then the four-validator
   lifecycle and supported source-snapshot upgrade/restart/interruption tests
   using the final artifact. Changed source or artifacts require corresponding
   revalidation; old reports identify only their own revisions.
3. Complete public-testnet registration, protected transactions, both rotations,
   recovery/cancellation, restart and IBC round-trip acceptance.
4. Run representative sustained and adversarial capacity benchmarks on the
   intended testnet hardware. Per the agreed scope, this work is deferred from
   the small local environment to that testnet; it is **not marked passed**.
   Measure admission/recheck, block execution, CPU/RSS, large messages/signers
   and recovery latency under load.
5. Review the evidence and obtain separate release/network-change approval.
   Coordinate the exact plan, height, prerequisites, artifact hashes and validator
   voting power before activation.

Unit tests and finite smoke tests do not certify absence of vulnerabilities,
production capacity, fair transaction ordering or a maximum recovery inclusion
delay. Hardware capacity cannot replace authentication/state-machine tests.

## Governance operations

There are three mutable settings: enforcement, verification gas and emergency
mode. Network ID and the three launch delays are immutable. Defaults are
17,280 governance-delay blocks, 107,520 recovery-delay blocks and 46,080 maximum
pause blocks. Their approximate durations depend on block time.

Use explicit `emergency_only` intent:

- Full updates cancel/replace ordinary plans as documented; retaining the active
  pause preserves its expiry rather than renewing it.
- Emergency-only updates activate at H+1 and preserve the ordinary plan and its
  original activation height.
- Before that emergency activation, complete updates are rejected, including
  when no ordinary plan existed beforehand. Explicit emergency replacements
  remain possible.
- Submit pauses separately from complete updates. A failing later message rolls
  back the whole governance proposal; a failed separate proposal does not retry
  automatically.

Recovery/cancellation exceptions still require all signatures/proofs, including a
protected independent payer's authentication. They are not an escape from a broken
ML-DSA algorithm. Check actual active/pending state, expiry and `resulting_params`;
do not rely solely on a successful transaction receipt.

Before changing block gas, SDK signature limits or PQCAuth price:

1. Snapshot the effective and pending consensus/auth/PQCAuth settings at one
   confirmed height; check every activation stage.
2. For finite block gas, check `3 × verification_gas < block.max_gas`, with measured
   allowance for all other gas. This is a minimum sanity check, not total cost or
   a per-transaction count limit; unlimited block gas gives no capacity guarantee.
3. Test supported signer combinations, native multisig leaves, independent payers
   and lifecycle operations with the proposed settings.
4. Keep results and ordering in the proposal record; re-query and exercise the
   affected paths after activation. Changing consensus gas does not itself invoke
   PQCAuth's governance price check.

Raising SDK signature limits does not increase the fixed eight-entry / 64 KiB
PQC extension caps.

## Client and recovery preparation

Use separate classical, signing and recovery secrets. Generate replacement keys
on a trusted device. Offline recovery and both offline rotations must compare the
new key against an independently trusted local key or full SHA-256 fingerprint;
a hash supplied by the untrusted preparation host is not an intent check.
The module README contains the current commands and required flags.

Keep recheck enabled. Its crypto reuse assumes previously admitted bytes, ordered
transactions and a pending block before policy changes. New admission and final
execution still verify signatures; changing those assumptions requires review.

## Phase two: separately scoped work

Potential future work includes permission visibility/revocation tools,
account-specific delegation policies, multisig and hardware-wallet support,
additional algorithms and stronger enforcement. Any delegation index needs
bounded initialization, maintenance and interruption recovery.

Reintroducing fresh-only enrollment would require a designed persistent key
commitment and transaction-bound retry protocol, including OOG, replay, sequence,
fee, export/import and restart tests. Static PoP reuse or relaxed freshness checks
are not a substitute.

These features are not implicitly enabled by phase one. See the
[documentation index](README.md) for revision-specific audit and acceptance records.
