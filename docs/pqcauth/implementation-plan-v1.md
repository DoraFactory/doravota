# PQC authentication implementation plan v1

## Milestones

1. **Implemented:** freeze the threat model, wire format, signer document,
   lifecycle, and unsupported sign modes.
2. **Implemented:** pin Go, Cosmos SDK v0.55 and CometBFT v0.40, use the SDK's
   native ML-DSA-65 key API through a bounded adapter, and add mutation tests,
   a fuzz target, and a benchmark.
3. **Implemented:** protobuf state, lifecycle messages, queries, signing and
   recovery-key rotation, recovery, and H+1 key/policy/parameter activation.
4. **Implemented:** critical-extension registration, app store, module manager,
   and v1.0.0 upgrade wiring.
5. **Implemented:** cheap canonical structure checks and expensive hybrid
   authorization/proof verification in Ante.
6. **Implemented:** non-no-op PrepareProposal and ProcessProposal validation,
   finite proposal fallbacks, and finite defaults for new genesis chains.
7. **Implemented:** Go CLI key generation, offline proofs, protected
   single-signer broadcast, versioned offline transaction bundles, upgrade
   handling, metrics, and operator runbooks. A transport-neutral `PQCSigner`
   boundary is available for remote signers, HSMs, and hardware wallets.
   Concrete remote transports remain deployment-specific.
8. **Partially verified, not yet a production gate pass:** deterministic and
   mutation vectors, full Go tests, the race detector, an 80% handwritten-code
   coverage gate, proposal rejection, upgrade initialization, Linux
   amd64/arm64 static builds, stale-bundle rejection, and explicit
   sponsor-message, fee-granter, nested-authz binding, target upgrade source
   guards, and retained group-state tests are covered. Native
   multi-architecture execution, the v0.47 -> v0.53/IBC v10 bridge release,
   two-height production-snapshot and recovery rehearsals, load testing, and
   external review remain.

## Production gates

- No unresolved Critical or High audit finding.
- ProcessProposal is not a no-op.
- Consensus block max gas is finite and benchmark-derived.
- amd64 and arm64 produce identical signing bytes, verification decisions, gas,
  ABCI codes, and app hashes.
- Protected transactions have no classical-only success path.
- Recovery and fail-closed incident procedures have been rehearsed.
- The mainnet rollout starts in `DISABLED` or `OPTIONAL`; enforcement is
  activated only at a separately announced height.
