# PQC transaction authentication

This directory contains the consensus and rollout specifications for
`x/pqcauth`.

The v1 design adds ML-DSA-65 as a second transaction-authentication factor:

```text
existing Cosmos account signature AND ML-DSA-65
```

It does not replace the existing Cosmos SDK account public key and it does not
protect validator consensus keys, CometBFT P2P identities, IBC light clients,
historical signatures, or contract-specific authorization.

The implementation is gated by the following documents:

- [Threat model](./threat-model-v1.md)
- [Signing and wire specification](./signing-spec-v1.md)
- [Implementation and rollout plan](./implementation-plan-v1.md)
- [Operator runbook](./operator-runbook-v1.md)

Consensus code must not weaken the hybrid `AND` rule on verification errors.
Emergency operation is fail-closed: protected transactions may be paused, but
they must never fall back to classical-only authentication.
