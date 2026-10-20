# PQC Auth integration and enrollment

The supported source baseline for this candidate is the already upgraded
v1.0.0 archive runtime. The old multi-version SDK bridge and retired execution
modules are not part of this integration.

## Chain upgrade

1. Build and review the candidate on `feature/pqcauth-sdk-keyring`.
2. Rehearse store addition, migration, feegrant-index reconstruction, restart,
   archive queries, genesis export/import and ordinary transactions against a
   recent snapshot. Local app tests are not a snapshot rehearsal.
3. Finalize release identity and upgrade plan before publishing artifacts.
   `pqcauth-v1` is currently the candidate plan; no mainnet schedule is implied.
4. Keep enrollment OPTIONAL at activation. Do not change global enforcement,
   registration cutoffs, account algorithms or consensus signatures implicitly.
5. Do not reuse the released `v1.0.0` upgrade handler for the new module.

The handler validates module versions and the archive activation marker, adds
only the pqcauth store, assigns a chain/upgrade-specific signature domain and
rebuilds the reverse feegrant index from canonical allowances. Existing account
addresses, balances and archived contract data are preserved.

## Account enrollment

- Generate fresh SDK ML-DSA signing and offline recovery keys from **different
  dedicated mnemonics**, separate from every classical wallet mnemonic.
- Revoke outgoing authz/feegrant capabilities, then register both proofs with
  the classical owner signature. Registration is one top-level message.
- Wait until H+1. Verify that a classical-only transfer fails and a correctly
  bound hybrid transaction succeeds. Retain transaction evidence.
- Offline recovery and key rotation are separate from recovering the original
  account private key. Recovery still requires that classical signer.
- Native ML-DSA accounts do not need this extra-factor enrollment.

The local reuse guard detects only coupling to the available owner key. It is
not a chain-wide or cryptographic proof of seed independence. Backup restoration
is allowed. The CLI neither invents a new derivation standard nor claims to
identify whether a mnemonic has ever been used elsewhere.

For commands, candidate defaults, legacy-file compatibility and testing scope,
see [README](README.md). Full keyring-backed lifecycle rehearsal and production
operational review remain release acceptance work.
