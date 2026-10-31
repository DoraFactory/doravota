# PQC Auth integration and enrollment

The supported source baseline for this candidate is the already upgraded
v1.0.1 runtime, including its completed v1.0.0 archive upgrade. The old multi-version SDK bridge and retired execution
modules are not part of this integration.

## Chain upgrade

1. Build and review the candidate on `feature/pqcauth-sdk-keyring`.
2. Rehearse store addition, bounded PQC initialization, restart,
   archive queries, genesis export/import and ordinary transactions against a
   recent snapshot. Local app tests are not a snapshot rehearsal.
3. Finalize release identity and upgrade plan before publishing artifacts.
   `v1.1.0` is currently the candidate plan; no mainnet schedule is implied.
4. Keep enrollment OPTIONAL at activation. Do not change global enforcement,
   registration cutoffs, account algorithms or consensus signatures implicitly.
5. Do not reuse the released `v1.0.0` upgrade handler for the new module.

The handler validates module versions and the archive activation marker, adds
only the pqcauth store and assigns a chain/upgrade-specific signature domain.
It does not scan accounts or delegations or build any Feegrant reverse index.
Existing account addresses, balances, Authz/Feegrant permissions and archived
contract data are preserved. Internal module version 3 is not a migration for
older experimental PQC version 1/2 databases; do not switch those development
chains to this binary without a separately reviewed transition.

## Account enrollment

- Generate fresh SDK ML-DSA signing and offline recovery keys from **different
  dedicated mnemonics**, separate from every classical wallet mnemonic.
- Review outgoing Authz/Feegrant capabilities, then register both proofs with
  the classical owner signature. Existing permissions remain valid; revoking
  unwanted ones is the user's choice, not an enrollment precondition.
  Registration is one top-level message.
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

Phase one protects direct signing and key management, not every asset movement
through delegated capabilities. Recovery does not revoke delegations. Indirect
key-management execution is still rejected. Comprehensive delegation policy is
separate phase-two work: see the [rollout plan](../../docs/PQCAUTH-ROLLOUT-PLAN.md).

## Eligibility and hardware owners

Existing threshold/multisig accounts cannot enroll in PQCAuth. OPTIONAL allows
ordinary SDK authentication; REQUIRED rejects ALL composite keys, including
all-ML-DSA multisigs. Do not activate REQUIRED or recommend a treasury migration
until multisig policy has been separately implemented, reviewed and tested.
See README's multisig support boundary for the exact scope.

For Ledger/watch-only/offline owners, introducing any new factor requires
`--acknowledge-independent-factors`; use independently generated dedicated
factor mnemonics. Never recover a Ledger mnemonic into a software PQC key.
This acknowledgement cannot prove independence and cannot bypass locally
detected coupling. Existing-factor restoration remains available for recovery.
