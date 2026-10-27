# PQCAuth candidate follow-up — 2026-10-27

Branch: `feature/pqcauth-sdk-keyring`; candidate `v1.1.0-dev`; future upgrade
plan `v1.1.0`. No release tag, public-network upgrade, or mainnet transaction
was made in this follow-up.

## Changes and verification

1. **Docker candidate builds repaired (`b167f62`).** The native build step
   allowed the development version, but the Dockerfile did not receive the
   opt-in. Both architecture jobs failed before compiling the Docker image.
   The workflow now shares the same branch-scoped policy with both builds.
   Docker defaults to the repository VERSION instead of hard-coded v1.0.0,
   and validates the image's reported version. Prerelease builds remain
   disabled by default; the public release workflow does not opt in.
2. **Release-identity negative tests (`9ff043d`).** Exercise the actual shell
   build gate: reject prerelease without opt-in, mismatched source/version,
   and missing full commit identity before building anything.
3. **Packaged-binary regression (`9ff043d`).** Added
   `scripts/rehearse-pqcauth-lifecycle.py` and made it a candidate CI gate for
   both native Linux AMD64 and ARM64 runners. The test extracts the exact
   packaged binary, starts four local validators, and preserves public
   evidence separately from synthetic keyrings. It refuses existing run
   directories and stops only processes it started.

No Go source, dependency, consensus parameter default, derivation rule, or
multisig policy changed relative to runtime commit `d783507`.

The repaired build CI passed all jobs:
https://github.com/DoraFactory/doravota/actions/runs/40426002766

The expanded CI passed all jobs at source commit
`9ff043d82442ebbc744f18e316269d5071950f6a`, including both packaged-binary
rehearsals:
https://github.com/DoraFactory/doravota/actions/runs/40427868201

Downloaded and checked each architecture's public evidence artifact:

| Native runner | Packaged-binary rehearsal | Recipient increase |
| --- | --- | --- |
| Linux AMD64 | PASS: 49 successful transactions, 6 expected rejection checks | Exactly 85 peaka |
| Linux ARM64 | PASS: 49 successful transactions, 6 expected rejection checks | Exactly 85 peaka |

Tested binary SHA-256 values from that CI run:

- AMD64: `c038334e9355e989129ad64c96b3395a9a30e71746f32995cd8d600f0246fdfd`
- ARM64: `e571fa66dcc9983bc63e3d1db2142478db5796e2644829e036067174024d7344`

This report and its documentation links are a subsequent documentation-only
commit. CI results above refer to the tested source commit, not a release tag.

## Remote packaged-binary rehearsal

Artifact: `dorad-v1.1.0-dev-linux-amd64`, built by CI from `b167f62`.

- Binary SHA-256: `002ef75760cd756dc15da2c82d03d3de0bb851f25b5f98053355ba10e357f952`
- Archive SHA-256: `2bcdb780035e281b787d8c785d4217ce3bd32caaaa85afbbb69935f7392b7f42`
- Result: **PASS**, 89 successful transactions and 6 expected rejection checks.
- Local evidence: `review-records/pqcauth-followup-20261027/ci-artifact-8rounds/evidence/`
  under the operator's DoraFactory workspace.

| Check | Observed result |
| --- | --- |
| SDK-keyring enrollment and offline bundle transfer | Pass |
| Signing-key rotation | New factor transfers successfully; old factor and pre-rotation bundle rejected |
| Recovery-key rotation | Replacement recovery factor works; retired factor rejected |
| Recovery cancellation | Current signing factor cancels; cancelled replacement does not activate after its old deadline |
| Recovery activation | Replacement rejected while pending, activates after delay, then transfers successfully |
| Restart during pending recovery | Four validators resume and complete the scheduled recovery |
| Post-recovery controls | Previous signing factor and classic-only send rejected |
| Mixed traffic | 8 rounds, 80 successful transfers: 64 native ML-DSA, 8 classical, 8 hybrid |
| Validator outage | One of four validators offline for rounds 1–2; network continues; node rejoins for round 3 |
| State agreement | Equal AppHashes on all four nodes after lifecycle and load phases |
| Funds accounting | Recipient increased by exactly 149 peaka across all transfer cases |
| Budget under load | Native transfers occupied 16 blocks with four native verifications each, matching the test cap |

Rejections are checked against their expected errors; they include CLI and
CheckTx rejection, not six failed committed transactions. The load phase took
56.72 seconds on the remote host. This is a bounded traffic/failure regression,
not a throughput benchmark, a long-duration soak, or a Byzantine-network proof.
Recovery delay (12 blocks) and budgets (4 per transaction/block) were reduced
only in synthetic genesis. Production defaults were not changed.

After the remote rehearsals, all processes started by the test drivers had
stopped. The two pre-existing dorad processes remained running. The host had
98 GiB free disk and 56 GiB available memory; no production node was restarted.

Reproduce on a Linux host with free ports and sufficient resources:

```sh
python3 scripts/rehearse-pqcauth-lifecycle.py \
  --binary /absolute/path/to/dorad-v1.1.0-dev-linux-amd64 \
  --work-dir /absolute/path/to/a-new-isolated-directory \
  --rpc-port 47757 --rounds 8
```

The script always creates a synthetic chain and keys. It accepts no public RPC
or existing wallet argument. Ports are loopback-only. CI runs four load rounds
per architecture; remote extended validation ran eight.

## Previously upgraded mainnet snapshot: packaged binary check

The same CI binary resumed the previously isolated
`pqc-v110-snapshot-20261020` four-validator network. This follow-up checks
packaged-binary compatibility with that existing upgraded snapshot; it does
**not** claim to repeat the v1.0.0 → v1.1.0 upgrade or download a new snapshot.

- Startup agreement at state height **17,852,363**.
- Transfer succeeded at **17,852,365**, code 0:
  `91A85F95A903016DBC6B6598A92D6E82B104ABEF2E3CBC7BD0B34A0C9909CDF0`.
- After another full restart, four nodes agreed at **17,852,368**.
- All **18 IBC channel records** and **3 Wasm raw-query samples** matched the
  earlier snapshot evidence. Enforcement remained OPTIONAL.

These transactions are on isolated networks and have no public explorer URL.
Full-store root and feegrant-index checks belong to the earlier
[2026-10-20 validation](PQCAUTH-VALIDATION-20261020.md), not this sampled follow-up.

## Failure → correction → retest

- Earlier GitHub CI failed in both Docker architecture jobs because the
  prerelease flag was absent. Repair above: both jobs passed in run 40426002766.
- First rehearsal script attempt stopped before key creation: `keys add`
  does not support the `-o` shorthand. Replaced it with `--output`; retained
  the failure log, then successfully ran the fixture and the CI artifact in
  separate fresh directories. No module runtime fix was needed.
- Downloading the CI artifact initially hit a TLS handshake timeout. Retried
  the read-only download and matched the archive SHA-256 before execution.
- A public-testnet node-info read timed out with incomplete JSON and is not
  treated as version evidence. Its PQCAuth REST path returned HTTP 501; that
  is not a successful public-testnet acceptance check.

## Remaining gates — not completed by this follow-up

| Gate | Required evidence / decision |
| --- | --- |
| Public testnet activation | Final approved binary, governance plan/height, validator coordination, actual activation and restart |
| Public testnet account lifecycle | Registration, both rotations, delayed/cancelled recovery, offline send; public transaction hashes and precise outcomes |
| Live IBC | Classical and hybrid transfers out/return, acknowledgments, timeout refund where practical; counterparties and relayer versions recorded |
| Physical Ledger | Sign actual owner transactions through the hardware device; never export its seed; current tests cover SDK record types and acknowledgment guards only |
| Independent security review | Review final integrated source, resolve findings, and retest; this author follow-up is not independent sign-off |
| Extended performance / adversarial testing | Sustained load at proposed production budgets, measured resources, invalid proposer behavior and network faults |
| Formal release | Freeze final source/artifacts, approve identity/checksums and deployment plan; development CI artifacts are not a published release |

Keep initial enforcement **OPTIONAL**. Classical and all-ML-DSA SDK composite
multisigs still cannot enroll PQCAuth and are rejected by global REQUIRED mode.
This limitation is intentional and has not been silently relaxed.

Use separate fresh signing/recovery mnemonics. Local reuse checks and Ledger
acknowledgment do not prove global mnemonic independence. Existing key recovery
must remain available for users to rotate away from unsafe factors.
