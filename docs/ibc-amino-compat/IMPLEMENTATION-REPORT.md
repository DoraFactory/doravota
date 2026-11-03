# IBC Amino compatibility: initial implementation — 2026-10-28

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

Baseline v1.0.0: `1a2b30927a7799d4cd6890a3fb3fa80d25613fa2`. This first stage had **no activation handler**; [the subsequent upgrade report](UPGRADE-REPORT.md) supersedes that implementation-stage limitation.

The pinned upstream source was IBC-Go `v11.0.0-20260929073332-7b1838a13bc4`, not the nominal require version or latest main. The local module snapshot contained 906 files, with two patched upstream files:

1. Remove amino.dont_omitempty from MsgTransfer.use_aliasing (field 10).
2. Regenerate the protobuf descriptor bytes in tx.pb.go.

Amino false is omitted; true remains signed. DIRECT/protobuf encoding, field number, routes, state and aliasing functionality remain unchanged. An old Amino signature explicitly containing false is rejected under the new rule: this is a **consensus signing-rule change**, not an RPC display fix.

[Patch](upstream.patch), [source manifest](upstream-manifest.json), and scripts verify the exact two-file delta. Official proto-builder 0.18.1 regeneration matched byte-for-byte; descriptor comparison showed only the intended option removed.

Remote Go 1.26.5/Linux AMD64 checks passed: four baseline vectors, expected failure on unpatched dependency, compatibility/CheckTx tests, root and transfer-package tests, vet, CGO-disabled build, integrity check, regeneration and buf breaking. A successful breaking check did not mean consensus semantics were unchanged. Optional simulations, hardware wallets, ARM64 and race checks were not claimed.

[Remote evidence](evidence/remote/), including status.tsv and failed preparation attempts. Review binary SHA-256: `3bd15aec3cda83598f902ae9f856662265b1abbb9b8eeb9dd4afe4150632035c`; its label explicitly identified uncommitted review code.

No wallets, public broadcasts, production services, tags or releases were used. CheckTx used deterministic test keys without a counterparty channel, so it did not prove IBC delivery. Coordinated activation, historic replay strategy, real wallets/Ledger and cross-chain business remained separate work. A browser workaround that inserts false conflicts with this signing contract.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/ibc-amino-compat/IMPLEMENTATION-REPORT.md). Raw evidence is unchanged.
