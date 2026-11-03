# Independent PQCAuth audit and re-review — 2026-10-31

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Initial review

Reviewer: Claude, using an independent offline copy of `d3099314cbb14ff7c5a10e167e1c1b0e780ffe12` at `/root/claude-pqcauth-audit-20261031`. Codex's workspace was not modified.

Vet and tests across 14 packages passed. Two parameter defects were reproduced; 500 malformed-input probes did not halt the tested execution. This was not an exhaustive line-by-line audit, long fuzz campaign or four-validator load test.

Confirmed findings in that historical implementation:

- A one-byte extension limit could activate and prevent protected transactions, including disabling protection. Ordinary blocks continued.
- A per-transaction verification quota of one could activate and prevent operations needing multiple proofs.
- Existing authz and feegrant permissions remained effective. PQCAuth did not automatically harden or revoke delegated authority.
- Independently legal verification price/quota combinations could exceed block gas capacity.
- A one-signer extension limit could block protected transactions with an independent protected payer.

These were governance availability/configuration issues and delegation boundaries, not evidence of universal asset theft or deterministic chain halt.

## Re-review

Revision `a2de29d3ede7a2aefd1551543dd7b8a5e2fd391f` was tested in another independent copy. Vet and all 14 package tests passed. Unsafe small parameters were rejected; capacity validation occurred on governance updates rather than scanning every BeginBlock. Client warnings documented delegation without an automatic permission scan.

The five findings were closed within that review's scope. Quota and registration parameters were subsequently removed; their historical limits must not be used as current configuration instructions.

The original signed-off report and amendment are available through the fixed source link below. Hashes quoted in [the fix record](PQCAUTH-AUDIT-FIXES-20261031.md) identify those original records, not this translated summary.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-CLAUDE-AUDIT-20261031.md). Raw evidence was not modified.
