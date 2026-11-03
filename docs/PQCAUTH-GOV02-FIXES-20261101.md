# PQCAuth explicit governance intent — 2026-11-01

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `23dfcf89cc8ebe356b2c87bf3147a1c5bf145706`. GOV-02 arose when cancelling ordinary restrictions while retaining a pause was mistaken for renewing that pause. Gas, authentication and the then-existing 16/400 quotas were unchanged.

## Reproduction and fix

A real keeper/MsgServer/IAVL overlay tested six cases: NORMAL controls cancelled correctly; both pause modes, with/without queued CLOSED, returned success but still activated REQUIRED/CLOSED at H=110. Expected cancellation assertions failed. Log: `/tmp/pqcauth-gov02-review.XfWf4n/result.log`. This was not a governance-vote or cryptographic execution test; its account keeper was a test double.

`MsgUpdateParams` gained `bool emergency_only = 3`. Omitted/false means full update; true explicitly selects the H+1 emergency-only path. Matching active values cancels a cancellable ordinary plan, retaining the pause and its original expiry, with response activation 0. A new full update replaces the ordinary bundle under its delay rules. True renews/releases/changes emergency state while preserving ordinary fields and activation. Non-emergency fields must match the complete active or pending set.

Authority, immutable-field validation, then-existing cutoff commitments, no-early-activation and internal-expiry restrictions remained. An ordinary replacement scheduled after the retained pause expires stores NORMAL, avoiding pause resurrection. A full update can change emergency mode but retains full-bundle semantics; it is not the fast path.

## API and regression coverage

Response field `resulting_params = 2` reports actual saved state. `emergency_only` belongs beside `authority`/`params`, not inside Params. Clear `pending`, `pending_activation_height`, `pending_emergency` and `emergency_expires_height` when building a request. Old omitted-field clients now get full-update semantics; previously inferred emergency requests must explicitly set true.

Tests covered six cancellation cases, renewal then cancellation, smuggled fields, cutoff irreversibility, expiry ordering, original 72 GOV-01 combinations and protobuf/JSON/sign-byte differences. Generated tx code used gogoproto v1.7.2. No dedicated interactive CLI was added.

Recorded Go 1.26.10 results: 741 test/subtest passes, 14 packages, three separately enabled simulations, seven Python tests, 906 IBC sources, vet and local build. Logs: `/tmp/pqcauth-gov02-gate-final.log`, `/tmp/pqcauth-gov02-gate-final/{unit,simulations}.jsonl`, `/tmp/pqcauth-gov02-{vet,build}.log`. `pqcauth-gov02-first.log` records old tests not yet switched to explicit true; it is not success evidence.

No public-chain work or final-artifact load/snapshot acceptance was performed. This changed consensus message/execution semantics. Same-block behavior was later tightened by [G-1](PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md); cutoff and quotas were later removed.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-GOV02-FIXES-20261101.md). Original evidence files were not translated or modified.
