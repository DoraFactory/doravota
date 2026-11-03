# SDK 0.53 in-flight IBC and deployed Wasm rehearsal — 2026-09-11

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

A separate four-validator fork of snapshot height 17,249,823 upgraded at 17,250,384 through test proposal 20. Candidate review5 SHA-256: `066360c4ff46696bb41162b7ce5a505e58325311a3b73fefef07a90f5057bfe1`. Test validator keys, funding and governance settings were isolated; no production-code changes were made for this round.

## Cross-upgrade packets

A controlled channel was created before upgrade. Relaying was paused to leave packets/acknowledgements in flight, then resumed after migration.

- 7 DORA already received: acknowledgement completed without duplicate credit.
- 10 DORA not yet delivered: received and acknowledged after upgrade.
- 20 DORA timed out: refunded using a timeout proof.
- 30 DORA to an invalid receiver: error acknowledgement caused refund.
- 40 counterparty test tokens inbound: received as the correct voucher.
- Return transfers restored principal, cleared commitments and zeroed test vouchers; fees/delegation were separately accounted.

An additional replay attempt had already expired and returned channel/code 40. It was **not** evidence of unexpired duplicate rejection. Controlled new channels did not establish real legacy Cosmos Hub/Osmosis/Noble path acceptance.

## Existing aMACI contracts

The original registry (address ending rmgg4, code 152) and round code 153 were used without upload, migration or forged administrator signatures. Eight contracts / 57 queries matched. An old round accepted another signup and a synthetic message; the registry created rounds before/after upgrade. Unauthorized administration and missing-fee execution were rejected without the checked state changes. Cold-cache restart preserved queries.

Synthetic message acceptance did not establish decryptable ballots, Groth16 processing, tally, settlement or claims. Measured creation gas changed from 890,714 to 911,015 and signup from 394,032 to 436,036, but differing state/inputs prevent treating these as controlled performance ratios.

Four nodes agreed at 17,250,474. This was not a 24-hour observation.

[Public evidence and staged scripts](sdk-053-inflight-rehearsal-2026-09-11/). Scripts depend on previous stages and are not safe recipes to rerun on an existing home. Private keys/keyrings are not included.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/upgrades/sdk-053-inflight-wasm-2026-09-11.md). Raw evidence is unchanged.
