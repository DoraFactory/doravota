# PQCAuth governance and load regressions — 2026-11-02

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Historical scope

Implementation baseline: `1997bcdac2998584ca5d42169976110d5e927880`; test record: `59dddd8`. This round used the old 16/400 quotas and pre-optimization recheck behavior. Neither describes the current implementation.

Real FinalizeBlock, governance tally, EndBlock and Commit paths covered 20 combinations of two pause modes, presence/absence of an ordinary pending schedule, and five message orders through height 24. Two additional cases used signed proposal, deposit and vote transactions. The 20 fixture cases did not each conduct a live voting period.

The observed same-block cancellation difference was subsequently fixed; see [same-block emergency protection](PQCAUTH-SAMEBLOCK-EMERGENCY-FIX-20261102.md).

## Old-quota load results

Using 750 verification gas, quotas 16/400, block gas 600 million, block bytes 10 MB and a four-block recovery delay, the tests admitted 200 native and 200 hybrid noise transactions plus recovery/cancellation and an ordinary transfer.

Recovery placed after exhausted quota was omitted. Moving recovery first allocated its two verification slots before noise; cancellation similarly needed one slot. Six blocks executed 2,405 successful transactions in total. This demonstrated ordering-dependent recovery delay under that quota, not fairness or reserved capacity.

Invalid-admission checks included 300 New, 300 artificial Recheck and 100 simulation calls, plus final-execution rejection and a subsequent valid transaction. These were direct ABCI tests, not real mempool retention or a network DoS bound.

## Verification evidence

Recorded: 767 passing test/subtest events across 14 packages, three simulations, seven Python tests, 906 IBC source checks and vet. Four entry points repeated three times passed in 13.30 s with peak RSS 260,980 KiB and no swap. Across 18 load blocks, Finalize/Commit took 102–155 ms and 402 CheckTx calls took 93–138 ms. These were shared-host in-memory measurements.

Original local logs:

- `/tmp/pqcauth-governance-load-gate-20261102.log`
- `/tmp/pqcauth-governance-load-gate-20261102/{unit,simulations}.jsonl`
- `/tmp/pqcauth-governance-load-vet-20261102.log`
- `/tmp/pqcauth-governance-load-repeat-20261102.log`
- `/tmp/pqcauth-governance-load-resource-20261102.log`

No final-artifact snapshot or multi-node capacity acceptance was established by this record.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-GOVERNANCE-LOAD-TESTS-20261102.md). Raw evidence was not modified.
