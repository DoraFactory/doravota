# SDK 0.53 configuration review — 2026-09-12

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Baseline 0.4.4; target `917c53b` plus local corrections. The only production-code change in this round connected SDK SetQueryGasLimit to the real daemon constructor. Default zero remained unlimited; transaction/block gas policy was not changed.

## Important configuration boundaries

- gRPC-Web moved to the API listener, requiring API, gRPC and gRPC-Web enablement. Old standalone address/CORS keys did not restore port 9091 behavior.
- Existing valid local config remained authoritative, but removed Rosetta, file-streamer, IAVL and Comet fields no longer had their old effects. Do not regenerate a production home or replace its entire config.
- app.toml mempool.max-txs changed in templates, but both application constructors still used NoOp mempool.
- query-gas-limit zero meant unlimited SDK queries, distinct from the unchanged 3,000,000 Wasm query limit and 100 MiB Wasm cache.
- Existing consensus values were migrated from upgrade/Consensus, not replaced with genesis values or a 100M fallback.
- Legacy x/params writes did not automatically update parameters migrated into module stores.
- Upgraded-chain policy was not new-genesis policy: only the upgrade handler applied the three approved governance overrides.

The approved migration values were zero min_deposit_ratio, zero proposal_cancel_ratio and 110,000 DORA expedited deposit. SDK defaults for the other new fields remained one-day expedited voting, threshold 0.667 and empty cancellation destination. Ordinary source governance fields stayed unchanged; incompatible expedited/ordinary relationships caused preflight rejection.

## Evidence and unresolved items at that revision

Go 1.24.7/Darwin tests passed, including real constructor/query-context checks for finite/default query meters. Earlier simulations were not counted as rerun. Final Linux builds, snapshot, public clients and long-running business tests were not performed.

A dependency scan found 49 binary symbol-match candidates, **not 49 proven exploitable vulnerabilities**. Historical gRPC/Go advisories required reachability triage and patched final builds. The msgpack bounds-check backport needed source-aware treatment, not automatic classification from version matching. See [scan triage](sdk-053-config-review-evidence-2026-09-12/dependency-scan-triage.json).

The then-current RC version, release notes and upgrade plan also needed alignment; old RC artifact hashes could not identify newly changed source.

[Evidence and source manifest](sdk-053-config-review-evidence-2026-09-12/source-manifest.json). The complete 37 generated-config differences remain in the original [CSV](sdk-053-config-review-evidence-2026-09-12/node-config-diff.csv) and [JSON](sdk-053-config-review-evidence-2026-09-12/node-config-diff.json), preserved byte-for-byte, including original-language annotations. They describe template differences, not live production configuration.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-config-review-2026-09-12.md). Raw evidence is unchanged.
