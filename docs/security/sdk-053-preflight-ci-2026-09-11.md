# SDK 0.53 preflight and candidate CI — 2026-09-11

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Added a read-only candidate workflow for branch/PR/manual validation, uploading AMD64/ARM64 packages and build metadata without publishing a Release or image. Docker and release CI shared the build script. At this point changes were local, Docker unavailable and remote candidate builds had not run.

Before StoreLoader could delete legacy stores at the upgrade boundary, preflight required:

1. Valid committed multistore/IAVL roots.
2. Empty feeibc state and no fee-module balance entries, including anomalous zero-value entries.
3. The expected 0.4.4 module version map, allowing the observed historical crisis=2 entry.
4. A present, decodable, valid legacy upgrade/Consensus record.

The handler rechecked source versions and consensus parameters. Both successful and rejected preflight tests left copied GoLevelDB contents unchanged. Read-only mainnet inspection at 17,250,570 matched the expected version map; this alone did not authenticate the whole database.

Full tests and three explicitly enabled ten-block simulations passed; logs are in [preflight-ci-2026-09-11](preflight-ci-2026-09-11/). Malformed proposals, byte/gas bounds and overflow were covered for the then-present custom selector, but not complete valid-signature sequencing or multi-node behavior. That selector was later removed.

No production migration or broadcast occurred. Independent review, actual Linux artifacts, source-snapshot recovery and legacy ICA/ICS-721 business checks were still required.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-preflight-ci-2026-09-11.md). Raw evidence is unchanged.
