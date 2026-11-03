# IBC Amino v1.0.1 activation and remote rehearsal — 2026-10-28

Historical English summary. Results apply only to the recorded artifact and environment; see the [documentation index](../README.md) for current guidance.

This historical uncommitted candidate added activation, startup checks and a four-validator upgrade to the [initial Amino fix](IMPLEMENTATION-REPORT.md). It did not add PQCAuth, change the pinned IBC patch or authorize production deployment.

## Activation boundaries

- v1.0.1 handler required the existing v1.0.0 Wasm archive activation and returned the module version map unchanged, without RunMigrations or new stores.
- Before BaseApp, read-only preflight verified the committed upgrade tree/root. A local halt file alone could not authorize early startup.
- Old state required the correct on-chain plan, H−1 database boundary, matching halt information and no skip. Committed completion allowed later restart without the halt file.
- Fresh genesis used a separate application marker; this was not a shortcut for replaying old chain history.
- PreBlock checked activation before module execution.

No module migration does not mean no database bytes change: normal upgrade plan/completion/protocol metadata still update. Historical replay requires historical binaries; no height-segmented old signing rules were implemented.

## Recorded tests

Go 1.26.5/Linux AMD64, isolated containers with loopback-only nodes and test keys: root/transfer tests, vet, build, signature vectors, expected unpatched failure, compatibility/tamper tests, 12 startup-boundary cases, actual keeper lifecycle, explicit simulations, release gates and 906-file integrity checks passed.

Four validators voted through a test upgrade at height 85. A forged early local plan failed startup. New nodes resumed, transferred funds and restarted successfully after all upgrade-info files were moved away. Hashes agreed at heights 87 and 92.

[Upgrade evidence](evidence/upgrade/), [rehearsal result](evidence/upgrade/rehearsal/result.json) and [source fingerprints](evidence/upgrade/source-manifest.sha256). Binary SHA-256: `cab41596bbd4da16b24c09ad7280831bef15fb3be8a3e3f59fbd34c27bae8103`, explicitly an uncommitted review build.

Initial failures in iterator-end handling, test HeaderInfo and the script's account wrapper parsing were retained in the evidence; they were corrected and rerun, not counted as passing attempts.

This was a fresh isolated chain with manual process switching, not a production snapshot or Cosmovisor/systemd automation test. GitHub Actions, real Keplr/Ledger, actual counterparties/Skip routes, ARM64, race/load and production state-sync acceptance were not completed in this round. Later operator guidance: [VALIDATOR-1.0.1](../VALIDATOR-1.0.1.md).

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/ibc-amino-compat/UPGRADE-REPORT.md). Raw evidence is unchanged.
