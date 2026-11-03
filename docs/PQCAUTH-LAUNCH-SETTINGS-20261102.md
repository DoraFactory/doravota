# PQCAuth launch settings — 2026-11-02

Historical English summary. Results belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

## Decisions and scope

Baseline: `26d15bb9adabca372cfff6e11fa8cf4e8ed98bb6`.

| Setting | Approved value |
| --- | --- |
| Recovery delay | 107,520 blocks (approximately seven days at the observed block interval) |
| Maximum emergency duration | 46,080 blocks (approximately 72 hours) |
| Governance safety delay | 17,280 blocks (approximately 27 hours) |
| Phase-one registration | OPEN only |
| Global REQUIRED enforcement | Disabled |

These are block counts, not wall-clock guarantees. Existing explicitly stored legal delays were not silently rewritten. Incompatible experimental states were not supported as drop-in upgrades.

This round still retained two verification-price fields and the 16/400 quotas. Those were subsequently replaced/removed; see [parameter simplification](PQCAUTH-SIMPLIFICATION-20261102.md).

## Recorded verification

Go 1.26.10: 831 passing test/subtest events across 14 packages, three explicit simulations, seven Python tests, 906 IBC source checks, vet, build and race checks.

The recovery regression admitted an old-policy recovery before a protection change committed. The next recheck evicted it while the policy change was pending; final execution also rejected it without changing balance, sequence or policy. Artificially rechecking already-evicted bytes later does not represent normal mempool retention.

A four-validator rehearsal recorded 132 successful transactions and six expected rejections, ending at height 127 with matching state:

```text
C03A4BF764BF997836F506098743E32CB642585EF57A6997077549E46BC6EBF7
```

The development binary was `/tmp/pqcauth-launch-settings.h4Fw1h/dorad`, SHA-256:

```text
ee3ce51cafccbc79697a577b502c821c7e88e932f6e39b7402b8011c3c0c91d6
```

Logs were under the same directory: `gate-final.log`, `gate-final/{unit,simulations}.jsonl`, `vet.log`, `race.log`, and `four-validator/evidence/`.

The rehearsal used a 12-block recovery delay and reduced signer/budget settings; it did not wait seven days or run the 5,000-transaction capacity test. No new production snapshot, public IBC or physical-wallet acceptance was completed in this round.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-LAUNCH-SETTINGS-20261102.md). Raw evidence was not modified.
