# SDK 0.53 bridge fixes — 2026-09-11

Historical English summary; not current deployment instructions or a new audit. See the [documentation index](../README.md) for current guidance.

Based on bridge revision `6d03e3b`; changes were local and unpushed when recorded.

- Made the read-only empty-IAVL compatibility view independent of upgrade-info.json. Missing keys remain missing and corrupt roots still fail. Fixed version-key parsing when a version byte equals a separator.
- Replaced duplicate ICA controller wrapping with one middleware layer, retaining the then-configured callback/ICS4 wiring.
- Updated release builds to use go.mod's Go version, matching WasmVM 3.0.7 static libraries and pinned checksums, plus architecture-specific startup/init and loader checks.
- Isolated simulation home/cache directories, VM cleanup, deterministic chain IDs and seed handling. CI required explicit PASS events for all three simulations.
- Excluded the old-SDK proof tool from normal package compilation using its build tag.

Empty-root regressions and the full test suite passed. Three explicit simulations passed with seed 42, ten blocks, block size five and commits enabled. A 100-block run hit the upstream empty-validator-set skip condition: it was not a successful 100-block validation. Local build, script syntax, YAML and diff checks passed.

[Recorded test logs](fixes-2026-09-11/). Docker was unavailable, so Linux AMD64/ARM64 release execution remained unverified. ICA compilation/simulation did not establish old-channel handshake/callback compatibility. Snapshot, restart and production-business acceptance remained outstanding.

[Original detailed record](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/security/sdk-053-bridge-fixes-2026-09-11.md). Raw evidence is unchanged.
