# PQCAuth round-four fixes — 2026-11-01

Historical English summary. Results below belong to the recorded revision, not current release acceptance. Current behavior: [module README](../x/pqcauth/README.md).

Baseline: `c2927448af4e41ed811822d5a3374f1466a4672d`. Implementation: `b26badc38c85d6785789ce45a4fe130095c3a24e`; smoke-test port isolation: `e10e9851ce144e264c046fc9515684f642e9a545`. The custom selector described here was subsequently removed.

## Selection and dependency changes

Over-budget candidates were skipped and their actual SDK signers, including independent fee payers, entered a local blocked set. Blocking propagated through shared signers; unrelated transactions remained eligible. A fee granter was not automatically a signer. When effective parameter limits rejected inspection, Prepare retried within absolute 256 KiB / 32-entry bounds to distinguish tightened limits from invalid structure/public keys. Omitted candidates never committed discovered keys. Process used strict effective limits, without this retry.

This was not full Ante replay, cross-account business-dependency analysis or a fairness guarantee. Native ML-DSA's 750 floor was unchanged; the proposed DORA/day attack estimate was not presented as measured cost.

Real signed tests covered independent transfers after budget exhaustion, transitive signer/fee-payer dependencies, H-1 admission followed by H parameter activation, and poisoning isolation. An overlay restoring only the old proposal selector failed all six expected subcases.

## Dependency/build changes

- Actual Go build/test toolchain: 1.26.5 → 1.26.10; x/net: 0.58.0 → 0.62.0.
- OTel log components: 0.20.0 → 0.21.0; matching core/exporters 1.45.0; otelslog 0.20.0 and otelconf 0.25.0 for API compatibility.
- Pion DTLS 3.1.4, STUN 3.1.5 and transport/v4 4.0.2; checksums resolved normally.
- Release artifacts gained actual `go version -m` build information. Smoke tests disabled unused API/gRPC and used ephemeral loopback ABCI ports, without changing node defaults or stopping existing services.

Original advisory references: [Go releases](https://go.dev/doc/devel/release), [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617), [GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860), [GO-2026-6866](https://pkg.go.dev/vuln/GO-2026-6866), [OTel TLS](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-w34q-cm8f-9c5x), [OTel CPU](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-hjf4-fphr-2h65), [STUN](https://pkg.go.dev/vuln/GO-2026-6163), [DTLS](https://pkg.go.dev/vuln/GO-2026-6165). These are the historical record's references, not a fresh vulnerability assessment.

## Recorded validation

607 test/subtest passes, 14 packages, three explicit simulations, seven Python tests and 906 IBC files; vet and module verification passed. Twenty-second wire fuzz: 101,106 executions. Source symbol scans with govulncheck v1.9.0 used the 2026-10-27 database, including a release-equivalent CGO-disabled scan. Peak RSS was about 7.6 million KiB. Scan exit 0 did not mean zero findings; stripped-binary scanning used a conservative module fallback, not confirmed call paths.

Binary `release/dorad-v1.1.0-dev-linux-amd64`, embedded commit `e10e9851ce144e264c046fc9515684f642e9a545`:

- Binary SHA-256: `03ed39d02984f9872b968a99ad6b482ede6b37296a043b73695d8d07309d17d9`.
- Archive SHA-256: `8e28ef5170b5240e12656b1a508a78fa38972d5907b98e96e49613b32232cb0f`.
- Extracted archive binary matched. Build info confirmed the patched versions.

That same artifact passed a synthetic four-validator lifecycle run with 92 successful transactions and six expected rejections. Final height 110 AppHash: `79A5AC4D28092E2B5E9C73C474AC4924877D33DCEB1CF6AF6C90852886FA5412`. The group was limited to two cores/7 GiB, no swap, loopback only. Evidence: `/tmp/pqcauth-round4-rehearsal.j0aGGt/network/evidence/`. Node homes/keyrings were not deliverables.

Logs use `/tmp/pqcauth-round4-`: `gate-final.log`, `gate-final/{unit,simulations}.jsonl`, `old-behavior.log`, `old-overlay.json`, `vet.log`, `mod-verify.log`, `fuzz.log`, `vuln-package-final.json`, `vuln-symbol.json`, `vuln-release-source.json`, `vuln-binary.json`, `build-final.log`, `lifecycle.log`. Early OTel compilation, changing-script EOF and port-conflict attempts were failures, not final acceptance evidence.

## Residual risk and scope

GO-2023-1821/1881 and GO-2025-3442 were module-level warnings without source package/symbol hits in that scan. Existing CometBFT checks were inspected, not tested against a malicious blocksync network. GO-2026-5932 remained: ten source-symbol records in SDK encrypted-key import/export via deprecated OpenPGP packages; no known patched upstream version was claimed.

No signature domain, algorithm or public deployment changed. This artifact did not receive a new mainnet-snapshot, public IBC or physical Ledger rehearsal; ARM64/Docker results were left to CI. The dependency patch was not a blanket closure of all dependency or mainnet deployment risks.

[Original detailed record at the documentation-cleanup baseline](https://github.com/DoraFactory/doravota/blob/eb5bbec2a88a36224bd27c5b487f3d726a6bfeda/docs/PQCAUTH-ROUND4-FIXES-20261101.md). Original evidence files were not translated or modified.
