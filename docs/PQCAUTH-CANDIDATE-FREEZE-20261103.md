# v1.1.0 candidate source freeze

Date: 2026-11-03. Branch: `feature/pqcauth-sdk-keyring`.
Reviewed implementation base: `d7d4e64430bf3b8a3dfe7941fa145a986b04a17c`.
The commit introducing this record identifies the frozen candidate source.

## Scope

- Align VERSION, CLI fallback version and the version-identity regression with
  `v1.1.0`. Keep the existing `v1.1.0` upgrade handler and all historical handlers.
- Replace obsolete development release notes with the actual module-version-4
  implementation. Update the module README's candidate identity.
- No changes to authentication, gas pricing, parameters, storage, mempool or
  proposal selection. No release tag, GitHub Release or network deployment.

## Local validation

Toolchain: Go 1.26.10, Linux amd64, pinned dependencies, `GOTOOLCHAIN=local` and
`GOPROXY=off`. Tests are run with `-count=1`, not accepted from the test cache.

- `bash scripts/test-release-candidate.sh`: PASS. Full repository tests report
  816 test/subtest pass events across 14 tested packages; required-test checks
  pass. The four normal-run skips are the opt-in network fixture and three
  simulations; those three simulations are explicitly enabled and pass in a
  separate run. Packages without test files are not counted as tested packages.
- Python release-tool and capacity-harness unit tests: PASS. The pinned IBC
  source check passes for 906 files, with exactly the two approved patch files.
- `go vet ./...`: PASS.
- `go test -race ./... -count=1 -json`: PASS, 816 test/subtest pass
  events across 14 tested packages, no race-detector reports. The same four
  opt-in tests are skipped in this run; simulations are covered separately above.

Raw logs are retained in `/tmp/pqcauth-v110-freeze.y97gdc/` on the validation host.
That path is a local evidence location, not a portable download or a promise of
permanent storage. Artifact build information and SHA-256 must identify the
actual committed source; a version string alone is insufficient.

## Known ordering boundary

The preceding investigation independently reproduced a CometBFT local-client /
mempool insertion-order window with both classic and native ML-DSA transactions.
Sequential CheckTx execution does not guarantee identical insertion order under
concurrent callers. SDK default selection can preserve that reversed order;
sequence validation then rejects dependent transactions during execution.

This is an availability limitation, not evidence of PQCAuth authentication bypass.
The controlled tests showed no fee/transfer committed for the rejected transaction
and a subsequent empty block committed normally. Five fresh four-validator native
load runs and one all-pools control passed at the reviewed base; those finite
passes do not prove the race absent. The historical CI failure's exact thread
schedule was not captured. No upstream-ordering fix is included in this freeze.

Applications should confirm execution, not only CheckTx acceptance, and manage
same-account sequence dependencies. Waiting for confirmation before issuing a
dependent transaction is a client mitigation, not a global ordering fix.

## Remaining acceptance

Source freeze is not production approval. The final release-format artifact must
be identified by commit and SHA-256 and used for lifecycle, supported snapshot
upgrade/restart and public-testnet/IBC acceptance. Prior artifact results remain
historical evidence. Sustained/adversarial capacity tests are deferred to the
intended testnet hardware by project decision; they are not marked passed here.

Do not push the `v1.1.0` tag to start rehearsals: the tag workflow publishes a
GitHub Release. Any subsequent code change creates a new candidate identity and
requires corresponding revalidation.
