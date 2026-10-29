# IBC-Go Amino compatibility snapshot

This review snapshot is the exact Go module distribution of
`github.com/cosmos/ibc-go/v11@v11.0.0-20260929073332-7b1838a13bc4`, the effective
IBC dependency of Dora Vota `v1.0.0`, with only two patched files:

1. `proto/ibc/applications/transfer/v1/tx.proto`: remove `amino.dont_omitempty`
   from `MsgTransfer.use_aliasing` (field 10).
2. `modules/apps/transfer/types/tx.pb.go`: regenerate its embedded descriptor.

The module path, dependencies, LICENSE, NOTICE, Go sources, tests, proto sources,
and build scripts are preserved. Upstream `docs/**` and PNG assets are omitted
to avoid importing 32 MiB of documentation unrelated to the build. This is a
Go module distribution, not a full upstream Git checkout (separate upstream
Go modules such as simapp are not included by the Go module proxy).

The root `go.mod` uses a local replace so a clean checkout can build this fix
without modifying a shared module cache or depending on an unpublished fork.
The 906-file snapshot is unchanged except for the two files above. Review the
compact `docs/ibc-amino-compat/upstream.patch`, and verify all source hashes with
`python3 scripts/verify-ibc-amino-snapshot.py`.

Regenerate/compare with `sh scripts/regenerate-ibc-amino.sh`, using upstream
proto-builder 0.18.1 or compatible buf and protoc-gen-gocosmos v1.7.2. The latter
must be on PATH. `--write` explicitly updates the generated Go source.

This changes consensus signature acceptance. It is NOT an RPC-only patch.
The application now registers the v1.0.1 coordinated upgrade and checks committed
activation state before loading an existing database. See
`docs/VALIDATOR-1.0.1.md` and `docs/ibc-amino-compat/UPGRADE-REPORT.md`.
There is no historical signature-rule dispatch: replay old history with the old
binary and switch at the coordinated halt. Never install this development
candidate as the current binary on a live validator. Old Amino signatures
containing explicit `use_aliasing: false` must be regenerated after activation.
Direct signatures and signed `use_aliasing: true` remain unchanged by this patch.

Future dependency updates must preserve the chosen Amino signing contract and
rerun the regression tests. Do not silently revert this patch or remove field 10.
