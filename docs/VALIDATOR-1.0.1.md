# v1.0.1 validator and client preparation

Status: development candidate; not a published release or approval to upgrade a live network.

This coordinated upgrade fixes IBC MsgTransfer Amino signatures which omit the
new `use_aliasing` flag when false. It does not add PQCAuth, upgrade IBC-Go to a
new upstream release, change transfer routing, migrate IBC state, or add stores.
Although this is a patch release, signature acceptance changes consensus and
requires an agreed on-chain activation height across validators.

## Identity and staging

The on-chain plan, release tag, binary version and Cosmovisor directory must all
be **v1.0.1**. The height is chosen by governance; it is not hard-coded here.
Only Linux amd64 is covered by the current build evidence.

Once the final release has been published and independently verified:

1. Verify the final source commit, binary SHA-256 and `dorad version --long`.
   The development binary in the implementation report is not the final release.
2. Back up node configuration and validator state using the operator's existing
   procedure. Never run two signing instances with the same validator key.
3. Stage the binary at `$DAEMON_HOME/cosmovisor/upgrades/v1.0.1/bin/dorad` and
   make it executable. Keep the current process on v1.0.0 until the halt.
4. Confirm the supervisor actually runs Cosmovisor, with the correct DAEMON_HOME,
   DAEMON_NAME=dorad and restart settings. Creating the directory alone does not
   configure automatic switching. Do not point `current` at v1.0.1 early.
5. Read the chain's upgrade plan and verify its name and height against the
   published proposal. After the old binary halts at height H, its committed
   database should be at H-1 and `data/upgrade-info.json` should match that plan.
6. Switch through the configured supervisor. The v1.0.1 startup guard checks the
   committed chain plan and the local halt file. A local file alone is not enough.
   Do not bypass a rejection with `--unsafe-skip-upgrades` or edit database keys.
7. Check new blocks, voting participation, peer synchronization, binary identity,
   archive queries and IBC acknowledgements. Test restart after activation.

The handler returns the existing module version map without RunMigrations.
The SDK records upgrade completion and normal protocol-version metadata.
Existing IBC/Wasm stores are not migrated by this handler. Fresh chains initialized
with this binary receive a separate activation marker in the existing upgrade
store; existing chains use the SDK's completed-upgrade record instead.

## History, restoration and rollback

This binary does **not** dispatch historical signature rules by block height.
Replay pre-upgrade history with the appropriate historical binaries. In particular,
start from an existing v1.0.0 snapshot with the v1.0.0 binary, execute up to the
v1.0.1 halt, then switch. Do not use v1.0.1 to replay old genesis or old blocks.
Cosmovisor does not reconstruct the correct historical binary sequence by itself.

The guard rejects an existing pre-activation database except at the verified
H-1 boundary. After activation it permits restart using the committed completion
record even if the local halt file is absent. A snapshot/state-sync provider must
serve a compatible state containing the completed-upgrade record; state sync has
not been accepted by the present rehearsal.

After v1.0.1 commits state, do not roll back only the binary against that database.
A recovery plan must preserve validator signing safety and coordinate chain state;
there is no claim of an automatic downgrade path.

## Wallets and integrations

- For false, Amino signing JSON must **omit** `use_aliasing`. Ordinary Keplr-format
  Amino IBC signing is the compatibility target. Explicit true stays signed.
- v1.0.0 CLI or custom Amino converters that explicitly sign false must be updated.
  Old pre-signed transactions containing false must be re-created and signed.
- Direct signatures remain unchanged for both true and false.
- Do not deploy the old browser workaround which injects false. Any such deployed
  workaround must be removed in coordination with the chain upgrade.
- A new node binary does not prove hardware-wallet, Skip Swap, counterparty or
  relayer acceptance. Those require their own end-to-end tests.

See [UPGRADE-REPORT.md](ibc-amino-compat/UPGRADE-REPORT.md) for executed checks and
remaining release gates. The PQCAuth development branch must receive this fix and
activation compatibility before its eventual release; this branch does not change it.
