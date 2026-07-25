package app

import (
	wasm "github.com/CosmWasm/wasmd/x/wasm"
	wasmexported "github.com/CosmWasm/wasmd/x/wasm/exported"
	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/wasmguard"
)

// sponsorAwareWasmMirroredConsensusVersion is the wasmd consensus version whose
// RegisterServices migrations are mirrored below. A parity test intentionally
// fails when wasmd is upgraded so the wrapper cannot silently omit migrations.
const sponsorAwareWasmMirroredConsensusVersion uint64 = 4

// sponsorAwareWasmAppModule preserves the upstream Wasm AppModule behavior
// while registering a guarded MsgServer for the contract-admin lifecycle.
type sponsorAwareWasmAppModule struct {
	wasm.AppModule
	keeper         *wasmkeeper.Keeper
	legacySubspace wasmexported.Subspace
	sponsorState   wasmguard.SponsorStateReader
}

func newSponsorAwareWasmAppModule(
	base wasm.AppModule,
	keeper *wasmkeeper.Keeper,
	legacySubspace wasmexported.Subspace,
	sponsorState wasmguard.SponsorStateReader,
) sponsorAwareWasmAppModule {
	return sponsorAwareWasmAppModule{
		AppModule:      base,
		keeper:         keeper,
		legacySubspace: legacySubspace,
		sponsorState:   sponsorState,
	}
}

// RegisterServices mirrors wasmd v0.45.0 AppModule.RegisterServices, replacing
// only the MsgServer with the Sponsor-aware wrapper. Keep the migration
// registrations synchronized when the wasmd dependency is upgraded.
func (am sponsorAwareWasmAppModule) RegisterServices(cfg module.Configurator) {
	upstreamMsgServer := wasmkeeper.NewMsgServerImpl(am.keeper)
	wasmtypes.RegisterMsgServer(
		cfg.MsgServer(),
		wasmguard.NewMsgServer(upstreamMsgServer, am.sponsorState),
	)
	wasmtypes.RegisterQueryServer(cfg.QueryServer(), wasmkeeper.Querier(am.keeper))

	migrator := wasmkeeper.NewMigrator(*am.keeper, am.legacySubspace)
	if err := cfg.RegisterMigration(wasmtypes.ModuleName, 1, migrator.Migrate1to2); err != nil {
		panic(err)
	}
	if err := cfg.RegisterMigration(wasmtypes.ModuleName, 2, migrator.Migrate2to3); err != nil {
		panic(err)
	}
	if err := cfg.RegisterMigration(wasmtypes.ModuleName, 3, migrator.Migrate3to4); err != nil {
		panic(err)
	}
}
