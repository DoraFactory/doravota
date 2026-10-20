package app

import (
	"context"
	"fmt"

	"cosmossdk.io/core/address"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	feegrantkeeper "github.com/cosmos/cosmos-sdk/x/feegrant/keeper"
	feegrantmodule "github.com/cosmos/cosmos-sdk/x/feegrant/module"

	pqcauthkeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
)

// pqcauthFeegrantAppModule preserves the SDK feegrant module behavior while
// making every MsgServer mutation update pqcauth's granter index atomically.
type pqcauthFeegrantAppModule struct {
	feegrantmodule.AppModule
	feegrantKeeper feegrantkeeper.Keeper
	pqcauthKeeper  pqcauthkeeper.Keeper
	addressCodec   address.Codec
}

func newPQCAwareFeegrantAppModule(
	appCodec codec.Codec,
	accountKeeper feegrant.AccountKeeper,
	bankKeeper feegrant.BankKeeper,
	moduleKeeper feegrantkeeper.Keeper,
	registry cdctypes.InterfaceRegistry,
	pqcKeeper pqcauthkeeper.Keeper,
) pqcauthFeegrantAppModule {
	return pqcauthFeegrantAppModule{
		AppModule: feegrantmodule.NewAppModule(
			appCodec,
			accountKeeper,
			bankKeeper,
			moduleKeeper,
			registry,
		),
		feegrantKeeper: moduleKeeper.SetBankKeeper(bankKeeper),
		pqcauthKeeper:  pqcKeeper,
		addressCodec:   accountKeeper.AddressCodec(),
	}
}

func (am pqcauthFeegrantAppModule) RegisterServices(configurator module.Configurator) {
	inner := feegrantkeeper.NewMsgServerImpl(am.feegrantKeeper)
	feegrant.RegisterMsgServer(
		configurator.MsgServer(),
		pqcauthkeeper.NewFeegrantMsgServer(
			inner,
			am.pqcauthKeeper,
			am.addressCodec,
		),
	)
	feegrant.RegisterQueryServer(configurator.QueryServer(), am.feegrantKeeper)
	migrator := feegrantkeeper.NewMigrator(am.feegrantKeeper)
	if err := configurator.RegisterMigration(feegrant.ModuleName, 1, migrator.Migrate1to2); err != nil {
		panic(fmt.Sprintf("failed to migrate x/feegrant from version 1 to 2: %v", err))
	}
}

func (am pqcauthFeegrantAppModule) EndBlock(ctx context.Context) error {
	if err := am.AppModule.EndBlock(ctx); err != nil {
		return err
	}
	return am.pqcauthKeeper.PruneExpiredFeegrantIndexForBlock(
		sdk.UnwrapSDKContext(ctx),
	)
}
