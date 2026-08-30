package app

import (
	"bytes"
	"testing"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	"github.com/stretchr/testify/require"

	pqcauthtypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestRunMigrationsInitializesSponsorModuleForExistingChain(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	chainApp := New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		map[int64]bool{},
		t.TempDir(),
		0,
		MakeEncodingConfig(),
		emptyAppOptions{},
		nil,
	)
	ctx := chainApp.BaseApp.NewUncachedContext(
		false,
		tmproto.Header{Height: 1, ChainID: "migration-test-1"},
	)

	store := ctx.KVStore(chainApp.GetKey(sponsortypes.StoreKey))
	require.False(t, store.Has(sponsortypes.ParamsKey))
	pqcStore := ctx.KVStore(chainApp.GetKey(pqcauthtypes.StoreKey))
	require.False(t, pqcStore.Has(pqcauthtypes.ParamsKey))
	feeGranter := sdk.AccAddress(bytes.Repeat([]byte{0x21}, 20))
	feeGrantee := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20))
	chainApp.AccountKeeper.SetAccount(
		ctx,
		authtypes.NewBaseAccountWithAddress(feeGrantee),
	)
	require.NoError(t, chainApp.FeeGrantKeeper.GrantAllowance(
		sdk.WrapSDKContext(ctx),
		feeGranter,
		feeGrantee,
		&feegrant.BasicAllowance{},
	))

	// An existing chain's version map does not contain a newly introduced
	// module. Cosmos SDK must therefore call its default InitGenesis.
	fromVM := chainApp.ModuleManager().GetVersionMap()
	delete(fromVM, sponsortypes.ModuleName)
	delete(fromVM, pqcauthtypes.ModuleName)

	updatedVM, err := chainApp.ModuleManager().RunMigrations(
		ctx,
		chainApp.Configurator(),
		fromVM,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), updatedVM[sponsortypes.ModuleName])
	require.Equal(t, uint64(2), updatedVM[pqcauthtypes.ModuleName])
	require.True(t, store.Has(sponsortypes.ParamsKey))
	require.True(t, pqcStore.Has(pqcauthtypes.ParamsKey))
	require.Equal(t, sponsortypes.DefaultParams(), chainApp.SponsorKeeper.GetParams(ctx))
	expectedPQCParams := pqcauthtypes.DefaultParams()
	expectedPQCParams.NetworkId = pqcauthtypes.NetworkIDForChain(ctx.ChainID())
	require.Equal(t, expectedPQCParams, chainApp.PQCAuthKeeper.GetParams(ctx))
	found, err := chainApp.PQCAuthKeeper.HasOutgoingFeegrant(ctx, feeGranter)
	require.NoError(t, err)
	require.True(t, found)
}

func TestPQCAuthMigrationBackfillsExistingFeegrants(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	chainApp := New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		map[int64]bool{},
		t.TempDir(),
		0,
		MakeEncodingConfig(),
		emptyAppOptions{},
		nil,
	)
	ctx := chainApp.BaseApp.NewUncachedContext(
		false,
		tmproto.Header{Height: 10, ChainID: "pqcauth-feegrant-migration-1"},
	)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x41}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20))
	chainApp.AccountKeeper.SetAccount(
		ctx,
		authtypes.NewBaseAccountWithAddress(grantee),
	)
	require.NoError(t, chainApp.FeeGrantKeeper.GrantAllowance(
		sdk.WrapSDKContext(ctx),
		granter,
		grantee,
		&feegrant.BasicAllowance{},
	))
	found, err := chainApp.PQCAuthKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)

	fromVM := chainApp.ModuleManager().GetVersionMap()
	fromVM[pqcauthtypes.ModuleName] = 1
	updatedVM, err := chainApp.ModuleManager().RunMigrations(
		ctx,
		chainApp.Configurator(),
		fromVM,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(2), updatedVM[pqcauthtypes.ModuleName])
	found, err = chainApp.PQCAuthKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.True(t, found)
	require.NoError(t, chainApp.PQCAuthKeeper.AuditStateWithFeegrant(
		ctx,
		chainApp.FeeGrantKeeper,
		100,
	).Error())
}

func TestFeegrantMessageRouterMaintainsPQCAuthIndex(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	chainApp := New(
		log.NewNopLogger(),
		db,
		nil,
		true,
		map[int64]bool{},
		t.TempDir(),
		0,
		MakeEncodingConfig(),
		emptyAppOptions{},
		nil,
	)
	ctx := chainApp.BaseApp.NewUncachedContext(
		false,
		tmproto.Header{Height: 10, ChainID: "pqcauth-feegrant-router-1"},
	)
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x51}, 20))
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x52}, 20))
	grant, err := feegrant.NewMsgGrantAllowance(
		&feegrant.BasicAllowance{},
		granter,
		grantee,
	)
	require.NoError(t, err)
	handler := chainApp.MsgServiceRouter().Handler(grant)
	require.NotNil(t, handler)

	_, err = handler(ctx, grant)
	require.NoError(t, err)
	found, err := chainApp.PQCAuthKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.True(t, found)

	revoke := feegrant.NewMsgRevokeAllowance(granter, grantee)
	handler = chainApp.MsgServiceRouter().Handler(&revoke)
	require.NotNil(t, handler)
	_, err = handler(ctx, &revoke)
	require.NoError(t, err)
	found, err = chainApp.PQCAuthKeeper.HasOutgoingFeegrant(ctx, granter)
	require.NoError(t, err)
	require.False(t, found)
}
