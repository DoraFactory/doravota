package pqcauth

import (
	"bytes"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func setupGenesisTest(t testing.TB, height int64) (sdk.Context, keeper.Keeper) {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	storeKey := sdk.NewKVStoreKey(types.StoreKey)
	database := dbm.NewMemDB()
	multiStore := store.NewCommitMultiStore(database)
	multiStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, multiStore.LoadLatestVersion())
	ctx := sdk.NewContext(
		multiStore,
		tmproto.Header{Height: height, ChainID: "pqcauth-export-test-1"},
		false,
		log.NewNopLogger(),
	)
	authority := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20)).String()
	return ctx, keeper.NewKeeper(cdc, storeKey, authority)
}

func TestExportGenesisNormalizesActivatedParamsAndPolicies(t *testing.T) {
	ctx, moduleKeeper := setupGenesisTest(t, 50)
	params := types.DefaultParams()
	scheduled := params.AsScheduled()
	scheduled.EnforcementMode = types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	params.Pending = &scheduled
	params.PendingActivationHeight = 50
	require.NoError(t, moduleKeeper.SetParams(ctx, params))

	owner := sdk.AccAddress(bytes.Repeat([]byte{0x33}, 20))
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner:                  owner.String(),
		CurrentSigningKeyId:    1,
		SelfEnforced:           false,
		PolicyVersion:          1,
		PendingSigningKeyId:    2,
		PendingEffectiveHeight: 50,
		PendingSelfEnforced:    true,
		PendingPolicyVersion:   2,
	}))

	exported := ExportGenesis(ctx, moduleKeeper)
	require.Equal(t, scheduled.EnforcementMode, exported.Params.EnforcementMode)
	require.Nil(t, exported.Params.Pending)
	require.Zero(t, exported.Params.PendingActivationHeight)
	require.Len(t, exported.Policies, 1)
	require.Equal(t, uint64(2), exported.Policies[0].CurrentSigningKeyId)
	require.Equal(t, uint64(2), exported.Policies[0].PolicyVersion)
	require.True(t, exported.Policies[0].SelfEnforced)
	require.Zero(t, exported.Policies[0].PendingEffectiveHeight)
}

func TestInitGenesisImportsStateAndDerivesMissingSequence(t *testing.T) {
	ctx, moduleKeeper := setupGenesisTest(t, 20)
	ownerWithSequence := sdk.AccAddress(bytes.Repeat([]byte{0x34}, 20))
	ownerDerived := sdk.AccAddress(bytes.Repeat([]byte{0x35}, 20))
	publicKey1, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	publicKey2, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	genesis := types.GenesisState{
		Params: types.DefaultParams(),
		Keys: []types.PQCKeyRecord{
			{
				Owner:           ownerWithSequence.String(),
				KeyId:           1,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       publicKey1,
				Role:            types.KeyRole_KEY_ROLE_SIGNING,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
			{
				Owner:           ownerDerived.String(),
				KeyId:           2,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       publicKey2,
				Role:            types.KeyRole_KEY_ROLE_SIGNING,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
		},
		Policies: []types.AccountPolicy{
			{
				Owner:               ownerWithSequence.String(),
				CurrentSigningKeyId: 1,
				PolicyVersion:       1,
			},
			{
				Owner:               ownerDerived.String(),
				CurrentSigningKeyId: 2,
				PolicyVersion:       1,
			},
		},
		KeySequences: []types.AccountKeySequence{{
			Owner:     ownerWithSequence.String(),
			NextKeyId: 2,
		}},
	}

	InitGenesis(ctx, moduleKeeper, genesis)

	expectedParams := genesis.Params
	expectedParams.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	require.Equal(t, expectedParams, moduleKeeper.GetParams(ctx))
	key, found := moduleKeeper.GetKey(ctx, ownerDerived, 2)
	require.True(t, found)
	require.Equal(t, publicKey2, key.PublicKey)
	policy, found := moduleKeeper.GetAccountPolicy(ctx, ownerWithSequence)
	require.True(t, found)
	require.Equal(t, uint64(1), policy.CurrentSigningKeyId)
	require.Equal(
		t,
		uint64(2),
		moduleKeeper.GetKeySequence(ctx, ownerWithSequence).NextKeyId,
	)
	require.Equal(
		t,
		uint64(3),
		moduleKeeper.GetKeySequence(ctx, ownerDerived).NextKeyId,
	)

	exported := ExportGenesis(ctx, moduleKeeper)
	require.Len(t, exported.Keys, 2)
	require.Len(t, exported.Policies, 2)
	require.Len(t, exported.KeySequences, 2)
}

func TestInitGenesisPanicsOnInvalidState(t *testing.T) {
	ctx, moduleKeeper := setupGenesisTest(t, 1)
	invalid := *types.DefaultGenesisState()
	invalid.Params.NetworkId = nil

	require.PanicsWithError(
		t,
		"invalid pqcauth genesis: invalid pqcauth parameters: network_id length must be between 16 and 64 bytes",
		func() {
			InitGenesis(ctx, moduleKeeper, invalid)
		},
	)
}
