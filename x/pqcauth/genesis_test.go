package pqcauth

import (
	"bytes"
	"context"
	"testing"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/store/v2"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type genesisAccountKeeperStub struct {
	account sdk.AccountI
}

func (stub genesisAccountKeeperStub) GetAccount(
	_ context.Context,
	address sdk.AccAddress,
) sdk.AccountI {
	if stub.account != nil && stub.account.GetAddress().Equals(address) {
		return stub.account
	}
	return authtypes.NewBaseAccount(address, secp256k1.GenPrivKey().PubKey(), 0, 0)
}

func setupGenesisTest(t testing.TB, height int64) (sdk.Context, keeper.Keeper) {
	return setupGenesisTestWithAccountKeeper(t, height, genesisAccountKeeperStub{})
}

func setupGenesisTestWithAccountKeeper(
	t testing.TB,
	height int64,
	accountKeeper keeper.AccountKeeper,
) (sdk.Context, keeper.Keeper) {
	t.Helper()
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	database := dbm.NewMemDB()
	multiStore := store.NewCommitMultiStore(database, log.NewNopLogger())
	multiStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, nil)
	require.NoError(t, multiStore.LoadLatestVersion())
	ctx := sdk.NewContext(
		multiStore,
		tmproto.Header{Height: height, ChainID: "pqcauth-export-test-1"},
		false,
		log.NewNopLogger(),
	)
	authority := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20)).String()
	return ctx, keeper.NewKeeper(cdc, storeKey, authority, accountKeeper)
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
	publicKey3, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	publicKey4, _, err := pqccrypto.GenerateMLDSA65Key(nil)
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
				Owner:           ownerWithSequence.String(),
				KeyId:           2,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       publicKey2,
				Role:            types.KeyRole_KEY_ROLE_RECOVERY,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
			{
				Owner:           ownerDerived.String(),
				KeyId:           3,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       publicKey3,
				Role:            types.KeyRole_KEY_ROLE_SIGNING,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
			{
				Owner:           ownerDerived.String(),
				KeyId:           4,
				Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:       publicKey4,
				Role:            types.KeyRole_KEY_ROLE_RECOVERY,
				Status:          types.KeyStatus_KEY_STATUS_LIVE,
				EffectiveHeight: 1,
			},
		},
		Policies: []types.AccountPolicy{
			{
				Owner:               ownerWithSequence.String(),
				CurrentSigningKeyId: 1,
				RecoveryKeyId:       2,
				PolicyVersion:       1,
			},
			{
				Owner:               ownerDerived.String(),
				CurrentSigningKeyId: 3,
				RecoveryKeyId:       4,
				PolicyVersion:       1,
			},
		},
		KeySequences: []types.AccountKeySequence{{
			Owner:     ownerWithSequence.String(),
			NextKeyId: 3,
		}},
		KeyHistories: []types.AccountKeyHistory{{
			Owner:              ownerDerived.String(),
			Role:               types.KeyRole_KEY_ROLE_SIGNING,
			CompactedCount:     1,
			LastCompactedKeyId: 1,
			Accumulator:        bytes.Repeat([]byte{0x5a}, types.KeyHistoryAccumulatorSize),
		}},
	}

	InitGenesis(ctx, moduleKeeper, genesis)

	expectedParams := genesis.Params
	expectedParams.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	require.Equal(t, expectedParams, moduleKeeper.GetParams(ctx))
	key, found := moduleKeeper.GetKey(ctx, ownerDerived, 3)
	require.True(t, found)
	require.Equal(t, publicKey3, key.PublicKey)
	policy, found := moduleKeeper.GetAccountPolicy(ctx, ownerWithSequence)
	require.True(t, found)
	require.Equal(t, uint64(1), policy.CurrentSigningKeyId)
	require.Equal(
		t,
		uint64(3),
		moduleKeeper.GetKeySequence(ctx, ownerWithSequence).NextKeyId,
	)
	require.Equal(
		t,
		uint64(5),
		moduleKeeper.GetKeySequence(ctx, ownerDerived).NextKeyId,
	)
	history, found := moduleKeeper.GetKeyHistory(
		ctx,
		ownerDerived,
		types.KeyRole_KEY_ROLE_SIGNING,
	)
	require.True(t, found)
	require.Equal(t, genesis.KeyHistories[0], history)

	exported := ExportGenesis(ctx, moduleKeeper)
	require.Len(t, exported.Keys, 4)
	require.Len(t, exported.Policies, 2)
	require.Len(t, exported.KeySequences, 2)
	require.Equal(t, genesis.KeyHistories, exported.KeyHistories)
}

func TestInitGenesisRejectsNativeMLDSAOwner(t *testing.T) {
	privateKey, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	owner := sdk.AccAddress(privateKey.PubKey().Address())
	account := authtypes.NewBaseAccount(owner, privateKey.PubKey(), 1, 0)
	ctx, moduleKeeper := setupGenesisTestWithAccountKeeper(
		t,
		1,
		genesisAccountKeeperStub{account: account},
	)

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		InitGenesis(ctx, moduleKeeper, types.GenesisState{
			Params: types.DefaultParams(),
			KeySequences: []types.AccountKeySequence{{
				Owner:     owner.String(),
				NextKeyId: 1,
			}},
		})
	}()
	require.ErrorIs(t, recovered.(error), types.ErrIneligibleAccount)
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

// A key still in use may be older than newer cancelled keys already compacted.
// Export/import must preserve both that key and the accumulated history.
func TestKeyHistoryOutOfOrderRetirementGenesisRoundTrip(t *testing.T) {
	ctx, k := setupGenesisTest(t, 100)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20))
	params := types.DefaultParams()
	params.NetworkId = types.NetworkIDForChain(ctx.ChainID())
	require.NoError(t, k.SetParams(ctx, params))
	for id := uint64(1); id <= 3; id++ {
		public, _, err := pqccrypto.GenerateMLDSA65Key(nil)
		require.NoError(t, err)
		key := types.PQCKeyRecord{Owner: owner.String(), KeyId: id,
			Algorithm: types.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: public,
			Role: types.KeyRole_KEY_ROLE_SIGNING, Status: types.KeyStatus_KEY_STATUS_LIVE,
			CreatedHeight: 1, EffectiveHeight: 2}
		if id == 2 {
			key.Role = types.KeyRole_KEY_ROLE_RECOVERY
		}
		if id == 3 {
			key.Status = types.KeyStatus_KEY_STATUS_REVOKED
			accumulator, err := types.AccumulateKeyHistory(nil, key)
			require.NoError(t, err)
			require.NoError(t, k.SetKeyHistory(ctx, owner, types.AccountKeyHistory{
				Owner: owner.String(), Role: key.Role, LastCompactedKeyId: id,
				CompactedCount: 1, Accumulator: accumulator,
			}))
		} else {
			require.NoError(t, k.SetKey(ctx, owner, key))
		}
	}
	require.NoError(t, k.SetAccountPolicy(ctx, owner, types.AccountPolicy{
		Owner: owner.String(), CurrentSigningKeyId: 1, RecoveryKeyId: 2,
		SelfEnforced: true, PolicyVersion: 1,
	}))
	require.NoError(t, k.SetKeySequence(ctx, owner, types.AccountKeySequence{Owner: owner.String(), NextKeyId: 4}))
	exported := ExportGenesis(ctx, k)
	require.NoError(t, types.ValidateGenesis(*exported))
	require.NoError(t, k.AuditState(ctx, 100).Error())
	restoredCtx, restored := setupGenesisTest(t, 100)
	InitGenesis(restoredCtx, restored, *exported)
	require.Equal(t, exported, ExportGenesis(restoredCtx, restored))
	require.NoError(t, restored.AuditState(restoredCtx, 100).Error())
	// The watermark itself was compacted; resurrecting that exact ID is invalid.
	exported.Keys[0].KeyId = 3
	require.ErrorContains(t, types.ValidateGenesis(*exported), "overlaps compacted")
}
