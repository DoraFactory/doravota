package sdk_v053_bridge

import (
	"testing"

	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	"github.com/stretchr/testify/require"
)

func TestLoadLegacyConsensusParams(t *testing.T) {
	key := storetypes.NewKVStoreKey("upgrade")
	tkey := storetypes.NewTransientStoreKey("transient_test")
	ctx := testutil.DefaultContext(key, tkey)
	cdc := codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())
	want := tmproto.ConsensusParams{
		Block:     &tmproto.BlockParams{MaxBytes: 22_020_096, MaxGas: -1},
		Evidence:  &tmproto.EvidenceParams{MaxAgeNumBlocks: 100_000, MaxBytes: 1_048_576},
		Validator: &tmproto.ValidatorParams{PubKeyTypes: []string{"ed25519"}},
	}
	ctx.KVStore(key).Set(legacyConsensusParamsStoreKey, cdc.MustMarshal(&want))

	got, found, err := LoadLegacyConsensusParams(ctx, key, cdc)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, want, got)
}

func TestLoadLegacyConsensusParamsMissing(t *testing.T) {
	key := storetypes.NewKVStoreKey("upgrade")
	ctx := testutil.DefaultContext(key, storetypes.NewTransientStoreKey("transient_test"))

	_, found, err := LoadLegacyConsensusParams(
		ctx,
		key,
		codec.NewProtoCodec(cdctypes.NewInterfaceRegistry()),
	)
	require.NoError(t, err)
	require.False(t, found)
}

func TestLoadLegacyConsensusParamsRejectsCorruption(t *testing.T) {
	key := storetypes.NewKVStoreKey("upgrade")
	ctx := testutil.DefaultContext(key, storetypes.NewTransientStoreKey("transient_test"))
	ctx.KVStore(key).Set(legacyConsensusParamsStoreKey, []byte{0xff, 0xff})

	_, found, err := LoadLegacyConsensusParams(
		ctx,
		key,
		codec.NewProtoCodec(cdctypes.NewInterfaceRegistry()),
	)
	require.Error(t, err)
	require.False(t, found)
}
