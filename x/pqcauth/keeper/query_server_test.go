package keeper

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestQueryServerAccountAndKeyMatrix(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	require.NoError(t, moduleKeeper.SetParams(ctx, types.DefaultParams()))
	server := NewQueryServer(moduleKeeper)
	goCtx := sdk.WrapSDKContext(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x71}, 20))

	_, err := server.Account(goCtx, nil)
	require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
	_, err = server.Account(goCtx, &types.QueryAccountRequest{Owner: "invalid"})
	require.ErrorIs(t, err, sdkerrors.ErrInvalidAddress)
	_, err = server.Account(goCtx, &types.QueryAccountRequest{Owner: owner.String()})
	require.ErrorIs(t, err, types.ErrPolicyNotFound)

	policy := types.AccountPolicy{
		Owner:               owner.String(),
		CurrentSigningKeyId: 1,
		PolicyVersion:       1,
	}
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, owner, policy))
	accountResponse, err := server.Account(goCtx, &types.QueryAccountRequest{
		Owner: owner.String(),
	})
	require.NoError(t, err)
	require.Equal(t, policy, accountResponse.Policy)
	require.Nil(t, accountResponse.ActiveSigningKey)

	publicKey, _ := keyPair(30)
	key := types.PQCKeyRecord{
		Owner:           owner.String(),
		KeyId:           1,
		Algorithm:       types.Algorithm_ALGORITHM_ML_DSA_65,
		PublicKey:       publicKey,
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		EffectiveHeight: 1,
	}
	require.NoError(t, moduleKeeper.SetKey(ctx, owner, key))
	accountResponse, err = server.Account(goCtx, &types.QueryAccountRequest{
		Owner: owner.String(),
	})
	require.NoError(t, err)
	require.NotNil(t, accountResponse.ActiveSigningKey)
	require.Equal(t, key, *accountResponse.ActiveSigningKey)

	_, err = server.Key(goCtx, nil)
	require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
	for _, request := range []*types.QueryKeyRequest{
		{Owner: "invalid", KeyId: 1},
		{Owner: owner.String(), KeyId: 0},
	} {
		_, err = server.Key(goCtx, request)
		require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
	}
	_, err = server.Key(goCtx, &types.QueryKeyRequest{
		Owner: owner.String(),
		KeyId: 99,
	})
	require.ErrorIs(t, err, types.ErrKeyNotFound)
	keyResponse, err := server.Key(goCtx, &types.QueryKeyRequest{
		Owner: owner.String(),
		KeyId: 1,
	})
	require.NoError(t, err)
	require.Equal(t, key, keyResponse.Key)
}

func TestQueryServerKeysPaginationAndCorruptRecord(t *testing.T) {
	moduleKeeper, ctx := setupKeeper(t, 10)
	server := NewQueryServer(moduleKeeper)
	goCtx := sdk.WrapSDKContext(ctx)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x72}, 20))

	_, err := server.Keys(goCtx, nil)
	require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
	_, err = server.Keys(goCtx, &types.QueryKeysRequest{Owner: "invalid"})
	require.ErrorIs(t, err, sdkerrors.ErrInvalidAddress)

	for keyID := uint64(1); keyID <= 3; keyID++ {
		require.NoError(t, moduleKeeper.SetKey(ctx, owner, types.PQCKeyRecord{
			Owner: owner.String(),
			KeyId: keyID,
		}))
	}
	response, err := server.Keys(goCtx, &types.QueryKeysRequest{
		Owner: owner.String(),
		Pagination: &query.PageRequest{
			Limit:      2,
			CountTotal: true,
		},
	})
	require.NoError(t, err)
	require.Len(t, response.Keys, 2)
	require.Equal(t, uint64(3), response.Pagination.Total)
	require.NotEmpty(t, response.Pagination.NextKey)

	next, err := server.Keys(goCtx, &types.QueryKeysRequest{
		Owner: owner.String(),
		Pagination: &query.PageRequest{
			Key: response.Pagination.NextKey,
		},
	})
	require.NoError(t, err)
	require.Len(t, next.Keys, 1)
	require.Equal(t, uint64(3), next.Keys[0].KeyId)

	ctx.KVStore(moduleKeeper.storeKey).Set(
		types.PQCKeyRecordKey(owner, 4),
		[]byte{0xff},
	)
	_, err = server.Keys(sdk.WrapSDKContext(ctx), &types.QueryKeysRequest{
		Owner: owner.String(),
	})
	require.Error(t, err)
}
