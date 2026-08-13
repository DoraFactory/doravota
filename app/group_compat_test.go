package app

import (
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
)

func TestGroupStateRemainsReadableAndExportableAfterV055Wiring(t *testing.T) {
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
	require.NotNil(t, chainApp.GetKey(group.StoreKey))
	require.Contains(t, chainApp.ModuleManager().Modules, group.ModuleName)
	require.Equal(t, uint64(2), chainApp.ModuleManager().GetVersionMap()[group.ModuleName])

	ctx := chainApp.BaseApp.NewUncachedContext(
		false,
		tmproto.Header{
			Height:  1,
			ChainID: "group-compat-test-1",
			Time:    time.Unix(1_700_000_000, 0).UTC(),
		},
	)
	admin := sdk.AccAddress([]byte("group-compat-admin-1"))
	member := sdk.AccAddress([]byte("group-compat-member"))
	response, err := chainApp.GroupKeeper.CreateGroup(
		sdk.WrapSDKContext(ctx),
		&group.MsgCreateGroup{
			Admin:    admin.String(),
			Metadata: "preserved across the SDK v0.55 application wiring",
			Members: []group.MemberRequest{{
				Address: member.String(),
				Weight:  "1",
			}},
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), response.GroupId)

	queryResponse, err := chainApp.GroupKeeper.GroupInfo(
		sdk.WrapSDKContext(ctx),
		&group.QueryGroupInfoRequest{GroupId: response.GroupId},
	)
	require.NoError(t, err)
	require.Equal(t, admin.String(), queryResponse.Info.Admin)

	exported := chainApp.GroupKeeper.ExportGenesis(ctx, chainApp.AppCodec())
	require.Len(t, exported.Groups, 1)
	require.Equal(t, response.GroupId, exported.Groups[0].Id)
	require.Len(t, exported.GroupMembers, 1)
}
