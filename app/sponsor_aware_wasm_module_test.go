package app

import (
	"bytes"
	"testing"

	"cosmossdk.io/log/v2"
	wasm "github.com/CosmWasm/wasmd/x/wasm"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

type emptyAppOptions struct{}

func (emptyAppOptions) Get(string) interface{} { return nil }

func TestSponsorAwareWasmMigrationMirrorVersion(t *testing.T) {
	require.Equal(
		t,
		sponsorAwareWasmMirroredConsensusVersion,
		(wasm.AppModule{}).ConsensusVersion(),
		"wasmd consensus version changed; synchronize sponsor-aware RegisterServices migrations",
	)
}

func TestRegisteredWasmMsgServerRejectsClearAdminWithSponsor(t *testing.T) {
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
		tmproto.Header{Height: 1},
	)
	admin := sdk.AccAddress(bytes.Repeat([]byte{0x31}, 20)).String()
	contract := sdk.AccAddress(bytes.Repeat([]byte{0x32}, 20)).String()

	require.NoError(t, chainApp.SponsorKeeper.SetSponsor(ctx, sponsortypes.ContractSponsor{
		ContractAddress: contract,
		CreatorAddress:  admin,
	}))

	msg := &wasmtypes.MsgClearAdmin{
		Sender:   admin,
		Contract: contract,
	}
	handler := chainApp.MsgServiceRouter().Handler(msg)
	require.NotNil(t, handler)

	_, err := handler(ctx, msg)
	require.ErrorIs(t, err, sponsortypes.ErrSponsorMustBeRemoved)
}
