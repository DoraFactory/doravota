package app

import (
	"testing"
	"time"

	"cosmossdk.io/core/header"
	"cosmossdk.io/log/v2"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestStartupCheckContextScope(t *testing.T) {
	stamp := time.Unix(1700000000, 0).UTC()
	saved := startupCheckContext{height: 42, time: stamp}
	for _, mode := range []sdk.ExecMode{sdk.ExecModeCheck, sdk.ExecModeReCheck, sdk.ExecModeSimulate, sdk.ExecModePrepareProposal, sdk.ExecModeProcessProposal, sdk.ExecModeFinalize, sdk.ExecModeVoteExtension, sdk.ExecModeVerifyVoteExtension} {
		ctx := sdk.NewContext(nil, tmproto.Header{ChainID: "chain", AppHash: []byte{1}}, true, log.NewNopLogger()).WithHeaderInfo(header.Info{ChainID: "chain", AppHash: []byte{1}}).WithExecMode(mode)
		got := saved.restore(ctx)
		if mode == sdk.ExecModeCheck || mode == sdk.ExecModeReCheck || mode == sdk.ExecModeSimulate {
			require.EqualValues(t, 42, got.BlockHeight())
			require.Equal(t, stamp, got.BlockTime())
			require.EqualValues(t, 42, got.HeaderInfo().Height)
			require.Equal(t, stamp, got.HeaderInfo().Time)
		} else {
			require.Equal(t, ctx.BlockHeader(), got.BlockHeader())
			require.Equal(t, ctx.HeaderInfo(), got.HeaderInfo())
		}
		require.Equal(t, ctx.ChainID(), got.ChainID())
		require.Equal(t, ctx.HeaderInfo().AppHash, got.HeaderInfo().AppHash)
		require.Equal(t, ctx.ExecMode(), got.ExecMode())
		require.Equal(t, ctx.GasMeter(), got.GasMeter())
		// A fresh database must retain genesis behavior, and an initialized
		// context must never be rolled back to the startup height/time.
		require.Equal(t, ctx.BlockHeader(), (startupCheckContext{}).restore(ctx).BlockHeader())
		live := ctx.WithBlockHeight(43).WithBlockTime(stamp.Add(time.Minute))
		require.Equal(t, live.BlockHeader(), saved.restore(live).BlockHeader())
	}
}
