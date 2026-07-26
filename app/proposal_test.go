package app

import (
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/libs/log"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestProposalLimitsRemainFiniteForLegacyUnlimitedConsensusParams(t *testing.T) {
	ctx := sdk.Context{}.WithConsensusParams(&tmproto.ConsensusParams{
		Block: &tmproto.BlockParams{MaxBytes: -1, MaxGas: -1},
	})
	require.Equal(t, fallbackProposalGasLimit, effectiveProposalGasLimit(ctx))
	require.Equal(t, fallbackProposalMaxBytes, effectiveProposalMaxBytes(ctx, 0))
}

func TestProposalLimitsHonorStricterConsensusAndRequestLimits(t *testing.T) {
	ctx := sdk.Context{}.WithConsensusParams(&tmproto.ConsensusParams{
		Block: &tmproto.BlockParams{MaxBytes: 10_000, MaxGas: 20_000},
	})
	require.Equal(t, uint64(20_000), effectiveProposalGasLimit(ctx))
	require.Equal(t, int64(10_000), effectiveProposalMaxBytes(ctx, 0))
	require.Equal(t, int64(5_000), effectiveProposalMaxBytes(ctx, 5_000))
}

func TestEnsureFiniteBlockLimitsPreservesExplicitLimits(t *testing.T) {
	params := &tmproto.ConsensusParams{
		Block: &tmproto.BlockParams{MaxBytes: 10_000, MaxGas: 20_000},
	}
	require.False(t, ensureFiniteBlockLimits(params))
	require.Equal(t, int64(10_000), params.Block.MaxBytes)
	require.Equal(t, int64(20_000), params.Block.MaxGas)

	unlimited := &tmproto.ConsensusParams{
		Block: &tmproto.BlockParams{MaxBytes: -1, MaxGas: -1},
	}
	require.True(t, ensureFiniteBlockLimits(unlimited))
	require.Equal(t, fallbackProposalMaxBytes, unlimited.Block.MaxBytes)
	require.Equal(t, int64(fallbackProposalGasLimit), unlimited.Block.MaxGas)
}

func TestProcessProposalRejectsMalformedTransaction(t *testing.T) {
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

	response := chainApp.ProcessProposal(abci.RequestProcessProposal{
		Height: 1,
		Txs:    [][]byte{{0xff}},
	})
	require.Equal(t, abci.ResponseProcessProposal_REJECT, response.Status)
}
