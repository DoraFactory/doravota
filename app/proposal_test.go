package app

import (
	"testing"

	"cosmossdk.io/log/v2"
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestProposalLimitsRemainFiniteForLegacyUnlimitedConsensusParams(t *testing.T) {
	ctx := sdk.Context{}.WithConsensusParams(tmproto.ConsensusParams{
		Block: &tmproto.BlockParams{MaxBytes: -1, MaxGas: -1},
	})
	require.Equal(t, fallbackProposalGasLimit, effectiveProposalGasLimit(ctx))
	require.Equal(t, fallbackProposalMaxBytes, effectiveProposalMaxBytes(ctx, 0))
}

func TestProposalLimitsHonorStricterConsensusAndRequestLimits(t *testing.T) {
	ctx := sdk.Context{}.WithConsensusParams(tmproto.ConsensusParams{
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

func TestCompleteConsensusParamsSeedsMissingMigratedRecord(t *testing.T) {
	observed := tmproto.ConsensusParams{
		Block:     &tmproto.BlockParams{MaxBytes: 10_000, MaxGas: 20_000},
		Evidence:  &tmproto.EvidenceParams{MaxAgeNumBlocks: 100},
		Validator: &tmproto.ValidatorParams{PubKeyTypes: []string{"ed25519"}},
		Version:   &tmproto.VersionParams{App: 7},
		Abci:      &tmproto.ABCIParams{VoteExtensionsEnableHeight: 9},
		Authority: &tmproto.AuthorityParams{Authority: "dora1authority"},
	}

	completed, changed := completeConsensusParams(tmproto.ConsensusParams{}, observed)
	require.True(t, changed)
	require.Equal(t, observed, completed)

	unchanged, changed := completeConsensusParams(completed, observed)
	require.False(t, changed)
	require.Equal(t, completed, unchanged)
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

	response, err := chainApp.ProcessProposal(&abci.RequestProcessProposal{
		Height: 1,
		Txs:    [][]byte{{0xff}},
	})
	require.NoError(t, err)
	require.Equal(t, abci.ResponseProcessProposal_REJECT, response.Status)
}
