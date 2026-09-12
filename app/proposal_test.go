package app

import (
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"math"
	"testing"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

func TestCompleteConsensusParamsSeedsMissingMigratedRecord(t *testing.T) {
	observed := tmproto.ConsensusParams{
		Block:     &tmproto.BlockParams{MaxBytes: 10_000, MaxGas: 20_000},
		Evidence:  &tmproto.EvidenceParams{MaxAgeNumBlocks: 100},
		Validator: &tmproto.ValidatorParams{PubKeyTypes: []string{"ed25519"}},
		Version:   &tmproto.VersionParams{App: 7},
		Abci:      &tmproto.ABCIParams{VoteExtensionsEnableHeight: 9},
	}

	completed, changed := completeConsensusParams(tmproto.ConsensusParams{}, observed)
	require.True(t, changed)
	require.Equal(t, observed, completed)

	unchanged, changed := completeConsensusParams(completed, observed)
	require.False(t, changed)
	require.Equal(t, completed, unchanged)
}

func TestProposalBudgetBoundaries(t *testing.T) {
	ctx := sdk.Context{}.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 123, MaxBytes: 456}})
	require.EqualValues(t, 123, effectiveProposalGasLimit(ctx))
	require.EqualValues(t, 100, effectiveProposalMaxBytes(ctx, 100))
	require.EqualValues(t, 456, effectiveProposalMaxBytes(ctx, 1000))
	require.EqualValues(t, 456, effectiveProposalMaxBytes(ctx, 0))
	ctx = ctx.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: -1, MaxBytes: 0}})
	require.Equal(t, fallbackProposalGasLimit, effectiveProposalGasLimit(ctx))
	require.Equal(t, fallbackProposalMaxBytes, effectiveProposalMaxBytes(ctx, 0))
	require.False(t, exceedsUint64(math.MaxUint64-1, 1))
	require.True(t, exceedsUint64(math.MaxUint64-1, 2))
}

func TestFiniteLimitsPreserveExplicitValues(t *testing.T) {
	p := tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 321, MaxBytes: 654}}
	require.False(t, ensureFiniteBlockLimits(&p))
	require.EqualValues(t, 321, p.Block.MaxGas)
	require.EqualValues(t, 654, p.Block.MaxBytes)
	p.Block.MaxGas = -1
	require.True(t, ensureFiniteBlockLimits(&p))
	require.EqualValues(t, fallbackProposalGasLimit, p.Block.MaxGas)
	require.EqualValues(t, 654, p.Block.MaxBytes)
}

// Rejections must happen before invoking ante against application state.
func TestProcessProposalRejectsInvalidBudgetsAndEncoding(t *testing.T) {
	encoding := MakeEncodingConfig()
	a := &App{txConfig: encoding.TxConfig}
	ctx := sdk.Context{}.WithConsensusParams(tmproto.ConsensusParams{Block: &tmproto.BlockParams{MaxGas: 100, MaxBytes: 1000}})
	encodeGas := func(gas uint64) []byte {
		b := encoding.TxConfig.NewTxBuilder()
		b.SetGasLimit(gas)
		raw, err := encoding.TxConfig.TxEncoder()(b.GetTx())
		require.NoError(t, err)
		return raw
	}
	for _, tc := range []struct {
		name   string
		txs    [][]byte
		status abci.ResponseProcessProposal_ProposalStatus
	}{
		{"empty", nil, abci.ResponseProcessProposal_ACCEPT},
		{"malformed", [][]byte{{255}}, abci.ResponseProcessProposal_REJECT},
		{"oversize", [][]byte{make([]byte, 1001)}, abci.ResponseProcessProposal_REJECT},
		{"zero gas", [][]byte{encodeGas(0)}, abci.ResponseProcessProposal_REJECT},
		{"excessive gas", [][]byte{encodeGas(101)}, abci.ResponseProcessProposal_REJECT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := a.processProposalHandler()(ctx, &abci.RequestProcessProposal{Txs: tc.txs})
			require.NoError(t, err)
			require.Equal(t, tc.status, r.Status)
		})
	}
}
