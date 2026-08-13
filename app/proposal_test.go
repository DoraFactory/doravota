package app

import (
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
