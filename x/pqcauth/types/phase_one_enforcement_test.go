package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhaseOneRejectsGlobalRequired(t *testing.T) {
	p := DefaultParams()
	p.EnforcementMode = EnforcementMode_ENFORCEMENT_MODE_REQUIRED
	require.ErrorIs(t, p.Validate(), ErrInvalidParams)
	require.ErrorIs(t, p.ValidateGovernanceUpdate(), ErrInvalidParams)
	require.ErrorIs(t, ValidateGenesis(GenesisState{Params: p}), ErrInvalidParams)
	base := DefaultParams()
	pending := p.AsScheduled()
	base.Pending, base.PendingActivationHeight = &pending, 100
	require.ErrorIs(t, base.Validate(), ErrInvalidParams)
	require.ErrorIs(t, ValidateGenesis(GenesisState{Params: base}), ErrInvalidParams)
	// The reserved enum must not silently normalize into an allowed mode.
	require.Equal(t, EnforcementMode_ENFORCEMENT_MODE_REQUIRED, base.Effective(100).EnforcementMode)
	for _, mode := range []EnforcementMode{EnforcementMode_ENFORCEMENT_MODE_DISABLED, EnforcementMode_ENFORCEMENT_MODE_OPTIONAL, EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED} {
		p.EnforcementMode = mode
		require.NoError(t, p.Validate())
	}
}
