package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func emergencyScheduleFixture() Params {
	p := DefaultParams()
	p.MaxEmergencyDurationBlocks = 20
	pending := p.AsScheduled()
	pending.VerificationGas = 1000
	pending.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	pending.EmergencyExpiresHeight = 122
	p.Pending = &pending
	p.PendingActivationHeight = 110
	p.PendingEmergency = &EmergencySchedule{Mode: EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, ActivationHeight: 102, ExpiresHeight: 122}
	return p
}

func TestIndependentEmergencyValidationAndCodec(t *testing.T) {
	p := emergencyScheduleFixture()
	require.NoError(t, p.Validate())
	require.Error(t, p.ValidateGovernanceUpdate(), "governance cannot inject a precomputed emergency schedule")
	bz, err := p.Marshal()
	require.NoError(t, err)
	var decoded Params
	require.NoError(t, decoded.Unmarshal(bz))
	require.Equal(t, p, decoded)
	for _, mutate := range []struct {
		name string
		fn   func(*Params)
	}{
		{"no bundle", func(p *Params) { p.Pending = nil; p.PendingActivationHeight = 0 }},
		{"zero activation", func(p *Params) { p.PendingEmergency.ActivationHeight = 0 }},
		{"late activation", func(p *Params) { p.PendingEmergency.ActivationHeight = 111 }},
		{"unknown mode", func(p *Params) { p.PendingEmergency.Mode = 99 }},
		{"zero expiry", func(p *Params) { p.PendingEmergency.ExpiresHeight = 0 }},
		{"expired at activation", func(p *Params) { p.PendingEmergency.ExpiresHeight = 102 }},
		{"unbounded duration", func(p *Params) { p.PendingEmergency.ExpiresHeight = 123 }},
		{"normal with expiry", func(p *Params) { p.PendingEmergency.Mode = EmergencyMode_EMERGENCY_MODE_NORMAL }},
		{"pending overwrites emergency", func(p *Params) {
			p.Pending.EmergencyMode = EmergencyMode_EMERGENCY_MODE_NORMAL
			p.Pending.EmergencyExpiresHeight = 0
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			p := emergencyScheduleFixture()
			mutate.fn(&p)
			require.Error(t, p.Validate())
			require.Error(t, ValidateGenesis(GenesisState{Params: p}))
		})
	}
	before := decoded
	active := p.Effective(102)
	require.Nil(t, active.PendingEmergency)
	require.Equal(t, EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS, active.EmergencyMode)
	require.Equal(t, before, p, "effective reads must not mutate source/pending pointers")
	require.Equal(t, EmergencyMode_EMERGENCY_MODE_NORMAL, p.Effective(122).EmergencyMode)
	// Empty old state retains the old wire format (new field omitted).
	old := DefaultParams()
	bz, err = old.Marshal()
	require.NoError(t, err)
	decoded = Params{}
	require.NoError(t, decoded.Unmarshal(bz))
	require.Nil(t, decoded.PendingEmergency)
}
