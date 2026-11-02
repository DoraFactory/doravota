package keeper

import (
	"math"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func withoutEmergency(p types.ScheduledParams) types.ScheduledParams {
	p.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_NORMAL
	p.EmergencyExpiresHeight = 0
	return p
}

// An explicitly emergency-only request may carry either the active or queued
// non-emergency bundle, but cannot change either. This is a validation check,
// never an inference of the caller's intent from its parameter values.
func validEmergencyOnlyFields(current, requested types.Params) bool {
	active := withoutEmergency(current.AsScheduled())
	want := withoutEmergency(requested.AsScheduled())
	if want.Equal(active) {
		return true
	}
	return current.Pending != nil && want.Equal(withoutEmergency(*current.Pending))
}

func (m msgServer) scheduleEmergencyOnly(ctx sdk.Context, current types.Params, mode types.EmergencyMode) (*types.MsgUpdateParamsResponse, error) {
	if ctx.BlockHeight() < 0 || uint64(ctx.BlockHeight()) == math.MaxUint64 {
		return nil, types.ErrInvalidParams.Wrap("emergency activation height overflow")
	}
	activation := uint64(ctx.BlockHeight()) + 1
	expiry := uint64(0)
	if mode != types.EmergencyMode_EMERGENCY_MODE_NORMAL {
		if activation > math.MaxUint64-current.MaxEmergencyDurationBlocks {
			return nil, types.ErrInvalidParams.Wrap("emergency expiration height overflow")
		}
		expiry = activation + current.MaxEmergencyDurationBlocks
	}
	if current.Pending == nil {
		pending := current.AsScheduled()
		pending.EmergencyMode, pending.EmergencyExpiresHeight = mode, expiry
		current.Pending = &pending
		current.PendingActivationHeight = activation
	} else {
		// Copy before editing; Params.Effective and keeper callers may share the
		// pointer. The original cutoff, budget, enforcement and activation stay put.
		pending := *current.Pending
		pending.EmergencyMode, pending.EmergencyExpiresHeight = mode, expiry
		if expiry != 0 && expiry <= current.PendingActivationHeight {
			pending.EmergencyMode, pending.EmergencyExpiresHeight = types.EmergencyMode_EMERGENCY_MODE_NORMAL, 0
		}
		current.Pending = &pending
	}
	// Protect every explicit emergency update until H+1, including the case
	// with no pre-existing ordinary bundle. Otherwise a later full update in
	// the same block could silently cancel or replace the emergency schedule.
	current.PendingEmergency = &types.EmergencySchedule{Mode: mode, ActivationHeight: activation, ExpiresHeight: expiry}
	if err := m.SetParams(ctx, current); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{ActivationHeight: activation, ResultingParams: current}, nil
}
