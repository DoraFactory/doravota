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

// A pure emergency request may carry either the active or the queued bundle.
// It changes neither bundle's non-emergency fields. In particular an active
// cutoff of zero is NOT a request to revoke a queued irreversible cutoff here.
// Existing ordinary-only cancellation and emergency-only bundle semantics are
// retained when no different non-emergency bundle is waiting.
func isOverlappingEmergencyUpdate(current, requested types.Params) bool {
	if current.Pending == nil {
		return false
	}
	active := withoutEmergency(current.AsScheduled())
	pending := withoutEmergency(*current.Pending)
	if active.Equal(pending) && current.PendingEmergency == nil {
		return false
	}
	want := withoutEmergency(requested.AsScheduled())
	if !want.Equal(active) && !want.Equal(pending) {
		return false
	}
	return current.PendingEmergency != nil ||
		requested.EmergencyMode != current.EmergencyMode ||
		requested.EmergencyMode != current.Pending.EmergencyMode ||
		requested.EmergencyMode != types.EmergencyMode_EMERGENCY_MODE_NORMAL
}

func (m msgServer) scheduleOverlappingEmergency(ctx sdk.Context, current types.Params, mode types.EmergencyMode) (*types.MsgUpdateParamsResponse, error) {
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
	current.PendingEmergency = &types.EmergencySchedule{Mode: mode, ActivationHeight: activation, ExpiresHeight: expiry}
	// Copy before editing; Params.Effective and keeper callers may share the
	// pointer. The original cutoff, budget, enforcement and activation stay put.
	pending := *current.Pending
	pending.EmergencyMode, pending.EmergencyExpiresHeight = mode, expiry
	if expiry != 0 && expiry <= current.PendingActivationHeight {
		pending.EmergencyMode, pending.EmergencyExpiresHeight = types.EmergencyMode_EMERGENCY_MODE_NORMAL, 0
	}
	current.Pending = &pending
	if err := m.SetParams(ctx, current); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{ActivationHeight: activation}, nil
}
