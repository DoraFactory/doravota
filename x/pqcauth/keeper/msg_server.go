package keeper

import (
	"context"
	"fmt"
	"math"
	"time"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type msgServer struct {
	types.UnimplementedMsgServer
	Keeper
}

var _ types.MsgServer = msgServer{}

func NewMsgServer(keeper Keeper) types.MsgServer {
	return msgServer{Keeper: keeper}
}

func (m msgServer) RegisterKey(
	goCtx context.Context,
	msg *types.MsgRegisterKey,
) (*types.MsgRegisterKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensureKeyChangeAllowed(params); err != nil {
		return nil, err
	}

	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	if err := m.RequireClassicAccount(ctx, owner); err != nil {
		return nil, err
	}
	if err := types.CheckRegistrationAllowed(
		params,
		ctx.BlockHeight(),
		execution.IsFreshRegistrationCandidate(ctx, msg),
	); err != nil {
		return nil, err
	}
	if _, found := m.GetAccountPolicy(ctx, owner); found {
		return nil, types.ErrAlreadyRegistered
	}

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedSigningKeyId,
		2,
	)
	if err != nil {
		return nil, err
	}

	effectiveHeight := uint64(ctx.BlockHeight()) + 1
	signingKey := types.PQCKeyRecord{
		Owner:           msg.Owner,
		KeyId:           ids[0],
		Algorithm:       msg.SigningAlgorithm,
		PublicKey:       append([]byte(nil), msg.SigningPublicKey...),
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		CreatedHeight:   uint64(ctx.BlockHeight()),
		EffectiveHeight: effectiveHeight,
	}
	if err := m.SetKey(ctx, owner, signingKey); err != nil {
		return nil, err
	}
	recoveryKey := types.PQCKeyRecord{
		Owner:           msg.Owner,
		KeyId:           ids[1],
		Algorithm:       msg.RecoveryAlgorithm,
		PublicKey:       append([]byte(nil), msg.RecoveryPublicKey...),
		Role:            types.KeyRole_KEY_ROLE_RECOVERY,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		CreatedHeight:   uint64(ctx.BlockHeight()),
		EffectiveHeight: effectiveHeight,
	}
	if err := m.SetKey(ctx, owner, recoveryKey); err != nil {
		return nil, err
	}

	const initialPolicyVersion = 1
	policy := types.AccountPolicy{
		Owner:                  msg.Owner,
		PendingSigningKeyId:    signingKey.KeyId,
		PendingRecoveryKeyId:   recoveryKey.KeyId,
		PendingEffectiveHeight: effectiveHeight,
		PendingSelfEnforced:    true,
		PendingPolicyVersion:   initialPolicyVersion,
		PendingChangeKind:      types.PolicyChangeKind_POLICY_CHANGE_KIND_REGISTRATION,
		PendingCreatedHeight:   uint64(ctx.BlockHeight()),
	}
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
		return nil, err
	}

	emitPolicyEvent(ctx, "pqc_register_key", msg.Owner, signingKey.KeyId, effectiveHeight, initialPolicyVersion)
	return &types.MsgRegisterKeyResponse{
		SigningKeyId:    signingKey.KeyId,
		RecoveryKeyId:   recoveryKey.KeyId,
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   initialPolicyVersion,
	}, nil
}

func (m msgServer) RotateKey(
	goCtx context.Context,
	msg *types.MsgRotateKey,
) (*types.MsgRotateKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensureKeyChangeAllowed(params); err != nil {
		return nil, err
	}
	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found, err := m.NormalizeAccountPolicy(ctx, owner)
	if err != nil {
		return nil, err
	}
	if !found || policy.CurrentSigningKeyId == 0 {
		return nil, types.ErrPolicyNotFound
	}
	if policy.HasPendingChange(ctx.BlockHeight()) {
		return nil, types.ErrPendingChange
	}
	recoveryKey, found := m.GetKey(ctx, owner, policy.RecoveryKeyId)
	if !found ||
		recoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
		!recoveryKey.IsEffective(ctx.BlockHeight()) {
		return nil, types.ErrKeyNotFound.Wrap("active recovery key")
	}
	if err := types.ValidateDistinctRoleKeys(
		msg.NewAlgorithm,
		msg.NewPublicKey,
		recoveryKey.Algorithm,
		recoveryKey.PublicKey,
	); err != nil {
		return nil, err
	}

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewKeyId,
		1,
	)
	if err != nil {
		return nil, err
	}
	newPolicyVersion := policy.PolicyVersion + 1
	if newPolicyVersion == 0 {
		return nil, types.ErrInvalidPolicyVersion.Wrap("policy version overflow")
	}

	oldKey, found := m.GetKey(ctx, owner, policy.CurrentSigningKeyId)
	if !found || !oldKey.IsEffective(ctx.BlockHeight()) {
		return nil, types.ErrKeyNotFound.Wrap("active signing key")
	}
	effectiveHeight := uint64(ctx.BlockHeight()) + 1
	oldKey.InactiveFromHeight = effectiveHeight
	if err := m.SetKey(ctx, owner, oldKey); err != nil {
		return nil, err
	}
	newKey := types.PQCKeyRecord{
		Owner:           msg.Owner,
		KeyId:           ids[0],
		Algorithm:       msg.NewAlgorithm,
		PublicKey:       append([]byte(nil), msg.NewPublicKey...),
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		CreatedHeight:   uint64(ctx.BlockHeight()),
		EffectiveHeight: effectiveHeight,
	}
	if err := m.SetKey(ctx, owner, newKey); err != nil {
		return nil, err
	}
	policy.PendingSigningKeyId = newKey.KeyId
	policy.PendingEffectiveHeight = effectiveHeight
	policy.PendingSelfEnforced = policy.SelfEnforced
	policy.PendingPolicyVersion = newPolicyVersion
	policy.PendingChangeKind = types.PolicyChangeKind_POLICY_CHANGE_KIND_ROTATE_SIGNING
	policy.PendingCreatedHeight = uint64(ctx.BlockHeight())
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
		return nil, err
	}
	if err := m.CompactTerminalKeyHistory(
		ctx,
		owner,
		policy,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	); err != nil {
		return nil, err
	}

	emitPolicyEvent(ctx, "pqc_rotate_key", msg.Owner, newKey.KeyId, effectiveHeight, newPolicyVersion)
	return &types.MsgRotateKeyResponse{
		NewKeyId:        newKey.KeyId,
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   newPolicyVersion,
	}, nil
}

func (m msgServer) RotateRecoveryKey(
	goCtx context.Context,
	msg *types.MsgRotateRecoveryKey,
) (*types.MsgRotateRecoveryKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensureKeyChangeAllowed(params); err != nil {
		return nil, err
	}
	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found, err := m.NormalizeAccountPolicy(ctx, owner)
	if err != nil {
		return nil, err
	}
	if !found || policy.CurrentSigningKeyId == 0 || policy.RecoveryKeyId == 0 {
		return nil, types.ErrPolicyNotFound.Wrap("active signing and recovery keys are required")
	}
	if policy.HasPendingChange(ctx.BlockHeight()) {
		return nil, types.ErrPendingChange
	}
	oldRecoveryKey, found := m.GetKey(ctx, owner, policy.RecoveryKeyId)
	if !found ||
		oldRecoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
		!oldRecoveryKey.IsEffective(ctx.BlockHeight()) {
		return nil, types.ErrKeyNotFound.Wrap("active recovery key")
	}
	signingKey, found := m.GetKey(ctx, owner, policy.CurrentSigningKeyId)
	if !found ||
		signingKey.Role != types.KeyRole_KEY_ROLE_SIGNING ||
		!signingKey.IsEffective(ctx.BlockHeight()) {
		return nil, types.ErrKeyNotFound.Wrap("active signing key")
	}
	if err := types.ValidateDistinctRoleKeys(
		signingKey.Algorithm,
		signingKey.PublicKey,
		msg.NewAlgorithm,
		msg.NewPublicKey,
	); err != nil {
		return nil, err
	}

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewKeyId,
		1,
	)
	if err != nil {
		return nil, err
	}
	newPolicyVersion := policy.PolicyVersion + 1
	if newPolicyVersion == 0 {
		return nil, types.ErrInvalidPolicyVersion.Wrap("policy version overflow")
	}

	effectiveHeight := uint64(ctx.BlockHeight()) + 1
	oldRecoveryKey.InactiveFromHeight = effectiveHeight
	if err := m.SetKey(ctx, owner, oldRecoveryKey); err != nil {
		return nil, err
	}
	newRecoveryKey := types.PQCKeyRecord{
		Owner:           msg.Owner,
		KeyId:           ids[0],
		Algorithm:       msg.NewAlgorithm,
		PublicKey:       append([]byte(nil), msg.NewPublicKey...),
		Role:            types.KeyRole_KEY_ROLE_RECOVERY,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		CreatedHeight:   uint64(ctx.BlockHeight()),
		EffectiveHeight: effectiveHeight,
	}
	if err := m.SetKey(ctx, owner, newRecoveryKey); err != nil {
		return nil, err
	}
	policy.PendingSigningKeyId = policy.CurrentSigningKeyId
	policy.PendingRecoveryKeyId = newRecoveryKey.KeyId
	policy.PendingEffectiveHeight = effectiveHeight
	policy.PendingSelfEnforced = policy.SelfEnforced
	policy.PendingPolicyVersion = newPolicyVersion
	policy.PendingChangeKind = types.PolicyChangeKind_POLICY_CHANGE_KIND_ROTATE_RECOVERY
	policy.PendingCreatedHeight = uint64(ctx.BlockHeight())
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
		return nil, err
	}
	if err := m.CompactTerminalKeyHistory(
		ctx,
		owner,
		policy,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	); err != nil {
		return nil, err
	}

	emitPolicyEvent(
		ctx,
		"pqc_rotate_recovery_key",
		msg.Owner,
		newRecoveryKey.KeyId,
		effectiveHeight,
		newPolicyVersion,
	)
	return &types.MsgRotateRecoveryKeyResponse{
		NewKeyId:        newRecoveryKey.KeyId,
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   newPolicyVersion,
	}, nil
}

func (m msgServer) SetProtection(
	goCtx context.Context,
	msg *types.MsgSetProtection,
) (*types.MsgSetProtectionResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensurePQCTransactionAllowed(params); err != nil {
		return nil, err
	}
	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found, err := m.NormalizeAccountPolicy(ctx, owner)
	if err != nil {
		return nil, err
	}
	if !found || policy.CurrentSigningKeyId == 0 {
		return nil, types.ErrPolicyNotFound
	}
	if policy.HasPendingChange(ctx.BlockHeight()) {
		return nil, types.ErrPendingChange
	}
	if policy.SelfEnforced == msg.Enabled {
		return &types.MsgSetProtectionResponse{
			EffectiveHeight: uint64(ctx.BlockHeight()),
			PolicyVersion:   policy.PolicyVersion,
		}, nil
	}

	effectiveHeight := uint64(ctx.BlockHeight()) + 1
	newPolicyVersion := policy.PolicyVersion + 1
	if newPolicyVersion == 0 {
		return nil, types.ErrInvalidPolicyVersion.Wrap("policy version overflow")
	}
	policy.PendingSigningKeyId = policy.CurrentSigningKeyId
	policy.PendingEffectiveHeight = effectiveHeight
	policy.PendingSelfEnforced = msg.Enabled
	policy.PendingPolicyVersion = newPolicyVersion
	policy.PendingChangeKind = types.PolicyChangeKind_POLICY_CHANGE_KIND_SET_PROTECTION
	policy.PendingCreatedHeight = uint64(ctx.BlockHeight())
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}

	emitPolicyEvent(ctx, "pqc_set_protection", msg.Owner, policy.CurrentSigningKeyId, effectiveHeight, newPolicyVersion)
	return &types.MsgSetProtectionResponse{
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   newPolicyVersion,
	}, nil
}

func (m msgServer) RevokeKey(
	goCtx context.Context,
	msg *types.MsgRevokeKey,
) (*types.MsgRevokeKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensurePQCTransactionAllowed(params); err != nil {
		return nil, err
	}
	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found := m.GetEffectiveAccountPolicy(ctx, owner)
	if !found {
		return nil, types.ErrPolicyNotFound
	}
	if msg.KeyId == policy.CurrentSigningKeyId ||
		msg.KeyId == policy.PendingSigningKeyId ||
		msg.KeyId == policy.RecoveryKeyId ||
		msg.KeyId == policy.PendingRecoveryKeyId {
		return nil, types.ErrActiveKey
	}
	key, found := m.GetKey(ctx, owner, msg.KeyId)
	if !found {
		return nil, types.ErrKeyNotFound
	}
	key.Status = types.KeyStatus_KEY_STATUS_REVOKED
	if err := m.SetKey(ctx, owner, key); err != nil {
		return nil, err
	}
	if err := m.CompactTerminalKeyHistory(
		ctx,
		owner,
		policy,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	); err != nil {
		return nil, err
	}
	emitPolicyEvent(
		ctx,
		"pqc_revoke_key",
		msg.Owner,
		key.KeyId,
		uint64(ctx.BlockHeight()),
		policy.PolicyVersion,
	)
	return &types.MsgRevokeKeyResponse{}, nil
}

func (m msgServer) RecoverKey(
	goCtx context.Context,
	msg *types.MsgRecoverKey,
) (*types.MsgRecoverKeyResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensureRecoveryAllowed(params); err != nil {
		return nil, err
	}
	recoveryDelay := params.EffectiveRecoveryDelayBlocks()
	if msg.ExpectedRecoveryDelayBlocks != recoveryDelay {
		return nil, types.ErrInvalidParams.Wrapf(
			"recovery delay mismatch: message expects %d blocks, chain requires %d",
			msg.ExpectedRecoveryDelayBlocks,
			recoveryDelay,
		)
	}
	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found, err := m.NormalizeAccountPolicy(ctx, owner)
	if err != nil {
		return nil, err
	}
	if !found || policy.RecoveryKeyId == 0 || policy.RecoveryKeyId != msg.RecoveryKeyId {
		return nil, types.ErrUnauthorized.Wrap("recovery key does not match account policy")
	}
	if policy.HasPendingChange(ctx.BlockHeight()) {
		return nil, types.ErrPendingChange
	}
	recoveryKey, found := m.GetKey(ctx, owner, msg.RecoveryKeyId)
	if !found || recoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
		!recoveryKey.IsEffective(ctx.BlockHeight()) {
		return nil, types.ErrKeyNotFound.Wrap("active recovery key")
	}
	if err := types.ValidateDistinctRoleKeys(
		msg.NewSigningAlgorithm,
		msg.NewSigningPublicKey,
		recoveryKey.Algorithm,
		recoveryKey.PublicKey,
	); err != nil {
		return nil, err
	}

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewSigningKeyId,
		1,
	)
	if err != nil {
		return nil, err
	}

	newPolicyVersion := policy.PolicyVersion + 1
	if newPolicyVersion == 0 {
		return nil, types.ErrInvalidPolicyVersion.Wrap("policy version overflow")
	}
	if ctx.BlockHeight() < 0 || uint64(ctx.BlockHeight()) > math.MaxUint64-recoveryDelay {
		return nil, types.ErrInvalidPolicyVersion.Wrap("recovery activation height overflow")
	}
	requestHeight := uint64(ctx.BlockHeight())
	effectiveHeight := requestHeight + recoveryDelay
	if oldKey, exists := m.GetKey(ctx, owner, policy.CurrentSigningKeyId); exists {
		oldKey.InactiveFromHeight = effectiveHeight
		if err := m.SetKey(ctx, owner, oldKey); err != nil {
			return nil, err
		}
	}
	newKey := types.PQCKeyRecord{
		Owner:           msg.Owner,
		KeyId:           ids[0],
		Algorithm:       msg.NewSigningAlgorithm,
		PublicKey:       append([]byte(nil), msg.NewSigningPublicKey...),
		Role:            types.KeyRole_KEY_ROLE_SIGNING,
		Status:          types.KeyStatus_KEY_STATUS_LIVE,
		CreatedHeight:   uint64(ctx.BlockHeight()),
		EffectiveHeight: effectiveHeight,
	}
	if err := m.SetKey(ctx, owner, newKey); err != nil {
		return nil, err
	}
	policy.PendingSigningKeyId = newKey.KeyId
	policy.PendingEffectiveHeight = effectiveHeight
	policy.PendingSelfEnforced = policy.SelfEnforced
	policy.PendingPolicyVersion = newPolicyVersion
	policy.PendingChangeKind = types.PolicyChangeKind_POLICY_CHANGE_KIND_RECOVER_SIGNING
	policy.PendingCreatedHeight = requestHeight
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
		return nil, err
	}
	if err := m.CompactTerminalKeyHistory(
		ctx,
		owner,
		policy,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	); err != nil {
		return nil, err
	}

	emitPolicyEvent(ctx, "pqc_recover_key", msg.Owner, newKey.KeyId, effectiveHeight, newPolicyVersion)
	return &types.MsgRecoverKeyResponse{
		NewSigningKeyId: newKey.KeyId,
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   newPolicyVersion,
		RequestHeight:   requestHeight,
	}, nil
}

func (m msgServer) CancelRecovery(
	goCtx context.Context,
	msg *types.MsgCancelRecovery,
) (*types.MsgCancelRecoveryResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := execution.RequireLifecycleMessage(ctx, msg); err != nil {
		return nil, err
	}
	params := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if err := ensureRecoveryAllowed(params); err != nil {
		return nil, err
	}

	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	policy, found := m.GetAccountPolicy(ctx, owner)
	if !found || !policy.HasPendingRecovery(ctx.BlockHeight()) {
		return nil, types.ErrNoPendingRecovery
	}
	if policy.PendingSigningKeyId != msg.ExpectedPendingSigningKeyId ||
		policy.PendingPolicyVersion != msg.ExpectedPendingPolicyVersion {
		return nil, types.ErrNoPendingRecovery.Wrap("pending recovery identifiers do not match")
	}
	if policy.CurrentSigningKeyId == 0 || policy.PendingSigningKeyId == policy.CurrentSigningKeyId {
		return nil, types.ErrInconsistentState.Wrap("recovery does not replace an active signing key")
	}

	currentKey, found := m.GetKey(ctx, owner, policy.CurrentSigningKeyId)
	if !found || currentKey.Role != types.KeyRole_KEY_ROLE_SIGNING ||
		!currentKey.IsEffective(ctx.BlockHeight()) ||
		currentKey.InactiveFromHeight != policy.PendingEffectiveHeight {
		return nil, types.ErrInconsistentState.Wrap("current signing key cannot cancel pending recovery")
	}
	pendingKey, found := m.GetKey(ctx, owner, policy.PendingSigningKeyId)
	if !found || pendingKey.Role != types.KeyRole_KEY_ROLE_SIGNING ||
		pendingKey.Status != types.KeyStatus_KEY_STATUS_LIVE ||
		pendingKey.EffectiveHeight != policy.PendingEffectiveHeight ||
		pendingKey.CreatedHeight != policy.PendingCreatedHeight {
		return nil, types.ErrInconsistentState.Wrap("pending recovery signing key is unavailable")
	}

	currentKey.InactiveFromHeight = 0
	if err := m.SetKey(ctx, owner, currentKey); err != nil {
		return nil, err
	}
	pendingKey.Status = types.KeyStatus_KEY_STATUS_REVOKED
	if err := m.SetKey(ctx, owner, pendingKey); err != nil {
		return nil, err
	}
	cancelledKeyID := policy.PendingSigningKeyId
	policy.ClearPendingChange()
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.CompactTerminalKeyHistory(
		ctx,
		owner,
		policy,
		params.EffectiveMaxRetainedKeyRecordsPerRole(),
	); err != nil {
		return nil, err
	}

	emitPolicyEvent(
		ctx,
		"pqc_cancel_recovery",
		msg.Owner,
		cancelledKeyID,
		uint64(ctx.BlockHeight()),
		policy.PolicyVersion,
	)
	return &types.MsgCancelRecoveryResponse{
		CancelledSigningKeyId: cancelledKeyID,
		PolicyVersion:         policy.PolicyVersion,
	}, nil
}

func (m msgServer) UpdateParams(
	goCtx context.Context,
	msg *types.MsgUpdateParams,
) (*types.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if msg.Authority != m.Authority() {
		return nil, types.ErrInvalidAuthority
	}
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	current := m.GetParams(ctx).Effective(ctx.BlockHeight())
	if !types.EqualNetworkID(current.NetworkId, msg.Params.NetworkId) {
		return nil, types.ErrInvalidParams.Wrap("network_id is immutable after genesis")
	}
	if current.GovernanceSafetyDelayBlocks != msg.Params.GovernanceSafetyDelayBlocks {
		return nil, types.ErrInvalidParams.Wrap(
			"governance_safety_delay_blocks is immutable after genesis",
		)
	}
	if current.MaxEmergencyDurationBlocks != msg.Params.MaxEmergencyDurationBlocks {
		return nil, types.ErrInvalidParams.Wrap(
			"max_emergency_duration_blocks is immutable after genesis",
		)
	}
	if current.EffectiveRecoveryDelayBlocks() != msg.Params.EffectiveRecoveryDelayBlocks() {
		return nil, types.ErrInvalidParams.Wrap(
			"recovery_delay_blocks is immutable after genesis",
		)
	}
	requested := msg.Params
	lockedCutoff := current.RegistrationCutoffHeight
	if lockedCutoff == 0 && current.Pending != nil {
		lockedCutoff = current.Pending.RegistrationCutoffHeight
	}
	if lockedCutoff != 0 && requested.RegistrationCutoffHeight != lockedCutoff {
		return nil, types.ErrInvalidParams.Wrap("registration cutoff is irreversible once scheduled or active")
	}
	var effectiveHeight uint64
	currentScheduled := current.AsScheduled()
	requestedScheduled := requested.AsScheduled()
	if requestedScheduled.RegistrationMode < currentScheduled.RegistrationMode {
		return nil, types.ErrInvalidParams.Wrap(
			"registration mode cannot be relaxed after activation",
		)
	}
	if currentScheduled.Equal(requestedScheduled) {
		// A proposal equal to the active state is an explicit cancellation of a
		// future schedule. This lets governance defuse a queued restrictive
		// change without waiting for it to activate first.
		current.Pending = nil
		current.PendingActivationHeight = 0
	} else {
		delay := uint64(1)
		if requiresGovernanceSafetyDelay(currentScheduled, requestedScheduled) {
			delay = current.GovernanceSafetyDelayBlocks
		}
		if ctx.BlockHeight() < 0 || uint64(ctx.BlockHeight()) > math.MaxUint64-delay {
			return nil, types.ErrInvalidParams.Wrap("parameter activation height overflow")
		}
		effectiveHeight = uint64(ctx.BlockHeight()) + delay
		if requestedScheduled.EmergencyMode != types.EmergencyMode_EMERGENCY_MODE_NORMAL {
			if effectiveHeight > math.MaxUint64-current.MaxEmergencyDurationBlocks {
				return nil, types.ErrInvalidParams.Wrap("emergency expiration height overflow")
			}
			requestedScheduled.EmergencyExpiresHeight =
				effectiveHeight + current.MaxEmergencyDurationBlocks
		}
		current.Pending = new(types.ScheduledParams)
		*current.Pending = requestedScheduled
		current.PendingActivationHeight = effectiveHeight
	}
	if err := m.SetParams(ctx, current); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{
		ActivationHeight: effectiveHeight,
	}, nil
}

func requiresGovernanceSafetyDelay(current, requested types.ScheduledParams) bool {
	if requested.EnforcementMode > current.EnforcementMode ||
		requested.RegistrationMode > current.RegistrationMode ||
		(current.RegistrationCutoffHeight == 0 && requested.RegistrationCutoffHeight != 0) ||
		requested.SignatureVerificationGas > current.SignatureVerificationGas ||
		requested.ProofVerificationGas > current.ProofVerificationGas ||
		requested.MaxPqcSigners < current.MaxPqcSigners ||
		requested.MaxPqcAuthBytes < current.MaxPqcAuthBytes {
		return true
	}

	allowed := make(map[types.Algorithm]struct{}, len(requested.AllowedAlgorithms))
	for _, algorithm := range requested.AllowedAlgorithms {
		allowed[algorithm] = struct{}{}
	}
	for _, algorithm := range current.AllowedAlgorithms {
		if _, found := allowed[algorithm]; !found {
			return true
		}
	}
	return false
}

func ensureKeyChangeAllowed(params types.Params) error {
	if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS {
		return types.ErrEmergencyPause
	}
	if err := ensurePQCTransactionAllowed(params); err != nil {
		return err
	}
	return nil
}

func ensurePQCTransactionAllowed(params types.Params) error {
	if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return types.ErrEmergencyPause
	}
	return nil
}

// Recovery operations are the only lifecycle escape hatches that remain open
// during either emergency mode. Ante still requires exactly one top-level
// recovery message and verifies its operation-specific authorization.
func ensureRecoveryAllowed(params types.Params) error {
	switch params.EmergencyMode {
	case types.EmergencyMode_EMERGENCY_MODE_NORMAL,
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS,
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS:
		return nil
	default:
		return types.ErrEmergencyPause
	}
}

func VerifyKeyProof(
	ctx sdk.Context,
	params types.Params,
	owner string,
	keyID uint64,
	algorithm types.Algorithm,
	publicKey []byte,
	role types.KeyRole,
	purpose string,
	currentPolicyVersion uint64,
	proof []byte,
	signatureContext []byte,
) error {
	if !params.IsAlgorithmAllowed(algorithm) {
		return fmt.Errorf("%w: %d", types.ErrUnsupportedAlgorithm, algorithm)
	}
	doc := types.KeyProofDocV1{
		FormatVersion:        types.FormatVersionV1,
		NetworkId:            params.NetworkId,
		ChainId:              ctx.ChainID(),
		Owner:                owner,
		ProposedKeyId:        keyID,
		Algorithm:            algorithm,
		PublicKey:            publicKey,
		Role:                 role,
		Purpose:              purpose,
		CurrentPolicyVersion: currentPolicyVersion,
	}
	signBytes, err := types.MarshalKeyProofDocV1(doc)
	if err != nil {
		return err
	}
	cryptoAlgorithm, err := types.CryptoAlgorithm(algorithm)
	if err != nil {
		return err
	}
	ctx.GasMeter().ConsumeGas(params.EffectiveProofVerificationGas(), "pqcauth key proof verification")
	start := time.Now()
	verifyErr := pqccrypto.Verify(cryptoAlgorithm, publicKey, signBytes, signatureContext, proof)
	types.RecordVerification(start, types.VerificationKindKeyProof, verifyErr)
	if verifyErr != nil {
		return errorsmod.Wrap(types.ErrInvalidKeyProof, verifyErr.Error())
	}
	return nil
}

func emitPolicyEvent(
	ctx sdk.Context,
	eventType string,
	owner string,
	keyID uint64,
	effectiveHeight uint64,
	policyVersion uint64,
) {
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		eventType,
		sdk.NewAttribute("owner", owner),
		sdk.NewAttribute("key_id", fmt.Sprintf("%d", keyID)),
		sdk.NewAttribute("effective_height", fmt.Sprintf("%d", effectiveHeight)),
		sdk.NewAttribute("policy_version", fmt.Sprintf("%d", policyVersion)),
	))
}
