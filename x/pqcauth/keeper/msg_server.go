package keeper

import (
	"context"
	"fmt"
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
	if err := ensureKeyChangeAllowed(ctx, params, true); err != nil {
		return nil, err
	}

	owner, _ := sdk.AccAddressFromBech32(msg.Owner)
	if _, found := m.GetAccountPolicy(ctx, owner); found {
		return nil, types.ErrAlreadyRegistered
	}

	keyCount := uint64(1)
	if len(msg.RecoveryPublicKey) != 0 {
		keyCount++
	}
	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedSigningKeyId,
		keyCount,
		params.EffectiveMaxKeysPerAccount(),
	)
	if err != nil {
		return nil, err
	}

	var recoveryKeyID uint64
	if keyCount == 2 {
		recoveryKeyID = ids[1]
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
	if recoveryKeyID != 0 {
		recoveryKey := types.PQCKeyRecord{
			Owner:           msg.Owner,
			KeyId:           recoveryKeyID,
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
	}

	const initialPolicyVersion = 1
	policy := types.AccountPolicy{
		Owner:                  msg.Owner,
		PendingSigningKeyId:    signingKey.KeyId,
		PendingEffectiveHeight: effectiveHeight,
		PendingSelfEnforced:    msg.SelfEnforce,
		PendingPolicyVersion:   initialPolicyVersion,
		RecoveryKeyId:          recoveryKeyID,
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
		RecoveryKeyId:   recoveryKeyID,
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
	if err := ensureKeyChangeAllowed(ctx, params, false); err != nil {
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

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewKeyId,
		1,
		params.EffectiveMaxKeysPerAccount(),
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
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
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
	if err := ensureKeyChangeAllowed(ctx, params, false); err != nil {
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

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewKeyId,
		1,
		params.EffectiveMaxKeysPerAccount(),
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
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
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
	if err := ensurePQCTransactionAllowed(m.GetParams(ctx).Effective(ctx.BlockHeight())); err != nil {
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
	if err := ensurePQCTransactionAllowed(m.GetParams(ctx).Effective(ctx.BlockHeight())); err != nil {
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
	if err := ensureKeyChangeAllowed(ctx, params, false); err != nil {
		return nil, err
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

	ids, sequence, err := m.ReserveKeyIDs(
		ctx,
		owner,
		msg.ExpectedNewSigningKeyId,
		1,
		params.EffectiveMaxKeysPerAccount(),
	)
	if err != nil {
		return nil, err
	}

	newPolicyVersion := policy.PolicyVersion + 1
	if newPolicyVersion == 0 {
		return nil, types.ErrInvalidPolicyVersion.Wrap("policy version overflow")
	}
	effectiveHeight := uint64(ctx.BlockHeight()) + 1
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
	if err := m.SetAccountPolicy(ctx, owner, policy); err != nil {
		return nil, err
	}
	if err := m.SetKeySequence(ctx, owner, sequence); err != nil {
		return nil, err
	}

	emitPolicyEvent(ctx, "pqc_recover_key", msg.Owner, newKey.KeyId, effectiveHeight, newPolicyVersion)
	return &types.MsgRecoverKeyResponse{
		NewSigningKeyId: newKey.KeyId,
		EffectiveHeight: effectiveHeight,
		PolicyVersion:   newPolicyVersion,
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
	requested := msg.Params
	if requested.Pending != nil || requested.PendingActivationHeight != 0 {
		return nil, types.ErrInvalidParams.Wrap("governance message cannot supply a nested pending schedule")
	}
	lockedCutoff := current.RegistrationCutoffHeight
	if lockedCutoff == 0 && current.Pending != nil {
		lockedCutoff = current.Pending.RegistrationCutoffHeight
	}
	if lockedCutoff != 0 && requested.RegistrationCutoffHeight != lockedCutoff {
		return nil, types.ErrInvalidParams.Wrap("registration cutoff is irreversible once scheduled or active")
	}
	if err := m.ensureLifetimeKeyQuotaCompatible(ctx, requested.MaxKeysPerAccount); err != nil {
		return nil, err
	}
	var effectiveHeight uint64
	currentScheduled := current.AsScheduled()
	requestedScheduled := requested.AsScheduled()
	if !currentScheduled.Equal(requestedScheduled) {
		effectiveHeight = uint64(ctx.BlockHeight()) + 1
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

// ensureLifetimeKeyQuotaCompatible prevents governance from scheduling a key
// quota that is already smaller than an account's append-only key-id space.
// Revocation does not release identifiers, so accepting such a reduction would
// permanently strand affected accounts on their current signing key.
func (m msgServer) ensureLifetimeKeyQuotaCompatible(ctx sdk.Context, requested uint32) error {
	var incompatible types.AccountKeySequence
	m.IterateAllSequences(ctx, func(sequence types.AccountKeySequence) bool {
		consumed := sequence.NextKeyId - 1
		if consumed > uint64(requested) {
			incompatible = sequence
			return true
		}
		return false
	})
	if incompatible.Owner == "" {
		return nil
	}
	return types.ErrInvalidParams.Wrapf(
		"max_keys_per_account %d is below the %d lifetime key records already allocated to %s",
		requested,
		incompatible.NextKeyId-1,
		incompatible.Owner,
	)
}

func ensureKeyChangeAllowed(ctx sdk.Context, params types.Params, enforceRegistrationCutoff bool) error {
	if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS {
		return types.ErrEmergencyPause
	}
	if err := ensurePQCTransactionAllowed(params); err != nil {
		return err
	}
	if enforceRegistrationCutoff &&
		params.RegistrationCutoffHeight != 0 &&
		uint64(ctx.BlockHeight()) >= params.RegistrationCutoffHeight {
		return types.ErrRegistrationClosed
	}
	return nil
}

func ensurePQCTransactionAllowed(params types.Params) error {
	if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return types.ErrEmergencyPause
	}
	return nil
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
