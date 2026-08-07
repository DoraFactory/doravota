package ante

import (
	"time"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func (d VerifyPQCDecorator) validateLifecycleProofs(
	ctx sdk.Context,
	tx sdk.Tx,
	params types.Params,
	simulate bool,
) error {
	for _, rawMessage := range tx.GetMsgs() {
		switch message := rawMessage.(type) {
		case *types.MsgRegisterKey:
			if len(tx.GetMsgs()) != 1 {
				return errorsmod.Wrap(types.ErrInvalidKeyProof, "PQC lifecycle messages cannot be batched")
			}
			if err := message.ValidateBasic(); err != nil {
				return err
			}
			if err := keyChangeAllowed(ctx, params, true); err != nil {
				return err
			}
			owner := sdk.MustAccAddressFromBech32(message.Owner)
			if _, found := d.keeper.GetAccountPolicy(ctx, owner); found {
				return types.ErrAlreadyRegistered
			}
			ids, _, err := d.keeper.ReserveKeyIDs(
				ctx,
				owner,
				message.ExpectedSigningKeyId,
				2,
			)
			if err != nil {
				return err
			}
			if err := verifyLifecycleKeyProof(
				ctx,
				params,
				simulate,
				message.Owner,
				ids[0],
				message.SigningAlgorithm,
				message.SigningPublicKey,
				types.KeyRole_KEY_ROLE_SIGNING,
				types.PurposeRegisterSigning,
				0,
				message.SigningKeyProof,
				[]byte(types.RegisterProofContext),
			); err != nil {
				return err
			}
			if err := verifyLifecycleKeyProof(
				ctx,
				params,
				simulate,
				message.Owner,
				ids[1],
				message.RecoveryAlgorithm,
				message.RecoveryPublicKey,
				types.KeyRole_KEY_ROLE_RECOVERY,
				types.PurposeRegisterRecovery,
				0,
				message.RecoveryKeyProof,
				[]byte(types.RegisterProofContext),
			); err != nil {
				return err
			}
		case *types.MsgRotateKey:
			if len(tx.GetMsgs()) != 1 {
				return errorsmod.Wrap(types.ErrInvalidKeyProof, "PQC lifecycle messages cannot be batched")
			}
			if err := message.ValidateBasic(); err != nil {
				return err
			}
			if err := keyChangeAllowed(ctx, params, false); err != nil {
				return err
			}
			owner := sdk.MustAccAddressFromBech32(message.Owner)
			policy, found := d.keeper.GetEffectiveAccountPolicy(ctx, owner)
			if !found || policy.CurrentSigningKeyId == 0 {
				return types.ErrPolicyNotFound
			}
			if policy.HasPendingChange(ctx.BlockHeight()) {
				return types.ErrPendingChange
			}
			recoveryKey, found := d.keeper.GetKey(ctx, owner, policy.RecoveryKeyId)
			if !found ||
				recoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
				!recoveryKey.IsEffective(ctx.BlockHeight()) {
				return types.ErrKeyNotFound
			}
			if err := types.ValidateDistinctRoleKeys(
				message.NewAlgorithm,
				message.NewPublicKey,
				recoveryKey.Algorithm,
				recoveryKey.PublicKey,
			); err != nil {
				return err
			}
			ids, _, err := d.keeper.ReserveKeyIDs(
				ctx,
				owner,
				message.ExpectedNewKeyId,
				1,
			)
			if err != nil {
				return err
			}
			if err := verifyLifecycleKeyProof(
				ctx,
				params,
				simulate,
				message.Owner,
				ids[0],
				message.NewAlgorithm,
				message.NewPublicKey,
				types.KeyRole_KEY_ROLE_SIGNING,
				types.PurposeRotateSigning,
				policy.PolicyVersion,
				message.NewKeyProof,
				[]byte(types.RotateProofContext),
			); err != nil {
				return err
			}
		case *types.MsgRotateRecoveryKey:
			if len(tx.GetMsgs()) != 1 {
				return errorsmod.Wrap(types.ErrInvalidKeyProof, "PQC lifecycle messages cannot be batched")
			}
			if err := message.ValidateBasic(); err != nil {
				return err
			}
			if err := keyChangeAllowed(ctx, params, false); err != nil {
				return err
			}
			owner := sdk.MustAccAddressFromBech32(message.Owner)
			policy, found := d.keeper.GetEffectiveAccountPolicy(ctx, owner)
			if !found || policy.CurrentSigningKeyId == 0 || policy.RecoveryKeyId == 0 {
				return types.ErrPolicyNotFound
			}
			if policy.HasPendingChange(ctx.BlockHeight()) {
				return types.ErrPendingChange
			}
			recoveryKey, found := d.keeper.GetKey(ctx, owner, policy.RecoveryKeyId)
			if !found ||
				recoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
				!recoveryKey.IsEffective(ctx.BlockHeight()) {
				return types.ErrKeyNotFound
			}
			signingKey, found := d.keeper.GetKey(ctx, owner, policy.CurrentSigningKeyId)
			if !found ||
				signingKey.Role != types.KeyRole_KEY_ROLE_SIGNING ||
				!signingKey.IsEffective(ctx.BlockHeight()) {
				return types.ErrKeyNotFound
			}
			if err := types.ValidateDistinctRoleKeys(
				signingKey.Algorithm,
				signingKey.PublicKey,
				message.NewAlgorithm,
				message.NewPublicKey,
			); err != nil {
				return err
			}
			ids, _, err := d.keeper.ReserveKeyIDs(
				ctx,
				owner,
				message.ExpectedNewKeyId,
				1,
			)
			if err != nil {
				return err
			}
			if err := verifyLifecycleKeyProof(
				ctx,
				params,
				simulate,
				message.Owner,
				ids[0],
				message.NewAlgorithm,
				message.NewPublicKey,
				types.KeyRole_KEY_ROLE_RECOVERY,
				types.PurposeRotateRecovery,
				policy.PolicyVersion,
				message.NewKeyProof,
				[]byte(types.RotateRecoveryContext),
			); err != nil {
				return err
			}
		case *types.MsgRecoverKey:
			if len(tx.GetMsgs()) != 1 {
				return errorsmod.Wrap(types.ErrInvalidKeyProof, "PQC lifecycle messages cannot be batched")
			}
			if err := message.ValidateBasic(); err != nil {
				return err
			}
			if err := keyChangeAllowed(ctx, params, false); err != nil {
				return err
			}
			owner := sdk.MustAccAddressFromBech32(message.Owner)
			policy, found := d.keeper.GetEffectiveAccountPolicy(ctx, owner)
			if !found || policy.RecoveryKeyId != message.RecoveryKeyId {
				return types.ErrUnauthorized
			}
			if policy.HasPendingChange(ctx.BlockHeight()) {
				return types.ErrPendingChange
			}
			recoveryKey, found := d.keeper.GetKey(ctx, owner, message.RecoveryKeyId)
			if !found ||
				recoveryKey.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
				!recoveryKey.IsEffective(ctx.BlockHeight()) {
				return types.ErrKeyNotFound
			}
			if err := types.ValidateDistinctRoleKeys(
				message.NewSigningAlgorithm,
				message.NewSigningPublicKey,
				recoveryKey.Algorithm,
				recoveryKey.PublicKey,
			); err != nil {
				return err
			}
			ids, _, err := d.keeper.ReserveKeyIDs(
				ctx,
				owner,
				message.ExpectedNewSigningKeyId,
				1,
			)
			if err != nil {
				return err
			}
			if err := verifyLifecycleKeyProof(
				ctx,
				params,
				simulate,
				message.Owner,
				ids[0],
				message.NewSigningAlgorithm,
				message.NewSigningPublicKey,
				types.KeyRole_KEY_ROLE_SIGNING,
				types.PurposeRecoverSigning,
				policy.PolicyVersion,
				message.NewSigningKeyProof,
				[]byte(types.RecoveryKeyProofContext),
			); err != nil {
				return err
			}
			recoverySignDoc, err := d.newRecoverySignDoc(
				ctx,
				tx,
				params,
				message,
				ids[0],
				policy.PolicyVersion,
			)
			if err != nil {
				return err
			}
			recoveryDoc, err := types.MarshalRecoverySignDocV1(recoverySignDoc)
			if err != nil {
				return err
			}
			algorithm, err := types.CryptoAlgorithm(recoveryKey.Algorithm)
			if err != nil {
				return err
			}
			ctx.GasMeter().ConsumeGas(
				params.EffectiveProofVerificationGas(),
				lifecycleProofGasDescriptor(simulate, "recovery signature"),
			)
			if !simulate {
				start := time.Now()
				verifyErr := pqccrypto.Verify(
					algorithm,
					recoveryKey.PublicKey,
					recoveryDoc,
					[]byte(types.RecoverySignatureContext),
					message.RecoverySignature,
				)
				types.RecordVerification(start, types.VerificationKindRecovery, verifyErr)
				if verifyErr != nil {
					return errorsmod.Wrap(types.ErrUnauthorized, "invalid recovery signature")
				}
			}
		case *types.MsgSetProtection, *types.MsgRevokeKey:
			if len(tx.GetMsgs()) != 1 {
				return errorsmod.Wrap(types.ErrInvalidKeyProof, "PQC lifecycle messages cannot be batched")
			}
		}
	}
	return nil
}

func (d VerifyPQCDecorator) newRecoverySignDoc(
	ctx sdk.Context,
	tx sdk.Tx,
	params types.Params,
	message *types.MsgRecoverKey,
	proposedSigningKeyID uint64,
	policyVersion uint64,
) (types.RecoverySignDocV1, error) {
	provider, ok := tx.(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(
			types.ErrInvalidKeyProof,
			"protobuf transaction is required for recovery authorization",
		)
	}
	signatureTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(
			types.ErrInvalidKeyProof,
			"recovery transaction does not expose signers",
		)
	}
	signers := signatureTx.GetSigners()
	signatures, err := signatureTx.GetSignaturesV2()
	if err != nil {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(types.ErrInvalidKeyProof, err.Error())
	}
	if len(signers) != len(signatures) {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(
			types.ErrInvalidKeyProof,
			"recovery signer metadata length mismatch",
		)
	}
	owner, err := sdk.AccAddressFromBech32(message.Owner)
	if err != nil {
		return types.RecoverySignDocV1{}, err
	}
	signerIndex := -1
	for index, signer := range signers {
		if signer.Equals(owner) {
			if signerIndex != -1 {
				return types.RecoverySignDocV1{}, errorsmod.Wrap(
					types.ErrInvalidKeyProof,
					"recovery owner appears more than once in signer metadata",
				)
			}
			signerIndex = index
		}
	}
	if signerIndex == -1 {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(
			types.ErrUnauthorized,
			"recovery owner is not a transaction signer",
		)
	}
	account := d.accountKeeper.GetAccount(ctx, owner)
	if account == nil {
		return types.RecoverySignDocV1{}, errorsmod.Wrap(
			types.ErrUnauthorized,
			"recovery owner account not found",
		)
	}
	return types.NewRecoverySignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		ctx.ChainID(),
		account.GetAccountNumber(),
		signatures[signerIndex].Sequence,
		uint32(signerIndex),
		owner.String(),
		message.Owner,
		message.RecoveryKeyId,
		proposedSigningKeyID,
		message.NewSigningAlgorithm,
		message.NewSigningPublicKey,
		policyVersion,
	)
}

func verifyLifecycleKeyProof(
	ctx sdk.Context,
	params types.Params,
	simulate bool,
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
	if !simulate {
		return pqckeeper.VerifyKeyProof(
			ctx,
			params,
			owner,
			keyID,
			algorithm,
			publicKey,
			role,
			purpose,
			currentPolicyVersion,
			proof,
			signatureContext,
		)
	}
	if !params.IsAlgorithmAllowed(algorithm) {
		return errorsmod.Wrapf(types.ErrUnsupportedAlgorithm, "%d", algorithm)
	}
	ctx.GasMeter().ConsumeGas(
		params.EffectiveProofVerificationGas(),
		lifecycleProofGasDescriptor(true, "key proof"),
	)
	return nil
}

func lifecycleProofGasDescriptor(simulate bool, proofKind string) string {
	if simulate {
		return "simulated pqcauth " + proofKind + " verification"
	}
	return "pqcauth " + proofKind + " verification"
}

func topLevelLifecycleMessage(tx sdk.Tx) sdk.Msg {
	if len(tx.GetMsgs()) != 1 {
		return nil
	}
	switch tx.GetMsgs()[0].(type) {
	case *types.MsgRegisterKey,
		*types.MsgRotateKey,
		*types.MsgRotateRecoveryKey,
		*types.MsgSetProtection,
		*types.MsgRevokeKey,
		*types.MsgRecoverKey:
		return tx.GetMsgs()[0]
	default:
		return nil
	}
}

func keyChangeAllowed(ctx sdk.Context, params types.Params, enforceRegistrationCutoff bool) error {
	if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS ||
		params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return types.ErrEmergencyPause
	}
	if enforceRegistrationCutoff &&
		params.RegistrationCutoffHeight != 0 &&
		uint64(ctx.BlockHeight()) >= params.RegistrationCutoffHeight {
		return types.ErrRegistrationClosed
	}
	return nil
}
