package ante

import (
	"fmt"
	"time"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type protoTxProvider interface {
	GetProtoTx() *txtypes.Tx
}

type VerifyPQCDecorator struct {
	keeper        pqckeeper.Keeper
	accountKeeper authante.AccountKeeper
}

type preparedPQCVerification struct {
	entry         types.SignerPQCSignature
	key           types.PQCKeyRecord
	accountNumber uint64
}

func NewVerifyPQCDecorator(
	moduleKeeper pqckeeper.Keeper,
	accountKeeper authante.AccountKeeper,
) VerifyPQCDecorator {
	return VerifyPQCDecorator{keeper: moduleKeeper, accountKeeper: accountKeeper}
}

func (d VerifyPQCDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	stateCtx := pqcStateContext(ctx, simulate)
	params := d.keeper.GetParams(stateCtx).Effective(stateCtx.BlockHeight())
	extension, found, cached := getValidatedExtension(ctx, tx)
	if !cached {
		var err error
		extension, found, err = ExtractExtension(tx, params)
		if err != nil {
			return ctx, err
		}
	}
	if err := d.validateLifecycleProofs(stateCtx, tx, params, simulate); err != nil {
		return ctx, err
	}
	lifecycleMessage := topLevelLifecycleMessage(tx)

	signatureTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, "transaction does not expose signers")
	}
	rawSigners, err := signatureTx.GetSigners()
	if err != nil {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, err.Error())
	}
	signers := make([]sdk.AccAddress, len(rawSigners))
	for index := range rawSigners {
		signers[index] = sdk.AccAddress(rawSigners[index])
	}
	signatures, err := signatureTx.GetSignaturesV2()
	if err != nil {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, err.Error())
	}
	if len(signers) != len(signatures) {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, "signer metadata length mismatch")
	}

	entries := make(map[uint32]types.SignerPQCSignature)
	if found {
		for _, entry := range extension.Signatures {
			if int(entry.SignerIndex) >= len(signers) {
				return ctx, errorsmod.Wrapf(
					types.ErrInvalidExtension,
					"signer index %d is out of range",
					entry.SignerIndex,
				)
			}
			entries[entry.SignerIndex] = entry
		}
	}

	requiredCount := 0
	missingRequiredCount := 0
	for index, signer := range signers {
		_, policy, hasActiveKey := d.keeper.GetActiveSigningKey(stateCtx, signer)
		policyExpectsActiveKey := policy.CurrentSigningKeyId != 0
		substituted := d.lifecycleProofSubstitutesPQC(stateCtx, tx, signer, hasActiveKey)
		if policyExpectsActiveKey && !hasActiveKey && !substituted {
			return ctx, errorsmod.Wrapf(
				types.ErrInconsistentState,
				"policy for signer index %d references unavailable signing key %d",
				index,
				policy.CurrentSigningKeyId,
			)
		}
		required := pqcRequired(params.EnforcementMode, policy, policyExpectsActiveKey)
		if hasActiveKey && lifecycleRequiresActivePQC(tx, signer) {
			required = true
		}
		if required {
			requiredCount++
		}
		_, hasEntry := entries[uint32(index)]
		if required && !hasEntry && !substituted {
			if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
				return ctx, types.ErrEmergencyPause
			}
			if !simulate {
				return ctx, errorsmod.Wrapf(
					types.ErrPQCRequired,
					"missing signer index %d",
					index,
				)
			}
			missingRequiredCount++
		}
	}

	if (found || requiredCount > 0) && len(signers) > 0 {
		if err := requireDirectSignMode(tx, simulate); err != nil {
			return ctx, err
		}
	}

	preparedVerifications := make([]preparedPQCVerification, 0)
	if found {
		preparedVerifications = make(
			[]preparedPQCVerification,
			0,
			len(extension.Signatures),
		)
		for _, entry := range extension.Signatures {
			signer := signers[entry.SignerIndex]
			if entry.Signer != signer.String() {
				return ctx, errorsmod.Wrapf(
					types.ErrInvalidExtension,
					"signer address mismatch at index %d",
					entry.SignerIndex,
				)
			}
			key, policy, active := d.keeper.GetActiveSigningKey(stateCtx, signer)
			if !active {
				return ctx, errorsmod.Wrapf(types.ErrKeyNotFound, "signer index %d", entry.SignerIndex)
			}
			if entry.KeyId != key.KeyId ||
				entry.Algorithm != key.Algorithm ||
				entry.PolicyVersion != policy.PolicyVersion {
				return ctx, errorsmod.Wrapf(
					types.ErrInvalidExtension,
					"key or policy mismatch at signer index %d",
					entry.SignerIndex,
				)
			}
			if !params.IsAlgorithmAllowed(entry.Algorithm) {
				return ctx, fmt.Errorf("%w: %d", types.ErrUnsupportedAlgorithm, entry.Algorithm)
			}
			account := d.accountKeeper.GetAccount(stateCtx, signer)
			if account == nil {
				return ctx, errorsmod.Wrapf(
					types.ErrUnauthorized,
					"account not found for signer index %d",
					entry.SignerIndex,
				)
			}
			preparedVerifications = append(preparedVerifications, preparedPQCVerification{
				entry:         entry,
				key:           key,
				accountNumber: account.GetAccountNumber(),
			})
		}
	}

	if simulate {
		verificationCount := len(preparedVerifications) + missingRequiredCount
		for i := 0; i < verificationCount; i++ {
			ctx.GasMeter().ConsumeGas(
				params.EffectiveSignatureVerificationGas(),
				"simulated pqcauth signature verification",
			)
		}
		return continueWithLifecycleAuthorization(ctx, tx, simulate, lifecycleMessage, next)
	}
	if !found {
		return continueWithLifecycleAuthorization(ctx, tx, simulate, lifecycleMessage, next)
	}

	provider, ok := tx.(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, "protobuf transaction is required")
	}
	protoTx := provider.GetProtoTx()
	if len(protoTx.AuthInfo.GetSignerInfos()) != len(signers) {
		return ctx, errorsmod.Wrap(types.ErrInvalidExtension, "AuthInfo signer length mismatch")
	}
	canonicalTx, err := types.NewCanonicalPQCTransaction(protoTx)
	if err != nil {
		return ctx, err
	}

	for _, prepared := range preparedVerifications {
		entry := prepared.entry
		signDoc := types.NewPQCSignDocV1FromCanonical(
			canonicalTx,
			params.NetworkId,
			ctx.ChainID(),
			prepared.accountNumber,
			signatures[entry.SignerIndex].Sequence,
			entry.SignerIndex,
			entry.Signer,
			entry.KeyId,
			entry.Algorithm,
			entry.PolicyVersion,
		)
		signBytes, err := types.MarshalPQCSignDocV1(signDoc)
		if err != nil {
			return ctx, err
		}
		algorithm, err := types.CryptoAlgorithm(entry.Algorithm)
		if err != nil {
			return ctx, err
		}
		ctx.GasMeter().ConsumeGas(
			params.EffectiveSignatureVerificationGas(),
			"pqcauth transaction signature verification",
		)
		start := time.Now()
		verifyErr := pqccrypto.Verify(
			algorithm,
			prepared.key.PublicKey,
			signBytes,
			[]byte(types.TxSignatureContext),
			entry.Signature,
		)
		types.RecordVerification(start, types.VerificationKindTransaction, verifyErr)
		if verifyErr != nil {
			return ctx, errorsmod.Wrapf(
				types.ErrUnauthorized,
				"invalid PQC signature at signer index %d",
				entry.SignerIndex,
			)
		}
	}
	return continueWithLifecycleAuthorization(ctx, tx, simulate, lifecycleMessage, next)
}

func continueWithLifecycleAuthorization(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	lifecycleMessage sdk.Msg,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	if lifecycleMessage != nil {
		var err error
		ctx, err = execution.AuthorizeLifecycleMessage(ctx, lifecycleMessage)
		if err != nil {
			return ctx, err
		}
	}
	return next(ctx, tx, simulate)
}

func pqcRequired(
	mode types.EnforcementMode,
	policy types.AccountPolicy,
	registered bool,
) bool {
	if registered && policy.SelfEnforced {
		return true
	}
	switch mode {
	case types.EnforcementMode_ENFORCEMENT_MODE_DISABLED:
		return false
	case types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL:
		return false
	case types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED:
		return registered
	case types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED:
		return true
	default:
		return true
	}
}

func lifecycleRequiresActivePQC(tx sdk.Tx, signer sdk.AccAddress) bool {
	if len(tx.GetMsgs()) != 1 {
		return false
	}
	switch message := tx.GetMsgs()[0].(type) {
	case *types.MsgRotateKey:
		return message.Owner == signer.String()
	case *types.MsgRotateRecoveryKey:
		return message.Owner == signer.String()
	case *types.MsgSetProtection:
		return message.Owner == signer.String()
	case *types.MsgRevokeKey:
		return message.Owner == signer.String()
	default:
		return false
	}
}

func (d VerifyPQCDecorator) lifecycleProofSubstitutesPQC(
	ctx sdk.Context,
	tx sdk.Tx,
	signer sdk.AccAddress,
	hasActiveKey bool,
) bool {
	if len(tx.GetMsgs()) != 1 {
		return false
	}
	switch message := tx.GetMsgs()[0].(type) {
	case *types.MsgRegisterKey:
		return !hasActiveKey && message.Owner == signer.String()
	case *types.MsgRecoverKey:
		policy, found := d.keeper.GetEffectiveAccountPolicy(ctx, signer)
		return found && policy.RecoveryKeyId == message.RecoveryKeyId && message.Owner == signer.String()
	default:
		return false
	}
}
