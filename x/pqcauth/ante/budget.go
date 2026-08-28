package ante

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	cryptomultisig "github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// PQCVerificationCost describes every expensive post-quantum verification a
// transaction can reach after the cheap structural checks have passed.
type PQCVerificationCost struct {
	NativeSignatures  uint64
	PQCAuthSignatures uint64
	LifecycleProofs   uint64
}

func (c PQCVerificationCost) Total() uint64 {
	return c.NativeSignatures + c.PQCAuthSignatures + c.LifecycleProofs
}

type discoveredPQCAccountKey struct {
	signer string
	key    cryptotypes.PubKey
}

// PQCVerificationInspection is a deterministic, non-mutating preflight result.
// Account-key discoveries are committed only after PrepareProposal accepts the
// transaction, or while ProcessProposal preflights the proposal in order.
type PQCVerificationInspection struct {
	Cost       PQCVerificationCost
	discovered []discoveredPQCAccountKey
}

// PQCVerificationBudgetTracker follows public keys first published within the
// same proposal. That matters when a fresh native ML-DSA account includes its
// key in its first transaction and later transactions omit the already-known
// key from signer metadata.
type PQCVerificationBudgetTracker struct {
	accountKeeper authante.AccountKeeper
	knownKeys     map[string]cryptotypes.PubKey
}

func NewPQCVerificationBudgetTracker(
	accountKeeper authante.AccountKeeper,
) *PQCVerificationBudgetTracker {
	return &PQCVerificationBudgetTracker{
		accountKeeper: accountKeeper,
		knownKeys:     make(map[string]cryptotypes.PubKey),
	}
}

func (t *PQCVerificationBudgetTracker) Inspect(
	ctx sdk.Context,
	tx sdk.Tx,
	params types.Params,
) (PQCVerificationInspection, error) {
	inspection := PQCVerificationInspection{}
	extension, found, err := ExtractExtension(tx, params)
	if err != nil {
		return inspection, err
	}
	if found {
		inspection.Cost.PQCAuthSignatures = uint64(len(extension.Signatures))
	}
	inspection.Cost.LifecycleProofs = lifecyclePQCVerificationCount(tx)

	signatureTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return inspection, errorsmod.Wrap(
			types.ErrInvalidExtension,
			"transaction does not expose signer metadata for PQC budget inspection",
		)
	}
	signers, err := signatureTx.GetSigners()
	if err != nil {
		return inspection, errorsmod.Wrap(types.ErrInvalidExtension, err.Error())
	}
	signatures, err := signatureTx.GetSignaturesV2()
	if err != nil {
		return inspection, errorsmod.Wrap(types.ErrInvalidExtension, err.Error())
	}
	if len(signers) != len(signatures) {
		return inspection, errorsmod.Wrap(
			types.ErrInvalidExtension,
			"signer metadata length mismatch during PQC budget inspection",
		)
	}

	for index, rawSigner := range signers {
		signerKey := string(rawSigner)
		publicKey := t.persistedOrTrackedKey(ctx, sdk.AccAddress(rawSigner), signerKey)
		if publicKey == nil {
			publicKey = signatures[index].PubKey
			if publicKey != nil {
				inspection.discovered = append(inspection.discovered, discoveredPQCAccountKey{
					signer: signerKey,
					key:    publicKey,
				})
			}
		}
		inspection.Cost.NativeSignatures += countNativeMLDSAVerifications(
			publicKey,
			signatures[index].Data,
		)
	}
	return inspection, nil
}

func (t *PQCVerificationBudgetTracker) Commit(inspection PQCVerificationInspection) {
	for _, discovered := range inspection.discovered {
		if _, exists := t.knownKeys[discovered.signer]; !exists {
			t.knownKeys[discovered.signer] = discovered.key
		}
	}
}

func (t *PQCVerificationBudgetTracker) persistedOrTrackedKey(
	ctx sdk.Context,
	address sdk.AccAddress,
	signerKey string,
) cryptotypes.PubKey {
	if t.accountKeeper != nil {
		if account := t.accountKeeper.GetAccount(ctx, address); account != nil && account.GetPubKey() != nil {
			return account.GetPubKey()
		}
	}
	return t.knownKeys[signerKey]
}

func countNativeMLDSAVerifications(
	publicKey cryptotypes.PubKey,
	signature txsigning.SignatureData,
) uint64 {
	if publicKey == nil {
		return 0
	}
	if _, ok := publicKey.(*mldsa65.PubKey); ok {
		return 1
	}
	multiKey, ok := publicKey.(cryptomultisig.PubKey)
	if !ok {
		return 0
	}
	multiSignature, ok := signature.(*txsigning.MultiSignatureData)
	if !ok || multiSignature.BitArray == nil {
		// The SDK rejects a key/data mismatch before invoking any leaf
		// signature verification, so it consumes no PQC verification budget.
		return 0
	}
	publicKeys := multiKey.GetPubKeys()
	if len(publicKeys) != multiSignature.BitArray.Count() {
		return 0
	}
	var count uint64
	signatureIndex := 0
	for keyIndex := range publicKeys {
		if !multiSignature.BitArray.GetIndex(keyIndex) {
			continue
		}
		if signatureIndex >= len(multiSignature.Signatures) {
			return count
		}
		count += countNativeMLDSAVerifications(
			publicKeys[keyIndex],
			multiSignature.Signatures[signatureIndex],
		)
		signatureIndex++
	}
	return count
}

func lifecyclePQCVerificationCount(tx sdk.Tx) uint64 {
	var count uint64
	for _, message := range tx.GetMsgs() {
		switch message.(type) {
		case *types.MsgRegisterKey:
			count += 2 // signing-key proof plus recovery-key proof
		case *types.MsgRotateKey, *types.MsgRotateRecoveryKey:
			count++
		case *types.MsgRecoverKey:
			count += 2 // replacement-key proof plus recovery signature
		}
	}
	return count
}

type ValidatePQCVerificationBudgetDecorator struct {
	keeper interface {
		GetParams(ctx sdk.Context) types.Params
	}
	accountKeeper authante.AccountKeeper
}

func NewValidatePQCVerificationBudgetDecorator(
	moduleKeeper interface {
		GetParams(ctx sdk.Context) types.Params
	},
	accountKeeper authante.AccountKeeper,
) ValidatePQCVerificationBudgetDecorator {
	return ValidatePQCVerificationBudgetDecorator{
		keeper:        moduleKeeper,
		accountKeeper: accountKeeper,
	}
}

func (d ValidatePQCVerificationBudgetDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	stateCtx := pqcStateContext(ctx, simulate)
	params := d.keeper.GetParams(stateCtx).Effective(stateCtx.BlockHeight())
	inspection, err := NewPQCVerificationBudgetTracker(d.accountKeeper).Inspect(stateCtx, tx, params)
	if err != nil {
		return ctx, err
	}
	limit := uint64(params.EffectiveMaxPQCVerificationsPerTx())
	if inspection.Cost.Total() > limit {
		return ctx, errorsmod.Wrapf(
			types.ErrVerificationBudget,
			"transaction requests %d PQC verifications, limit is %d",
			inspection.Cost.Total(),
			limit,
		)
	}
	if next == nil {
		return ctx, fmt.Errorf("PQC verification budget decorator requires a next handler")
	}
	return next(ctx, tx, simulate)
}
