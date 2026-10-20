package ante

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	errorsmod "cosmossdk.io/errors"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// ExtensionOptionChecker accepts the single pqcauth critical extension and
// delegates all other options to an optional application checker.
func ExtensionOptionChecker(fallback authante.ExtensionOptionChecker) authante.ExtensionOptionChecker {
	return func(option *codectypes.Any) bool {
		if option != nil && option.TypeUrl == types.ExtensionPQCAuthTypeURL {
			return true
		}
		return fallback != nil && fallback(option)
	}
}

type ValidatePQCStructureDecorator struct {
	keeper pqckeeper.Keeper
}

type validatedExtensionCacheKey struct{}

type validatedExtensionCache struct {
	optionsFingerprint [sha256.Size]byte
	extension          *types.ExtensionPQCAuth
	found              bool
}

func NewValidatePQCStructureDecorator(moduleKeeper pqckeeper.Keeper) ValidatePQCStructureDecorator {
	return ValidatePQCStructureDecorator{keeper: moduleKeeper}
}

func (d ValidatePQCStructureDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	stateCtx := pqcStateContext(ctx, simulate)
	params := d.keeper.GetParams(stateCtx).Effective(stateCtx.BlockHeight())
	if err := validateNoNestedLifecycleMessages(tx.GetMsgs(), 0); err != nil {
		return ctx, err
	}
	extension, found, err := ExtractExtension(tx, params)
	if err != nil {
		return ctx, err
	}
	if found {
		if params.EmergencyMode == types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS &&
			!isRecoveryCancellation(tx) {
			return ctx, types.ErrEmergencyPause
		}
		if err := requireDirectSignMode(tx, simulate); err != nil {
			return ctx, err
		}
	}
	ctx = withValidatedExtension(ctx, tx, extension, found)
	return next(ctx, tx, simulate)
}

func isRecoveryCancellation(tx sdk.Tx) bool {
	if len(tx.GetMsgs()) != 1 {
		return false
	}
	_, ok := tx.GetMsgs()[0].(*types.MsgCancelRecovery)
	return ok
}

// pqcStateContext maps the SDK's height-zero gas-simulation context to the
// latest committed store version. PQC policies and keys use absolute activation
// heights, so reading them at height zero would make every post-genesis key
// appear inactive. This adjustment is simulation-only; consensus execution
// always uses the block height supplied by BaseApp.
func pqcStateContext(ctx sdk.Context, simulate bool) sdk.Context {
	if !simulate || ctx.BlockHeight() > 0 {
		return ctx
	}
	if latest := ctx.MultiStore().LatestVersion(); latest > 0 {
		return ctx.WithBlockHeight(latest)
	}
	return ctx
}

func withValidatedExtension(
	ctx sdk.Context,
	tx sdk.Tx,
	extension *types.ExtensionPQCAuth,
	found bool,
) sdk.Context {
	return ctx.WithValue(validatedExtensionCacheKey{}, validatedExtensionCache{
		optionsFingerprint: extensionOptionsFingerprint(tx),
		extension:          extension,
		found:              found,
	})
}

func getValidatedExtension(
	ctx sdk.Context,
	tx sdk.Tx,
) (*types.ExtensionPQCAuth, bool, bool) {
	cached, ok := ctx.Value(validatedExtensionCacheKey{}).(validatedExtensionCache)
	if !ok || cached.optionsFingerprint != extensionOptionsFingerprint(tx) {
		return nil, false, false
	}
	return cached.extension, cached.found, true
}

func extensionOptionsFingerprint(tx sdk.Tx) [sha256.Size]byte {
	hasher := sha256.New()
	extensionTx, ok := tx.(authante.HasExtensionOptionsTx)
	if !ok {
		_, _ = hasher.Write([]byte{0})
		var result [sha256.Size]byte
		copy(result[:], hasher.Sum(nil))
		return result
	}
	_, _ = hasher.Write([]byte{1})
	writeExtensionOptionsHash(hasher, extensionTx.GetExtensionOptions())
	writeExtensionOptionsHash(hasher, extensionTx.GetNonCriticalExtensionOptions())
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func writeExtensionOptionsHash(hasher hash.Hash, options []*codectypes.Any) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(options)))
	_, _ = hasher.Write(length[:])
	for _, option := range options {
		if option == nil {
			_, _ = hasher.Write([]byte{0})
			continue
		}
		_, _ = hasher.Write([]byte{1})
		writeLengthPrefixedHash(hasher, []byte(option.TypeUrl))
		writeLengthPrefixedHash(hasher, option.Value)
	}
}

func writeLengthPrefixedHash(hasher hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

// ExtractExtension performs only bounded, state-independent validation. Any
// provided extension must use the unique canonical protobuf representation.
func ExtractExtension(
	tx sdk.Tx,
	params types.Params,
) (*types.ExtensionPQCAuth, bool, error) {
	extensionTx, ok := tx.(authante.HasExtensionOptionsTx)
	if !ok {
		return nil, false, nil
	}

	for _, option := range extensionTx.GetNonCriticalExtensionOptions() {
		if option != nil && option.TypeUrl == types.ExtensionPQCAuthTypeURL {
			return nil, false, errorsmod.Wrap(
				types.ErrInvalidExtension,
				"pqcauth must be a critical extension",
			)
		}
	}

	var encoded []byte
	for index, option := range extensionTx.GetExtensionOptions() {
		if option == nil || option.TypeUrl != types.ExtensionPQCAuthTypeURL {
			continue
		}
		if encoded != nil {
			return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "duplicate pqcauth extension")
		}
		if index != len(extensionTx.GetExtensionOptions())-1 {
			return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "pqcauth extension must be last")
		}
		encoded = option.Value
	}
	if encoded == nil {
		return nil, false, nil
	}
	if uint32(len(encoded)) > params.EffectiveMaxPQCAuthBytes() {
		return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "pqcauth extension exceeds size limit")
	}

	var extension types.ExtensionPQCAuth
	if err := extension.Unmarshal(encoded); err != nil {
		return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "cannot decode pqcauth extension")
	}
	canonical, err := extension.Marshal()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "non-canonical pqcauth extension encoding")
	}
	if extension.FormatVersion != types.FormatVersionV1 {
		return nil, false, errorsmod.Wrapf(
			types.ErrInvalidExtension,
			"unsupported format version %d",
			extension.FormatVersion,
		)
	}
	if uint32(len(extension.Signatures)) > params.EffectiveMaxPQCSigners() {
		return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "too many PQC signer entries")
	}

	var previous uint32
	for index, signature := range extension.Signatures {
		if index > 0 && signature.SignerIndex <= previous {
			return nil, false, errorsmod.Wrap(
				types.ErrDuplicateAuthorization,
				"signer entries must be strictly ordered",
			)
		}
		previous = signature.SignerIndex
		if signature.Signer == "" || signature.KeyId == 0 || signature.PolicyVersion == 0 {
			return nil, false, errorsmod.Wrap(types.ErrInvalidExtension, "incomplete signer entry")
		}
		algorithm, err := types.CryptoAlgorithm(signature.Algorithm)
		if err != nil {
			return nil, false, err
		}
		_, signatureSize, err := pqccrypto.Sizes(algorithm)
		if err != nil || len(signature.Signature) != signatureSize {
			return nil, false, errorsmod.Wrapf(
				types.ErrInvalidExtension,
				"invalid signature length for signer index %d",
				signature.SignerIndex,
			)
		}
	}
	return &extension, true, nil
}

func requireDirectSignMode(tx sdk.Tx, simulate bool) error {
	signatureTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return errorsmod.Wrap(types.ErrUnsupportedSignMode, "transaction does not expose signer metadata")
	}
	signatures, err := signatureTx.GetSignaturesV2()
	if err != nil {
		return errorsmod.Wrap(types.ErrUnsupportedSignMode, err.Error())
	}
	for index, signature := range signatures {
		single, ok := signature.Data.(*txsigning.SingleSignatureData)
		if !ok {
			return fmt.Errorf("%w: signer index %d must use SIGN_MODE_DIRECT", types.ErrUnsupportedSignMode, index)
		}
		if single.SignMode == txsigning.SignMode_SIGN_MODE_DIRECT {
			continue
		}
		// Cosmos SDK gas simulation creates an unsigned placeholder signer with
		// SIGN_MODE_UNSPECIFIED. Accept only that exact empty placeholder while
		// simulate=true; CheckTx and DeliverTx still require SIGN_MODE_DIRECT.
		if simulate &&
			single.SignMode == txsigning.SignMode_SIGN_MODE_UNSPECIFIED &&
			len(single.Signature) == 0 {
			continue
		}
		return fmt.Errorf("%w: signer index %d must use SIGN_MODE_DIRECT", types.ErrUnsupportedSignMode, index)
	}
	return nil
}
