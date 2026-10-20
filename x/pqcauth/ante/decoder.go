package ante

import (
	"bytes"

	errorsmod "cosmossdk.io/errors"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

var extensionPQCAuthTypeURLBytes = []byte(types.ExtensionPQCAuthTypeURL)

// CanonicalPQCAuthTxDecoder rejects wire-level PQC extension malleability
// before the SDK interface unpacker can normalize Any.Value. Ante operates on
// an already decoded transaction, so it cannot recover the original extension
// bytes by itself.
func CanonicalPQCAuthTxDecoder(next sdk.TxDecoder) sdk.TxDecoder {
	return func(txBytes []byte) (sdk.Tx, error) {
		// Preserve the SDK's single-decode path for ordinary transactions. An
		// exact PQC Any type URL must occur verbatim in its protobuf body.
		if bytes.Contains(txBytes, extensionPQCAuthTypeURLBytes) {
			if err := ValidateCanonicalPQCAuthWire(txBytes); err != nil {
				return nil, err
			}
		}
		return next(txBytes)
	}
}

// ValidateCanonicalPQCAuthWire examines only TxRaw.body_bytes. All semantic,
// size, placement, and cryptographic checks remain in the Ante decorators.
func ValidateCanonicalPQCAuthWire(txBytes []byte) error {
	var raw txtypes.TxRaw
	if err := raw.Unmarshal(txBytes); err != nil {
		return err
	}
	var body txtypes.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return err
	}
	for _, options := range [][]*codectypes.Any{body.ExtensionOptions, body.NonCriticalExtensionOptions} {
		for _, option := range options {
			if option == nil || option.TypeUrl != types.ExtensionPQCAuthTypeURL {
				continue
			}
			var extension types.ExtensionPQCAuth
			if err := extension.Unmarshal(option.Value); err != nil {
				return errorsmod.Wrap(types.ErrInvalidExtension, "cannot decode pqcauth extension")
			}
			canonical, err := extension.Marshal()
			if err != nil || !bytes.Equal(canonical, option.Value) {
				return errorsmod.Wrap(types.ErrInvalidExtension, "non-canonical pqcauth extension encoding")
			}
		}
	}
	return nil
}
