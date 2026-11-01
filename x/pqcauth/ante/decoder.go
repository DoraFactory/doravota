package ante

import (
	"bytes"

	errorsmod "cosmossdk.io/errors"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	"google.golang.org/protobuf/encoding/protowire"
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

// ValidateCanonicalPQCAuthWire bounds PQC extension bytes/entries before any
// generated decoder allocates them, then verifies original wire encoding.
// Governed limits, placement and cryptographic checks remain in Ante.
func ValidateCanonicalPQCAuthWire(txBytes []byte) error {
	if err := preflightPQCWire(txBytes); err != nil {
		return err
	}
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

// walkWire visits length-delimited slices without copying or allocating decoded
// messages. Groups are not part of the transaction/extension schemas.
func walkWire(raw []byte, visit func(protowire.Number, []byte) error) error {
	for len(raw) > 0 {
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return types.ErrInvalidExtension.Wrap("invalid protobuf tag")
		}
		raw = raw[n:]
		var size int
		switch kind {
		case protowire.VarintType:
			_, size = protowire.ConsumeVarint(raw)
		case protowire.Fixed32Type:
			_, size = protowire.ConsumeFixed32(raw)
		case protowire.Fixed64Type:
			_, size = protowire.ConsumeFixed64(raw)
		case protowire.BytesType:
			var value []byte
			value, size = protowire.ConsumeBytes(raw)
			if size >= 0 {
				if err := visit(number, value); err != nil {
					return err
				}
			}
		default:
			return types.ErrInvalidExtension.Wrap("unsupported protobuf wire type")
		}
		if size < 0 {
			return types.ErrInvalidExtension.Wrap("truncated protobuf field")
		}
		raw = raw[size:]
	}
	return nil
}

func preflightPQCWire(raw []byte) error {
	count := 0
	return walkWire(raw, func(field protowire.Number, body []byte) error {
		if field != 1 {
			return nil
		}
		return walkWire(body, func(field protowire.Number, option []byte) error {
			if field != 1023 && field != 2047 {
				return nil
			}
			var url, value []byte
			if err := walkWire(option, func(field protowire.Number, data []byte) error {
				if field == 1 {
					url = data
				}
				if field == 2 {
					value = data
				}
				return nil
			}); err != nil {
				return err
			}
			if !bytes.Equal(url, extensionPQCAuthTypeURLBytes) {
				return nil
			}
			count++
			if count > 1 {
				return types.ErrInvalidExtension.Wrap("duplicate pqcauth extension")
			}
			return preflightPQCExtension(value, types.AbsoluteMaxPQCAuthBytes, types.AbsoluteMaxPQCSigners)
		})
	})
}

func preflightPQCExtension(raw []byte, maxBytes, maxSigners uint32) error {
	if uint64(len(raw)) > uint64(maxBytes) {
		return types.ErrInvalidExtension.Wrap("pqcauth extension exceeds size limit")
	}
	count := uint32(0)
	return walkWire(raw, func(field protowire.Number, _ []byte) error {
		if field == 2 {
			count++
			if count > maxSigners {
				return types.ErrInvalidExtension.Wrap("too many PQC signer entries")
			}
		}
		return nil
	})
}
