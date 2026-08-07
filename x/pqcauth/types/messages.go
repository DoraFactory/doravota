package types

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

func validateOwner(owner string) error {
	address, err := sdk.AccAddressFromBech32(owner)
	if err != nil || address.String() != owner {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "owner must be a canonical bech32 account address")
	}
	return nil
}

func getSigners(owner string) []sdk.AccAddress {
	address, err := sdk.AccAddressFromBech32(owner)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{address}
}

func signBytes(message sdk.Msg) []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(message))
}

func (m MsgRegisterKey) Route() string                { return RouterKey }
func (m MsgRegisterKey) Type() string                 { return "register_key" }
func (m MsgRegisterKey) GetSigners() []sdk.AccAddress { return getSigners(m.Owner) }
func (m MsgRegisterKey) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgRegisterKey) ValidateBasic() error {
	if err := validateOwner(m.Owner); err != nil {
		return err
	}
	if m.ExpectedSigningKeyId == 0 {
		return errorsmod.Wrap(ErrUnexpectedKeyID, "expected signing key id must be non-zero")
	}
	if err := ValidatePublicKeyAndProofLengths(m.SigningAlgorithm, m.SigningPublicKey, m.SigningKeyProof); err != nil {
		return err
	}
	if err := ValidatePublicKeyAndProofLengths(
		m.RecoveryAlgorithm,
		m.RecoveryPublicKey,
		m.RecoveryKeyProof,
	); err != nil {
		return fmt.Errorf("invalid recovery key: %w", err)
	}
	if err := ValidateDistinctRoleKeys(
		m.SigningAlgorithm,
		m.SigningPublicKey,
		m.RecoveryAlgorithm,
		m.RecoveryPublicKey,
	); err != nil {
		return err
	}
	if !m.SelfEnforce {
		return errorsmod.Wrap(ErrInvalidKey, "registration must enable self-enforcement")
	}
	return nil
}

func (m MsgRotateKey) Route() string                { return RouterKey }
func (m MsgRotateKey) Type() string                 { return "rotate_key" }
func (m MsgRotateKey) GetSigners() []sdk.AccAddress { return getSigners(m.Owner) }
func (m MsgRotateKey) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgRotateKey) ValidateBasic() error {
	if err := validateOwner(m.Owner); err != nil {
		return err
	}
	if m.ExpectedNewKeyId == 0 {
		return errorsmod.Wrap(ErrUnexpectedKeyID, "expected new key id must be non-zero")
	}
	return ValidatePublicKeyAndProofLengths(m.NewAlgorithm, m.NewPublicKey, m.NewKeyProof)
}

func (m MsgRotateRecoveryKey) Route() string { return RouterKey }
func (m MsgRotateRecoveryKey) Type() string  { return "rotate_recovery_key" }
func (m MsgRotateRecoveryKey) GetSigners() []sdk.AccAddress {
	return getSigners(m.Owner)
}
func (m MsgRotateRecoveryKey) GetSignBytes() []byte { return signBytes(&m) }
func (m MsgRotateRecoveryKey) ValidateBasic() error {
	if err := validateOwner(m.Owner); err != nil {
		return err
	}
	if m.ExpectedNewKeyId == 0 {
		return errorsmod.Wrap(ErrUnexpectedKeyID, "expected new key id must be non-zero")
	}
	return ValidatePublicKeyAndProofLengths(m.NewAlgorithm, m.NewPublicKey, m.NewKeyProof)
}

func (m MsgSetProtection) Route() string                { return RouterKey }
func (m MsgSetProtection) Type() string                 { return "set_protection" }
func (m MsgSetProtection) GetSigners() []sdk.AccAddress { return getSigners(m.Owner) }
func (m MsgSetProtection) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgSetProtection) ValidateBasic() error         { return validateOwner(m.Owner) }

func (m MsgRevokeKey) Route() string                { return RouterKey }
func (m MsgRevokeKey) Type() string                 { return "revoke_key" }
func (m MsgRevokeKey) GetSigners() []sdk.AccAddress { return getSigners(m.Owner) }
func (m MsgRevokeKey) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgRevokeKey) ValidateBasic() error {
	if err := validateOwner(m.Owner); err != nil {
		return err
	}
	if m.KeyId == 0 {
		return errorsmod.Wrap(ErrInvalidKey, "key id must be non-zero")
	}
	return nil
}

func (m MsgRecoverKey) Route() string                { return RouterKey }
func (m MsgRecoverKey) Type() string                 { return "recover_key" }
func (m MsgRecoverKey) GetSigners() []sdk.AccAddress { return getSigners(m.Owner) }
func (m MsgRecoverKey) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgRecoverKey) ValidateBasic() error {
	if err := validateOwner(m.Owner); err != nil {
		return err
	}
	if m.RecoveryKeyId == 0 || m.ExpectedNewSigningKeyId == 0 {
		return errorsmod.Wrap(ErrInvalidKey, "recovery and expected signing key ids must be non-zero")
	}
	if err := ValidatePublicKeyAndProofLengths(
		m.NewSigningAlgorithm,
		m.NewSigningPublicKey,
		m.NewSigningKeyProof,
	); err != nil {
		return err
	}
	algorithm, err := CryptoAlgorithm(m.NewSigningAlgorithm)
	if err != nil {
		return err
	}
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	if err != nil {
		return err
	}
	if len(m.RecoverySignature) != signatureSize {
		return errorsmod.Wrapf(ErrInvalidKeyProof, "recovery signature length %d, want %d", len(m.RecoverySignature), signatureSize)
	}
	return nil
}

func (m MsgUpdateParams) Route() string                { return RouterKey }
func (m MsgUpdateParams) Type() string                 { return "update_params" }
func (m MsgUpdateParams) GetSigners() []sdk.AccAddress { return getSigners(m.Authority) }
func (m MsgUpdateParams) GetSignBytes() []byte         { return signBytes(&m) }
func (m MsgUpdateParams) ValidateBasic() error {
	if err := validateOwner(m.Authority); err != nil {
		return errorsmod.Wrap(ErrInvalidAuthority, err.Error())
	}
	return m.Params.ValidateGovernanceUpdate()
}
