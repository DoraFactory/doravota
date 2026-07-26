package types

import sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

var (
	ErrInvalidParams          = sdkerrors.Register(ModuleName, 1, "invalid pqcauth parameters")
	ErrInvalidKey             = sdkerrors.Register(ModuleName, 2, "invalid PQC key")
	ErrInvalidKeyProof        = sdkerrors.Register(ModuleName, 3, "invalid PQC key proof")
	ErrKeyNotFound            = sdkerrors.Register(ModuleName, 4, "PQC key not found")
	ErrPolicyNotFound         = sdkerrors.Register(ModuleName, 5, "PQC account policy not found")
	ErrAlreadyRegistered      = sdkerrors.Register(ModuleName, 6, "PQC signing key already registered")
	ErrKeyLimit               = sdkerrors.Register(ModuleName, 7, "PQC account key limit reached")
	ErrUnexpectedKeyID        = sdkerrors.Register(ModuleName, 8, "unexpected PQC key identifier")
	ErrPendingChange          = sdkerrors.Register(ModuleName, 9, "PQC policy change is already pending")
	ErrUnauthorized           = sdkerrors.Register(ModuleName, 10, "PQC authorization failed")
	ErrPQCRequired            = sdkerrors.Register(ModuleName, 11, "PQC authorization is required")
	ErrInvalidExtension       = sdkerrors.Register(ModuleName, 12, "invalid PQC transaction extension")
	ErrUnsupportedAlgorithm   = sdkerrors.Register(ModuleName, 13, "unsupported PQC algorithm")
	ErrRegistrationClosed     = sdkerrors.Register(ModuleName, 14, "PQC registration is closed")
	ErrEmergencyPause         = sdkerrors.Register(ModuleName, 15, "PQC operation is paused")
	ErrInvalidAuthority       = sdkerrors.Register(ModuleName, 16, "invalid pqcauth authority")
	ErrActiveKey              = sdkerrors.Register(ModuleName, 17, "active PQC key cannot be revoked")
	ErrInvalidPolicyVersion   = sdkerrors.Register(ModuleName, 18, "invalid PQC policy version")
	ErrUnsupportedSignMode    = sdkerrors.Register(ModuleName, 19, "unsupported sign mode for PQC authorization")
	ErrDuplicateAuthorization = sdkerrors.Register(ModuleName, 20, "duplicate PQC signer authorization")
	ErrNestedLifecycle        = sdkerrors.Register(ModuleName, 21, "PQC lifecycle messages must be executed directly")
	ErrInconsistentState      = sdkerrors.Register(ModuleName, 22, "inconsistent PQC authorization state")
)
