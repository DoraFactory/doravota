package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// Sponsor module sentinel errors
var (
	ErrSponsorNotFound        = sdkerrors.Register(ModuleName, 1, "sponsor not found")
	ErrSponsorAlreadyExists   = sdkerrors.Register(ModuleName, 2, "sponsor already exists")
	ErrUnauthorized           = sdkerrors.Register(ModuleName, 3, "unauthorized")
	ErrInvalidContractAddress = sdkerrors.Register(ModuleName, 4, "invalid contract address")
	ErrContractNotFound       = sdkerrors.Register(ModuleName, 5, "contract not found")
	ErrSponsorshipDisabled    = sdkerrors.Register(ModuleName, 6, "sponsorship is disabled")
	ErrGasLimitExceeded       = sdkerrors.Register(ModuleName, 7, "gas limit exceeded for sponsored transaction")
	ErrPolicyCheckFailed      = sdkerrors.Register(ModuleName, 8, "contract policy check failed")
	ErrInvalidPolicyResponse  = sdkerrors.Register(ModuleName, 9, "invalid policy response from contract")
	ErrInsufficientFunds      = sdkerrors.Register(ModuleName, 10, "insufficient funds for sponsorship")
	ErrInvalidParams          = sdkerrors.Register(ModuleName, 11, "invalid module parameters")
	ErrInvalidCreator         = sdkerrors.Register(ModuleName, 12, "invalid creator address")
	ErrContractNotAdmin       = sdkerrors.Register(ModuleName, 13, "not contract admin")
	ErrUserGrantLimitExceeded = sdkerrors.Register(ModuleName, 14, "user grant limit exceeded")
	ErrInvalidAuthority       = sdkerrors.Register(ModuleName, 15, "invalid authority")
	ErrSponsorBalanceNotEmpty = sdkerrors.Register(ModuleName, 16, "sponsor address balance must be zero before deletion")
)
