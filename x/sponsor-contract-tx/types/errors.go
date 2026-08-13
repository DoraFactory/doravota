package types

import errorsmod "cosmossdk.io/errors"

// Sponsor module sentinel errors
var (
	ErrSponsorNotFound        = errorsmod.Register(ModuleName, 1, "sponsor not found")
	ErrSponsorAlreadyExists   = errorsmod.Register(ModuleName, 2, "sponsor already exists")
	ErrUnauthorized           = errorsmod.Register(ModuleName, 3, "unauthorized")
	ErrInvalidContractAddress = errorsmod.Register(ModuleName, 4, "invalid contract address")
	ErrContractNotFound       = errorsmod.Register(ModuleName, 5, "contract not found")
	ErrSponsorshipDisabled    = errorsmod.Register(ModuleName, 6, "sponsorship is disabled")
	ErrGasLimitExceeded       = errorsmod.Register(ModuleName, 7, "gas limit exceeded for sponsored transaction")
	ErrPolicyCheckFailed      = errorsmod.Register(ModuleName, 8, "contract policy check failed")
	ErrInvalidPolicyResponse  = errorsmod.Register(ModuleName, 9, "invalid policy response from contract")
	ErrInsufficientFunds      = errorsmod.Register(ModuleName, 10, "insufficient funds for sponsorship")
	ErrInvalidParams          = errorsmod.Register(ModuleName, 11, "invalid module parameters")
	ErrInvalidCreator         = errorsmod.Register(ModuleName, 12, "invalid creator address")
	ErrContractNotAdmin       = errorsmod.Register(ModuleName, 13, "not contract admin")
	ErrUserGrantLimitExceeded = errorsmod.Register(ModuleName, 14, "user grant limit exceeded")
	ErrInvalidAuthority       = errorsmod.Register(ModuleName, 15, "invalid authority")
	ErrSponsorBalanceNotEmpty = errorsmod.Register(ModuleName, 16, "sponsor address balance must be zero before deletion")
	ErrSponsorBalanceEmpty    = errorsmod.Register(ModuleName, 17, "sponsor address balance is zero")
	// Ticket issuance conflicts
	ErrPolicyTicketAlreadyExists = errorsmod.Register(ModuleName, 18, "active policy ticket already exists")
	// Contract admin lifecycle conflicts
	ErrSponsorMustBeRemoved = errorsmod.Register(ModuleName, 19, "sponsor must be removed before clearing contract admin")
)
