package types

import (
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/cometbft/cometbft/libs/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// AccountKeeper defines the expected interface for the Account module keeper
type AccountKeeper interface {
	GetAccount(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI
	SetAccount(ctx sdk.Context, acc authtypes.AccountI)
	NewAccountWithAddress(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI
	GetModuleAddress(moduleName string) sdk.AccAddress
	GetModuleAccount(ctx sdk.Context, moduleName string) authtypes.ModuleAccountI
}

// AuthKeeper is an alias for AccountKeeper to maintain compatibility
type AuthKeeper = AccountKeeper

// BankKeeper defines the expected interface for the Bank module keeper
type BankKeeper interface {
	SpendableCoins(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins
	SendCoins(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx sdk.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	MintCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error
	GetAllBalances(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins
	GetBalance(ctx sdk.Context, addr sdk.AccAddress, denom string) sdk.Coin
	BlockedAddr(addr sdk.AccAddress) bool
}

// WasmKeeperInterface defines the expected interface for the Wasm module keeper
type WasmKeeperInterface interface {
	GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo
	QuerySmart(ctx sdk.Context, contractAddr sdk.AccAddress, req []byte) ([]byte, error)
}

// CheckContractPolicyResult holds the result of a contract policy check
type CheckContractPolicyResult struct {
	Eligible bool
	Reason   string
}

// SponsorKeeperInterface defines the expected interface for the SponsorKeeper
type SponsorKeeperInterface interface {
    GetParams(ctx sdk.Context) Params
    IsSponsored(ctx sdk.Context, contractAddr string) bool
    GetSponsor(ctx sdk.Context, contractAddr string) (ContractSponsor, bool)
    ValidateContractExists(ctx sdk.Context, contractAddr string) error
    CheckUserGrantLimit(ctx sdk.Context, userAddr, contractAddr string, requestedAmount sdk.Coins) error
    UpdateUserGrantUsage(ctx sdk.Context, userAddr, contractAddr string, consumedAmount sdk.Coins) error
    Logger(ctx sdk.Context) log.Logger
    // Two-phase ticket helpers
    GetPolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) (PolicyTicket, bool)
    ConsumePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error
    // Consume multiple method digests with counts atomically
    ConsumePolicyTicketsBulk(ctx sdk.Context, contractAddr, userAddr string, counts map[string]uint32) error
    RevokePolicyTicket(ctx sdk.Context, contractAddr, userAddr, digest string) error
    // Helpers for CheckTx gating
    EffectiveTicketTTLForContract(ctx sdk.Context, contractAddr string) uint32
    // Digest helpers (for ante gating)
    ComputeMethodDigest(contractAddr string, methodNames []string) string
}
