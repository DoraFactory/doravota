package app

import (
	errorsmod "cosmossdk.io/errors"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	ibcante "github.com/cosmos/ibc-go/v7/modules/core/ante"
	"github.com/cosmos/ibc-go/v7/modules/core/keeper"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmTypes "github.com/CosmWasm/wasmd/x/wasm/types"

	pqcauthante "github.com/DoraFactory/doravota/x/pqcauth/ante"
	pqcauthkeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"

	// sponsor module
	sponsorante "github.com/DoraFactory/doravota/x/sponsor-contract-tx/ante"
	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// HandlerOptions extend the SDK's AnteHandler options by requiring the IBC
// channel keeper.
type HandlerOptions struct {
	ante.HandlerOptions

	IBCKeeper         *keeper.Keeper
	WasmConfig        *wasmTypes.WasmConfig
	TXCounterStoreKey storetypes.StoreKey
	SponsorKeeper     sponsortypes.SponsorKeeperInterface
	PQCAuthKeeper     pqcauthkeeper.Keeper
	AppOptions        servertypes.AppOptions
}

func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	if options.AccountKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "account keeper is required for AnteHandler")
	}
	if options.BankKeeper == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "bank keeper is required for AnteHandler")
	}
	if options.SignModeHandler == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "sign mode handler is required for ante builder")
	}
	if options.WasmConfig == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "wasm config is required for ante builder")
	}
	if options.TXCounterStoreKey == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "tx counter key is required for ante builder")
	}

	anteDecorators := []sdk.AnteDecorator{
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreKey),
		ante.NewExtensionOptionsDecorator(
			pqcauthante.ExtensionOptionChecker(options.ExtensionOptionChecker),
		),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		pqcauthante.NewValidatePQCStructureDecorator(options.PQCAuthKeeper),
		sponsorante.NewSponsorContractTxAnteDecorator(options.SponsorKeeper, options.AccountKeeper.(authkeeper.AccountKeeper), options.BankKeeper.(bankkeeper.Keeper), options.TxFeeChecker),
		// Use sponsor-aware fee decorator that handles both normal fees and sponsor fees
		sponsorante.NewSponsorAwareDeductFeeDecorator(
			options.AccountKeeper.(authkeeper.AccountKeeper),
			options.BankKeeper.(bankkeeper.Keeper),
			options.FeegrantKeeper,
			options.SponsorKeeper,
			options.TxFeeChecker,
		),
		ante.NewSetPubKeyDecorator(options.AccountKeeper), // SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		pqcauthante.NewVerifyPQCDecorator(options.PQCAuthKeeper, options.AccountKeeper),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewRedundantRelayDecorator(options.IBCKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}
