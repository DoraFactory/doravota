package app

import (
	corestore "cosmossdk.io/core/store"
	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/codec"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	ibcante "github.com/cosmos/ibc-go/v11/modules/core/ante"
	"github.com/cosmos/ibc-go/v11/modules/core/keeper"

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

	IBCKeeper             *keeper.Keeper
	NodeConfig            *wasmTypes.NodeConfig
	TXCounterStoreService corestore.KVStoreService
	SponsorKeeper         sponsortypes.SponsorKeeperInterface
	PQCAuthKeeper         pqcauthkeeper.Keeper
	AuthzGrantReader      pqcauthante.AuthzGrantReader
	AppCodec              codec.Codec
	AppOptions            servertypes.AppOptions
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
	if options.NodeConfig == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "wasm config is required for ante builder")
	}
	if options.TXCounterStoreService == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "tx counter key is required for ante builder")
	}
	if options.AuthzGrantReader == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "authz grant reader is required for ante builder")
	}
	if options.AppCodec == nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrLogic, "app codec is required for ante builder")
	}

	anteDecorators := []sdk.AnteDecorator{
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.NodeConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreService),
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
		pqcauthante.NewCaptureRegistrationStateDecorator(options.AccountKeeper),
		ante.NewSetPubKeyDecorator(options.AccountKeeper), // SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		pqcauthante.NewAuthzPQCDecorator(
			options.PQCAuthKeeper,
			options.AccountKeeper,
			options.AuthzGrantReader,
			options.AppCodec,
		),
		pqcauthante.NewVerifyPQCDecorator(options.PQCAuthKeeper, options.AccountKeeper),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewRedundantRelayDecorator(options.IBCKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}
