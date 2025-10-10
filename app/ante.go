package app

import (
    "fmt"
	errorsmod "cosmossdk.io/errors"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	ibcante "github.com/cosmos/ibc-go/v7/modules/core/ante"
	"github.com/cosmos/ibc-go/v7/modules/core/keeper"
    servertypes "github.com/cosmos/cosmos-sdk/server/types"
    "time"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmTypes "github.com/CosmWasm/wasmd/x/wasm/types"

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
    AppOptions       servertypes.AppOptions
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


	// Build sponsor decorator with optional local cooldown config from app options
	sponsorDec := sponsorante.NewSponsorContractTxAnteDecorator(options.SponsorKeeper, options.AccountKeeper.(authkeeper.AccountKeeper), options.BankKeeper.(bankkeeper.Keeper), options.TxFeeChecker)
	if options.AppOptions != nil {
		cfg := sponsorante.CooldownConfig{}
		if v, ok := getBoolOpt(options.AppOptions, "sponsor.cooldown_enabled"); ok {
			cfg.Enabled = &v
		}
		if dur, ok := getDurationSecondsOpt(options.AppOptions, "sponsor.cooldown_ttl_seconds"); ok {
			cfg.BaseTTL = &dur
		}
		if dur, ok := getDurationSecondsOpt(options.AppOptions, "sponsor.cooldown_max_ttl_seconds"); ok {
			cfg.MaxTTL = &dur
		}
		if f, ok := getFloatOpt(options.AppOptions, "sponsor.cooldown_backoff_factor"); ok {
			cfg.BackoffFactor = &f
		}
		if n, ok := getIntOpt(options.AppOptions, "sponsor.cooldown_threshold"); ok {
			cfg.Threshold = &n
		}
		if dur, ok := getDurationSecondsOpt(options.AppOptions, "sponsor.cooldown_window_seconds"); ok {
			cfg.Window = &dur
		}
		if n, ok := getIntOpt(options.AppOptions, "sponsor.cooldown_max_entries"); ok {
			cfg.MaxEntries = &n
		}
		if n, ok := getIntOpt(options.AppOptions, "sponsor.cooldown_max_entries_per_contract"); ok {
			cfg.MaxEntriesPerContract = &n
		}
		sponsorDec = sponsorDec.WithCooldownConfig(cfg)
	}

	anteDecorators := []sdk.AnteDecorator{
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit), // after setup context to enforce limits early
		wasmkeeper.NewCountTXDecorator(options.TXCounterStoreKey),
		ante.NewExtensionOptionsDecorator(options.ExtensionOptionChecker),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		sponsorDec,
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
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewRedundantRelayDecorator(options.IBCKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}

// helper getters for AppOptions
func getBoolOpt(opts servertypes.AppOptions, key string) (bool, bool) {
    if opts == nil { return false, false }
    v := opts.Get(key)
    if v == nil { return false, false }
    switch t := v.(type) {
    case bool:
        return t, true
    case string:
        if t == "true" { return true, true }
        if t == "false" { return false, true }
        return false, false
    default:
        return false, false
    }
}

func getIntOpt(opts servertypes.AppOptions, key string) (int, bool) {
    if opts == nil { return 0, false }
    v := opts.Get(key)
    if v == nil { return 0, false }
    switch t := v.(type) {
    case int:
        return t, true
    case int64:
        return int(t), true
    case float64:
        return int(t), true
    case string:
        // best-effort parse
        var n int
        _, err := fmt.Sscanf(t, "%d", &n)
        if err == nil { return n, true }
        return 0, false
    default:
        return 0, false
    }
}

func getFloatOpt(opts servertypes.AppOptions, key string) (float64, bool) {
    if opts == nil { return 0, false }
    v := opts.Get(key)
    if v == nil { return 0, false }
    switch t := v.(type) {
    case float64:
        return t, true
    case int:
        return float64(t), true
    case int64:
        return float64(t), true
    case string:
        var f float64
        _, err := fmt.Sscanf(t, "%f", &f)
        if err == nil { return f, true }
        return 0, false
    default:
        return 0, false
    }
}

func getDurationSecondsOpt(opts servertypes.AppOptions, key string) (time.Duration, bool) {
    if n, ok := getIntOpt(opts, key); ok {
        return time.Duration(n) * time.Second, true
    }
    return 0, false
}
