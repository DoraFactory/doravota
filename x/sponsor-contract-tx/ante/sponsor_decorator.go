package sponsor

import (
	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	"math"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// SponsorAwareDeductFeeDecorator wraps the standard DeductFeeDecorator
// and handles sponsor fee payments
type SponsorAwareDeductFeeDecorator struct {
	standardDecorator ante.DeductFeeDecorator
	sponsorKeeper     types.SponsorKeeperInterface
	bankKeeper        bankkeeper.Keeper
	feegrantKeeper    ante.FeegrantKeeper
	txFeeChecker      ante.TxFeeChecker
	accountKeeper     authkeeper.AccountKeeper
}

// NewSponsorAwareDeductFeeDecorator creates a sponsor-aware fee decorator
func NewSponsorAwareDeductFeeDecorator(
	ak authkeeper.AccountKeeper,
	bk bankkeeper.Keeper,
	fgk ante.FeegrantKeeper,
	sponsorKeeper types.SponsorKeeperInterface,
	txFeeChecker ante.TxFeeChecker,
) SponsorAwareDeductFeeDecorator {
	if txFeeChecker == nil {
		txFeeChecker = SponsorTxFeeCheckerWithValidatorMinGasPrices
	}
	return SponsorAwareDeductFeeDecorator{
		standardDecorator: ante.NewDeductFeeDecorator(ak, bk, fgk, txFeeChecker),
		sponsorKeeper:     sponsorKeeper,
		bankKeeper:        bk,
		feegrantKeeper:    fgk,
		txFeeChecker:      txFeeChecker,
		accountKeeper:     ak,
	}
}

// AnteHandle implements the ante handler interface
func (safd SponsorAwareDeductFeeDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	// Check if this transaction has sponsor payment information in context using type-safe key
	if sponsorPayment, ok := ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo); ok {
		if sponsorPayment.IsSponsored && !sponsorPayment.Fee.IsZero() {
			// Handle sponsor fee payment directly
			return safd.handleSponsorFeePayment(ctx, tx, simulate, next, sponsorPayment.ContractAddr,
				sponsorPayment.SponsorAddr, sponsorPayment.UserAddr, sponsorPayment.Fee)
		}
	}

	// Fall back to standard fee decorator
	return safd.standardDecorator.AnteHandle(ctx, tx, simulate, next)
}

// handleSponsorFeePayment processes sponsor fee payment
func (safd SponsorAwareDeductFeeDecorator) handleSponsorFeePayment(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
	contractAddr sdk.AccAddress,
	sponsorAddr sdk.AccAddress,
	userAddr sdk.AccAddress,
	fee sdk.Coins,
) (newCtx sdk.Context, err error) {
	// Check for feegrant first - if present, delegate to standard decorator
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return ctx, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Tx must implement FeeTx interface")
	}

	if !simulate && ctx.BlockHeight() > 0 && feeTx.GetGas() == 0 {
		return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidGasLimit, "must provide positive gas")
	}

	feeGranter := feeTx.FeeGranter()
	// Priority: feegrant > sponsor - when FeeGranter is set, use standard fee handling
	if feeGranter != nil && !feeGranter.Empty() {
		// Delegate to standard fee decorator to handle feegrant properly
		return safd.standardDecorator.AnteHandle(ctx, tx, simulate, next)
	}

	var priority int64

	// Determine effective fee consistent with Cosmos SDK behavior:
	// - simulate: use tx-provided fee (feeTx.GetFee())
	// - non-simulate: use txFeeChecker(ctx, tx) result (enforces min gas price, sets priority)
	effectiveFee := fee
	if !simulate && safd.txFeeChecker != nil {
		effectiveFee, priority, err = safd.txFeeChecker(ctx, tx)
		if err != nil {
			return ctx, errorsmod.Wrapf(err, "failed to check required fee")
		}
	}

	// Step 1: Deduct fee from sponsor account (applies to both CheckTx and DeliverTx)
	// Defensive checks: ensure fee collector module account, sponsor account exist and fee is valid
	if addr := safd.accountKeeper.GetModuleAddress(authtypes.FeeCollectorName); addr == nil {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrLogic, "fee collector module account (%s) has not been set", authtypes.FeeCollectorName)
	}
	if safd.accountKeeper.GetAccount(ctx, sponsorAddr) == nil {
		return ctx, sdkerrors.ErrUnknownAddress.Wrapf("sponsor address: %s does not exist", sponsorAddr.String())
	}
	if !effectiveFee.IsValid() {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrInsufficientFee, "invalid fee amount: %s", effectiveFee)
	}
	err = safd.bankKeeper.SendCoinsFromAccountToModule(
		ctx,
		sponsorAddr,
		authtypes.FeeCollectorName,
		effectiveFee,
	)
	if err != nil {
		return ctx, errorsmod.Wrapf(err, "failed to deduct sponsor fee from %s", sponsorAddr)
	}

	// Step 2: Update user grant usage atomically
	if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), contractAddr.String(), effectiveFee); err != nil {
		return ctx, errorsmod.Wrapf(err, "failed to update user grant usage - sponsor fee deduction will be rolled back")
	}

	// Step 3: Emit success event only in DeliverTx (avoid events in CheckTx)
	if !ctx.IsCheckTx() {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeSponsoredTx,
				sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr.String()),
				sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAddr.String()),
				sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
				sdk.NewAttribute(types.AttributeKeySponsorAmount, effectiveFee.String()),
				sdk.NewAttribute(types.AttributeKeyIsSponsored, types.AttributeValueTrue),
			),
		)
	}

	ctx.Logger().With("module", "sponsor-contract-tx").Info(
		"sponsor fee deducted and user quota updated",
		"contract", contractAddr.String(),
		"sponsor", sponsorAddr.String(),
		"user", userAddr.String(),
		"fee", effectiveFee.String(),
	)

	newCtx = ctx.WithPriority(priority)

	return next(newCtx, tx, simulate)
}

func SponsorTxFeeCheckerWithValidatorMinGasPrices(ctx sdk.Context, tx sdk.Tx) (sdk.Coins, int64, error) {
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return nil, 0, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Tx must be a FeeTx")
	}

	feeCoins := feeTx.GetFee()
	gas := feeTx.GetGas()

	// Ensure that the provided fees meet a minimum threshold for the validator,
	// if this is a CheckTx. This is only for local mempool purposes, and thus
	// is only ran on check tx.
	if ctx.IsCheckTx() {
		minGasPrices := ctx.MinGasPrices()
		if !minGasPrices.IsZero() {
			requiredFees := make(sdk.Coins, len(minGasPrices))

			// Determine the required fees by multiplying each required minimum gas
			// price by the gas limit, where fee = ceil(minGasPrice * gasLimit).
			glDec := sdkmath.LegacyNewDec(int64(gas))
			for i, gp := range minGasPrices {
				fee := gp.Amount.Mul(glDec)
				requiredFees[i] = sdk.NewCoin(gp.Denom, fee.Ceil().RoundInt())
			}

			if !feeCoins.IsAnyGTE(requiredFees) {
				return nil, 0, errorsmod.Wrapf(sdkerrors.ErrInsufficientFee, "insufficient fees; got: %s required: %s", feeCoins, requiredFees)
			}
		}
	}

	priority := getTxPriority(feeCoins, int64(gas))
	return feeCoins, priority, nil
}

// getTxPriority returns a naive tx priority based on the amount of the smallest denomination of the gas price
// provided in a transaction.
// NOTE: This implementation should be used with a great consideration as it opens potential attack vectors
// where txs with multiple coins could not be prioritize as expected.
func getTxPriority(fee sdk.Coins, gas int64) int64 {
	var priority int64
	for _, c := range fee {
		p := int64(math.MaxInt64)
		gasPrice := c.Amount.QuoRaw(gas)
		if gasPrice.IsInt64() {
			p = gasPrice.Int64()
		}
		if priority == 0 || p < priority {
			priority = p
		}
	}

	return priority
}
