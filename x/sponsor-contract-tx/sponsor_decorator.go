package sponsor

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// SponsorAwareDeductFeeDecorator wraps the standard DeductFeeDecorator
// and handles sponsor fee payments
type SponsorAwareDeductFeeDecorator struct {
	standardDecorator ante.DeductFeeDecorator
	sponsorKeeper     keeper.Keeper
	bankKeeper        bankkeeper.Keeper
	feegrantKeeper    ante.FeegrantKeeper
	txFeeChecker      ante.TxFeeChecker
}

// NewSponsorAwareDeductFeeDecorator creates a sponsor-aware fee decorator
func NewSponsorAwareDeductFeeDecorator(
	ak authkeeper.AccountKeeper,
	bk bankkeeper.Keeper,
	fgk ante.FeegrantKeeper,
	sponsorKeeper keeper.Keeper,
	txFeeChecker ante.TxFeeChecker,
) SponsorAwareDeductFeeDecorator {
	return SponsorAwareDeductFeeDecorator{
		standardDecorator: ante.NewDeductFeeDecorator(ak, bk, fgk, txFeeChecker),
		sponsorKeeper:     sponsorKeeper,
		bankKeeper:        bk,
		feegrantKeeper:    fgk,
		txFeeChecker:      txFeeChecker,
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
			return safd.handleSponsorFeePayment(ctx, tx, simulate, next, 
				sponsorPayment.ContractAddr, sponsorPayment.UserAddr, sponsorPayment.Fee)
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
	sponsorAddr sdk.AccAddress,
	userAddr sdk.AccAddress,
	fee sdk.Coins,
) (newCtx sdk.Context, err error) {
	// Validate fee amount using txFeeChecker to ensure it meets minimum requirements
	if safd.txFeeChecker != nil {
		requiredFee, _, err := safd.txFeeChecker(ctx, tx)
		if err != nil {
			return ctx, sdkerrors.Wrapf(err, "failed to check required fee")
		}
		
		// Ensure sponsor fee meets minimum gas price and required fee
		if !fee.IsAllGTE(requiredFee) {
			return ctx, sdkerrors.Wrapf(
				sdkerrors.ErrInsufficientFee,
				"sponsor fee %s is insufficient, required minimum fee: %s",
				fee.String(),
				requiredFee.String(),
			)
		}
	}

	// Check for feegrant first (following official SDK pattern)
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must implement FeeTx interface")
	}

	feePayer := feeTx.FeePayer()
	feeGranter := feeTx.FeeGranter()
	deductFeesFrom := sponsorAddr // Default to sponsor

	// Priority logic: feegrant > sponsor > standard
	if feeGranter != nil && !feeGranter.Empty() {
		if safd.feegrantKeeper == nil {
		} else if !feeGranter.Equals(feePayer) {
			// Try to use standard feegrant
			err := safd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, tx.GetMsgs())
			if err != nil {
				return ctx, sdkerrors.Wrapf(err, "%s does not allow to pay fees for %s", feeGranter, feePayer)
			} else {
				deductFeesFrom = feeGranter
			}
		}
	}

	// Deduct fee from the determined account (feegranter or sponsor)
	if !simulate {
		err = safd.bankKeeper.SendCoinsFromAccountToModule(
			ctx,
			deductFeesFrom, // This is either feeGranter or sponsorAddr
			authtypes.FeeCollectorName, // Standard fee collector module
			fee,
		)
		if err != nil {
			return ctx, sdkerrors.Wrapf(err, "failed to deduct fee from %s", deductFeesFrom)
		}
		
		// Update user grant usage ONLY when using sponsor (not feegrant) only in DeliverTx period
		if deductFeesFrom.Equals(sponsorAddr)  && !ctx.IsCheckTx() {
			if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), sponsorAddr.String(), fee); err != nil {
				return ctx, sdkerrors.Wrapf(err, "failed to update user grant usage")
			}

			// Emit successful sponsored transaction event only in DeliverTx period
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					types.EventTypeSponsoredTx,
					sdk.NewAttribute(types.AttributeKeyContractAddress, sponsorAddr.String()),
					sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
					sdk.NewAttribute(types.AttributeKeySponsorAmount, fee.String()),
					sdk.NewAttribute(types.AttributeKeyIsSponsored, "true"),
				),
			)

			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"sponsor fee deducted successfully and usage updated",
				"sponsor", sponsorAddr.String(),
				"user", userAddr.String(),
				"fee", fee.String(),
			)
		}
		// If feegrant was used, fee is already deducted and events are handled by feegrant module
	}

	return next(ctx, tx, simulate)
}
