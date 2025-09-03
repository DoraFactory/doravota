package sponsor

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

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
}

// NewSponsorAwareDeductFeeDecorator creates a sponsor-aware fee decorator
func NewSponsorAwareDeductFeeDecorator(
	ak authkeeper.AccountKeeper,
	bk bankkeeper.Keeper,
	fgk ante.FeegrantKeeper,
	sponsorKeeper types.SponsorKeeperInterface,
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

	feeGranter := feeTx.FeeGranter()
	// Priority: feegrant > sponsor - when FeeGranter is set, use standard fee handling
	if feeGranter != nil && !feeGranter.Empty() {
		// Delegate to standard fee decorator to handle feegrant properly
		return safd.standardDecorator.AnteHandle(ctx, tx, simulate, next)
	}

	// No feegrant, proceed with sponsor payment
	// Validate fee amount using txFeeChecker to ensure it meets minimum requirements
	if safd.txFeeChecker != nil {
		requiredFee, _, err := safd.txFeeChecker(ctx, tx)
		if err != nil {
			return ctx, errorsmod.Wrapf(err, "failed to check required fee")
		}
		
		// Ensure sponsor fee meets minimum gas price and required fee
		if !fee.IsAllGTE(requiredFee) {
			return ctx, errorsmod.Wrapf(
				sdkerrors.ErrInsufficientFee,
				"sponsor fee %s is insufficient, required minimum fee: %s",
				fee.String(),
				requiredFee.String(),
			)
		}
	}

	// Deduct fee from sponsor account
	if !simulate {
		err = safd.bankKeeper.SendCoinsFromAccountToModule(
			ctx,
			sponsorAddr,
			authtypes.FeeCollectorName,
			fee,
		)
		if err != nil {
			return ctx, errorsmod.Wrapf(err, "failed to deduct sponsor fee from %s", sponsorAddr)
		}
		
		// Update user grant usage only in DeliverTx period
		if !ctx.IsCheckTx() {
			if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), contractAddr.String(), fee); err != nil {
				return ctx, errorsmod.Wrapf(err, "failed to update user grant usage")
			}

			// Emit successful sponsored transaction event only in DeliverTx period
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					types.EventTypeSponsoredTx,
					sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr.String()),
					sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAddr.String()),
					sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
					sdk.NewAttribute(types.AttributeKeySponsorAmount, fee.String()),
					sdk.NewAttribute(types.AttributeKeyIsSponsored, types.AttributeValueTrue),
				),
			)

			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"sponsor fee deducted successfully and usage updated",
				"contract", contractAddr.String(),
				"sponsor", sponsorAddr.String(),
				"user", userAddr.String(),
				"fee", fee.String(),
			)
		}
	}

	return next(ctx, tx, simulate)
}
