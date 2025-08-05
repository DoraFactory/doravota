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
	}
}

// AnteHandle implements the ante handler interface
func (safd SponsorAwareDeductFeeDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	// Check if this transaction has sponsor information in context
	if sponsorAddr, ok := ctx.Value("sponsor_contract_addr").(sdk.AccAddress); ok {
		fee, feeOk := ctx.Value("sponsor_fee_amount").(sdk.Coins)
		userAddr, userOk := ctx.Value("sponsor_user_addr").(sdk.AccAddress)

		if feeOk && userOk && !fee.IsZero() {
			// Handle sponsor fee payment directly
			return safd.handleSponsorFeePayment(ctx, tx, simulate, next, sponsorAddr, userAddr, fee)
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
	// Deduct fee from sponsor account directly
	if !simulate {
		err = safd.bankKeeper.SendCoinsFromAccountToModule(
			ctx,
			sponsorAddr,
			authtypes.FeeCollectorName, // Standard fee collector module
			fee,
		)
		if err != nil {
			return ctx, sdkerrors.Wrapf(err, "failed to deduct sponsor fee from %s", sponsorAddr)
		}
		// Update user grant usage ONLY after successful fee deduction
		if contractAddr, ok := ctx.Value("sponsor_contract_addr").(sdk.AccAddress); ok {
			if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), contractAddr.String(), fee); err != nil {
				return ctx, sdkerrors.Wrapf(err, "failed to update user grant usage")
			}

			// Emit successful sponsored transaction event
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					types.EventTypeSponsoredTx,
					sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr.String()),
					sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
					sdk.NewAttribute(types.AttributeKeySponsorAmount, fee.String()),
					sdk.NewAttribute(types.AttributeKeyIsSponsored, "true"),
				),
			)
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"sponsor fee deducted successfully and usage updated",
			"sponsor", sponsorAddr.String(),
			"user", userAddr.String(),
			"fee", fee.String(),
		)
	}

	return next(ctx, tx, simulate)
}
