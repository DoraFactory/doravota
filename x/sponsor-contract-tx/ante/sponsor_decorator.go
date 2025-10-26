package sponsor

import (
	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	"math"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// SponsorAwareDeductFeeDecorator wraps the standard DeductFeeDecorator and
// handles sponsor fee payments. It is intended to run AFTER
// SponsorContractTxAnteDecorator, which injects SponsorPaymentInfo into the
// context when a tx qualifies for sponsorship.
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

// AnteHandle implements the ante handler interface.
// Behavior:
//   - If SponsorPaymentInfo is present in context and IsSponsored=true, attempt
//     to deduct fees from the sponsor (unless FeeGranter is set on the tx).
//   - Otherwise, fall back to the standard DeductFeeDecorator.
func (safd SponsorAwareDeductFeeDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	// In CheckTx, if ExecuteTicketGate marked this tx as authorized via a valid ticket,
	// skip standard fee checks and proceed. This enables sponsored txs to enter the mempool
	// without requiring the user to prepay fees.
	if ctx.IsCheckTx() {
		if _, ok := ctx.Value(execTicketGateKey{}).(ExecTicketGateInfo); ok {
			// Basic checks already done in SponsorContractTxAnteDecorator; proceed
			return next(ctx, tx, simulate)
		}
	}
	// Check if this transaction has sponsor payment information in context using type-safe key
	if sponsorPayment, ok := ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo); ok {
		if sponsorPayment.IsSponsored {
			// Handle sponsor fee payment directly (two-phase aware; digestion is driven by DigestCounts on context)
            return safd.handleSponsorFeePayment(ctx, tx, simulate, next, sponsorPayment.ContractAddr,
                    sponsorPayment.SponsorAddr, sponsorPayment.UserAddr, sponsorPayment.Fee)
		}
	}

	// Fall back to standard fee decorator
	return safd.standardDecorator.AnteHandle(ctx, tx, simulate, next)
}

// handleSponsorFeePayment processes sponsor fee payment.
// Security/consistency highlights:
//   - Respects feegrant precedence: if tx sets FeeGranter, delegate to the
//     standard DeductFeeDecorator so the native feegrant logic applies.
//   - Computes effective fee using txFeeChecker in non-simulation paths, which
//     enforces min gas price and sets tx priority.
//   - Deducts fees into the fee collector module account and updates per-user
//     grant usage; emits events only in DeliverTx.
//   - Returns a context with priority set so downstream mempool prioritization is
//     consistent with fee calculation.
// handleSponsorFeePayment processes sponsor fee payment using two-phase context.
// It relies on DigestCounts carried in SponsorPaymentInfo for ticket consumption in DeliverTx.
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

	// Pre-checks moved to antecedent decorator; proceed to deduction

	// Step 1: Deduct fee from sponsor account (applies to both CheckTx and DeliverTx).
	// Defensive checks: ensure fee collector module account, sponsor account exist, and fee is valid.
	if addr := safd.accountKeeper.GetModuleAddress(authtypes.FeeCollectorName); addr == nil {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrLogic, "fee collector module account (%s) has not been set", authtypes.FeeCollectorName)
	}
	if safd.accountKeeper.GetAccount(ctx, sponsorAddr) == nil {
		return ctx, sdkerrors.ErrUnknownAddress.Wrapf("sponsor address: %s does not exist", sponsorAddr.String())
	}
	if !effectiveFee.IsValid() {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrInsufficientFee, "invalid fee amount: %s", effectiveFee)
	}
	// deduct fee from sponsor account and send to fee collector module account
	err = safd.bankKeeper.SendCoinsFromAccountToModule(
		ctx,
		sponsorAddr,
		authtypes.FeeCollectorName,
		effectiveFee,
	)
	if err != nil {
		return ctx, errorsmod.Wrapf(err, "failed to deduct sponsor fee from %s", sponsorAddr)
	}

	// Step 3: Update user grant usage atomically.
	if err := safd.sponsorKeeper.UpdateUserGrantUsage(ctx, userAddr.String(), contractAddr.String(), effectiveFee); err != nil {
		return ctx, errorsmod.Wrapf(err, "failed to update user grant usage - sponsor fee deduction will be rolled back")
	}

    // Best-effort: fetch uses_remaining and expiry before consuming (for summary event)
    usesRem := ""
    expiry := ""
    // For per-digest ticket events, take a pre-consumption snapshot for all digests
    type ticketSnap struct { uses uint32; expiry uint64; method string }
    pre := make(map[string]ticketSnap)
    if !ctx.IsCheckTx() {
        if sp, ok := ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo); ok && len(sp.DigestCounts) > 0 {
            if len(sp.DigestCounts) == 1 {
                for dg := range sp.DigestCounts {
                    if t, ok := safd.sponsorKeeper.GetPolicyTicket(ctx, contractAddr.String(), userAddr.String(), dg); ok {
                        pre[dg] = ticketSnap{uses: t.UsesRemaining, expiry: t.ExpiryHeight, method: t.Method}
                        usesRem = fmt.Sprintf("%d", t.UsesRemaining)
                        expiry = fmt.Sprintf("%d", t.ExpiryHeight)
                    }
                }
            } else {
                // Multi-digest: show the most constrained ticket state (min uses_remaining and min expiry)
                minRemaining := uint32(math.MaxUint32)
                minExpiry := uint64(math.MaxUint64)
                for dg := range sp.DigestCounts {
                    if t, ok := safd.sponsorKeeper.GetPolicyTicket(ctx, contractAddr.String(), userAddr.String(), dg); ok {
                        pre[dg] = ticketSnap{uses: t.UsesRemaining, expiry: t.ExpiryHeight, method: t.Method}
                        if t.UsesRemaining < minRemaining {
                            minRemaining = t.UsesRemaining
                        }
                        if t.ExpiryHeight < minExpiry {
                            minExpiry = t.ExpiryHeight
                        }
                    }
                }
                if minRemaining != math.MaxUint32 {
                    usesRem = fmt.Sprintf("%d", minRemaining)
                }
                if minExpiry != math.MaxUint64 {
                    expiry = fmt.Sprintf("%d", minExpiry)
                }
            }
        }
    }

	// Step 4: Consume ticket(s) in DeliverTx upon success. When multiple
	// method digests are required in this tx, consume each digest as many
	// times as needed. Fall back to single digest when no counts provided.
    if !ctx.IsCheckTx() {
        if sp, ok := ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo); ok && len(sp.DigestCounts) > 0 {
            if err := safd.sponsorKeeper.ConsumePolicyTicketsBulk(ctx, contractAddr.String(), userAddr.String(), sp.DigestCounts); err != nil {
                return ctx, errorsmod.Wrapf(err, "failed to consume policy tickets")
            }
        }
    }

    // Step 5: Emit success event only in DeliverTx (avoid events in CheckTx).
    if !ctx.IsCheckTx() {
        dType := "method" // only method tickets are supported
        ev := sdk.NewEvent(
            types.EventTypeSponsoredTx,
            sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr.String()),
            sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAddr.String()),
            sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
            sdk.NewAttribute(types.AttributeKeySponsorAmount, effectiveFee.String()),
            sdk.NewAttribute(types.AttributeKeyIsSponsored, types.AttributeValueTrue),
        )
        if usesRem != "" {
            ev = ev.AppendAttributes(sdk.NewAttribute("uses_remaining", usesRem))
        }
        if expiry != "" {
            ev = ev.AppendAttributes(sdk.NewAttribute(types.AttributeKeyExpiryHeight, expiry))
        }
        ev = ev.AppendAttributes(sdk.NewAttribute("digest_type", dType))
        ctx.EventManager().EmitEvent(ev)

        // Emit per-digest ticket detail events (one per digest)
        if sp, ok := ctx.Value(sponsorPaymentKey{}).(SponsorPaymentInfo); ok && len(sp.DigestCounts) > 0 {
            for dg, consumed := range sp.DigestCounts {
                // Fetch post state
                postUses := uint32(0)
                method := ""
                exp := uint64(0)
                if t, ok := safd.sponsorKeeper.GetPolicyTicket(ctx, contractAddr.String(), userAddr.String(), dg); ok {
                    postUses = t.UsesRemaining
                    method = t.Method
                    exp = t.ExpiryHeight
                }
                // Fall back to pre snapshot for method/expiry if post not found
                if snap, ok := pre[dg]; ok {
                    if method == "" { method = snap.method }
                    if exp == 0 { exp = snap.expiry }
                }
                ctx.EventManager().EmitEvent(
                    sdk.NewEvent(
                        types.EventTypeSponsoredTxTicket,
                        sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr.String()),
                        sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
                        sdk.NewAttribute(types.AttributeKeyDigest, dg),
                        sdk.NewAttribute(types.AttributeKeyMethod, method),
                        sdk.NewAttribute(types.AttributeKeyUsesConsumed, fmt.Sprintf("%d", consumed)),
                        sdk.NewAttribute(types.AttributeKeyUsesRemainingPre, fmt.Sprintf("%d", pre[dg].uses)),
                        sdk.NewAttribute(types.AttributeKeyUsesRemainingPost, fmt.Sprintf("%d", postUses)),
                        sdk.NewAttribute(types.AttributeKeyExpiryHeight, fmt.Sprintf("%d", exp)),
                    ),
                )
            }
        }
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
