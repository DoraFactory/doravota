package sponsor

import (
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Context key for sponsor payment information
type sponsorPaymentKey struct{}

// SponsorPaymentInfo holds all sponsor payment context information
type SponsorPaymentInfo struct {
	ContractAddr sdk.AccAddress
	UserAddr     sdk.AccAddress
	Fee          sdk.Coins
	IsSponsored  bool
}

// SponsorContractTxAnteDecorator handles sponsoring contract transactions
type SponsorContractTxAnteDecorator struct {
	keeper        keeper.Keeper
	accountKeeper authkeeper.AccountKeeper
	bankKeeper    bankkeeper.Keeper
}

// NewSponsorContractTxAnteDecorator creates a new ante decorator for sponsored contract transactions
func NewSponsorContractTxAnteDecorator(k keeper.Keeper, ak authkeeper.AccountKeeper, bk bankkeeper.Keeper) SponsorContractTxAnteDecorator {
	return SponsorContractTxAnteDecorator{
		keeper:        k,
		accountKeeper: ak,
		bankKeeper:    bk,
	}
}

// AnteHandle implements the ante handler for sponsored contract transactions
func (sctd SponsorContractTxAnteDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	// Check if sponsorship is globally enabled first
	params := sctd.keeper.GetParams(ctx)
	if !params.SponsorshipEnabled {
		// Sponsorship is globally disabled, skip all sponsor logic
		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"sponsorship globally disabled, using standard fee processing",
		)
		
		// Emit event to notify users that sponsorship is disabled
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeSponsorshipDisabled,
				sdk.NewAttribute(types.AttributeKeyReason, "globally_disabled"),
			),
		)
		
		return next(ctx, tx, simulate)
	}

	// Check for feegrant first - if present, delegate to standard processing
	if feeTx, ok := tx.(sdk.FeeTx); ok {
		feeGranter := feeTx.FeeGranter()
		if feeGranter != nil && !feeGranter.Empty() {
			// Transaction has feegrant set, skip sponsor logic entirely
			// Let standard fee processing handle feegrant behavior
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"transaction has feegrant set, skipping sponsor logic",
				"granter", feeGranter.String(),
			)
			return next(ctx, tx, simulate)
		}
	}

	// Find and validate contract execution messages
	contractAddr, err := validateSponsoredTransaction(tx)
	if err != nil {
		return ctx, err
	}

	// If no contract execution found, pass through
	if contractAddr == "" {
		return next(ctx, tx, simulate)
	}

	// Check if this contract is sponsored
	IsSponsored := sctd.keeper.IsSponsored(ctx, contractAddr)

	// Only apply sponsor functionality if the contract is explicitly sponsored
	if IsSponsored {
		// Get the appropriate user address for policy check and fee payment
		userAddr, err := sctd.getUserAddressForSponsorship(tx)
		if err != nil {
			// If we can't determine a consistent user address, fall back to standard processing
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"falling back to standard fee processing due to signer inconsistency",
				"contract", contractAddr,
				"error", err.Error(),
			)
			return next(ctx, tx, simulate)
		}

		if userAddr.Empty() {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "no signers found in transaction")
		}

		// Call contract to check if user is eligible according to contract policy
		// Create a gas-limited context to prevent DoS attacks through contract queries
		gasLimit := params.MaxGasPerSponsorship

		// Create a limited gas meter for the policy check
		limitedGasMeter := sdk.NewGasMeter(gasLimit)
		limitedCtx := ctx.WithGasMeter(limitedGasMeter)

		eligible, err := func() (bool, error) {
			defer func() {
				if r := recover(); r != nil {
					// Handle gas limit exceeded panic
					if _, ok := r.(sdk.ErrorOutOfGas); ok {
						err = sdkerrors.Wrapf(types.ErrGasLimitExceeded,
							"contract policy check exceeded gas limit: %d, used: %d",
							gasLimit, limitedGasMeter.GasConsumed())
					} else {
						// Re-panic for other types of panics
						panic(r)
					}
				}
			}()
			return sctd.keeper.CheckContractPolicy(limitedCtx, contractAddr, userAddr)
		}()

		// Add the consumed gas back to the original context
		gasUsed := limitedGasMeter.GasConsumed()
		ctx.GasMeter().ConsumeGas(gasUsed, "contract policy check")
		if err != nil {
			// If contract policy check fails, we must reject the sponsored transaction
			// This is critical for security - we cannot sponsor transactions without verifying eligibility
			ctx.Logger().With("module", "sponsor-contract-tx").Error(
				"Contract policy check failed, rejecting sponsored transaction",
				"contract", contractAddr,
				"user", userAddr.String(),
				"error", err.Error(),
			)
			return ctx, sdkerrors.Wrapf(
				types.ErrPolicyCheckFailed,
				"contract policy check failed for user %s on contract %s: %s",
				userAddr.String(),
				contractAddr,
				err.Error(),
			)
		} else if !eligible {
			// User is not eligible according to contract policy
			return ctx, sdkerrors.Wrapf(
				sdkerrors.ErrUnauthorized,
				"user %s is not eligible for sponsored transaction according to contract %s policy",
				userAddr.String(),
				contractAddr,
			)
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"user is eligible for sponsored transaction according to contract policy",
			"contract", contractAddr,
			"user", userAddr.String(),
		)

		// Validate contract address
		contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
		if err != nil {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid contract address")
		}

		// Handle sponsored fee payment using feegrant-like mechanism
		feeTx, ok := tx.(sdk.FeeTx)
		if ok {
			fee := feeTx.GetFee()
			if !fee.IsZero() {
				// Anti-abuse check: Only sponsor users who cannot afford the fee themselves
				// If user has sufficient balance, let them pay their own fees
				userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
				if userBalance.IsAllGTE(fee) {
					ctx.Logger().With("module", "sponsor-contract-tx").Info(
						"user has sufficient balance to pay fees themselves, skipping sponsor",
						"user", userAddr.String(),
						"user_balance", userBalance.String(),
						"required_fee", fee.String(),
					)

					// Emit user self pay event
					ctx.EventManager().EmitEvent(
						sdk.NewEvent(
							types.EventTypeUserSelfPay,
							sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
							sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
							sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
						),
					)

					// Don't sponsor - let standard fee processing handle this
					return next(ctx, tx, simulate)
				}

				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"user has insufficient balance, proceeding with sponsor",
					"user", userAddr.String(),
					"user_balance", userBalance.String(),
					"required_fee", fee.String(),
				)

				// Check user's grant limit before processing the transaction
				if err := sctd.keeper.CheckUserGrantLimit(ctx, userAddr.String(), contractAddr, fee); err != nil {
					return ctx, err
				}

				// Check if sponsor has sufficient balance
				sponsorBalance := sctd.bankKeeper.SpendableCoins(ctx, contractAccAddr)
				if !sponsorBalance.IsAllGTE(fee) {
					// Emit sponsor insufficient funds event
					ctx.EventManager().EmitEvent(
						sdk.NewEvent(
							types.EventTypeSponsorInsufficient,
							sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
							sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
							sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
						),
					)
					return ctx, sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "sponsor account %s has insufficient funds: required %s, available %s", contractAccAddr, fee, sponsorBalance)
				}

				// Store sponsor payment info in context for custom fee handling using type-safe key
				// Don't use SetFeeGranter as it conflicts with standard feegrant system
				sponsorPayment := SponsorPaymentInfo{
					ContractAddr: contractAccAddr,
					UserAddr:     userAddr,
					Fee:          fee,
					IsSponsored:  true,
				}
				ctx = ctx.WithValue(sponsorPaymentKey{}, sponsorPayment)

				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"sponsor info stored in context",
					"sponsor", contractAccAddr.String(),
					"user", userAddr.String(),
					"fee", fee.String(),
				)
			}
		}

		// Event will be emitted in sponsor_decorator.go after successful fee deduction
	}

	return next(ctx, tx, simulate)
}

// validateSponsoredTransaction validates that the transaction meets sponsor requirements
func validateSponsoredTransaction(tx sdk.Tx) (string, error) {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return "", nil
	}

	var sponsoredContract string

	// Check messages - for sponsored transactions, only allow MsgExecuteContract to the same sponsored contract
	for _, msg := range msgs {
		switch execMsg := msg.(type) {
		case *wasmtypes.MsgExecuteContract:
			// This is a contract execution message
			if sponsoredContract == "" {
				// First contract message - record the contract address
				sponsoredContract = execMsg.Contract
			} else {
				// Additional contract message - must be the same contract
				if execMsg.Contract != sponsoredContract {
					return "", sdkerrors.Wrap(sdkerrors.ErrUnauthorized, "sponsored transaction can only contain messages for the same contract")
				}
			}
		default:
			// Found non-contract message firstly in the transaction, pass through(no sponsor needed)
			if sponsoredContract == "" {
				return "", nil
			} else {
				// Found non-contract message later in the transaction - reject immediately
				return "", sdkerrors.Wrap(sdkerrors.ErrUnauthorized, "sponsored transaction cannot contain non-contract messages")
			}
		}
	}

	return sponsoredContract, nil
}

// getUserAddressForSponsorship determines the appropriate user address for sponsorship
// It first validates signer consistency, then checks FeePayer consistency for security
func (sctd SponsorContractTxAnteDecorator) getUserAddressForSponsorship(tx sdk.Tx) (sdk.AccAddress, error) {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return sdk.AccAddress{}, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "transaction has no messages")
	}

	// First, validate all message signers are consistent for security
	var validatedSigner sdk.AccAddress
	var allSigners []sdk.AccAddress

	for i, msg := range msgs {
		msgSigners := msg.GetSigners()
		if len(msgSigners) == 0 {
			return sdk.AccAddress{}, sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "message at index %d has no signers", i)
		}

		// For the first message, record all its signers
		if i == 0 {
			validatedSigner = msgSigners[0]
			allSigners = append(allSigners, msgSigners...)
		} else {
			// For subsequent messages, ensure signers match the first message
			if len(msgSigners) != len(allSigners) {
				return sdk.AccAddress{}, sdkerrors.Wrap(sdkerrors.ErrUnauthorized, 
					"inconsistent signer count across messages - sponsored transactions require consistent signers")
			}

			for j, signer := range msgSigners {
				if !signer.Equals(allSigners[j]) {
					return sdk.AccAddress{}, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized,
						"signer mismatch at message %d, position %d - sponsored transactions require consistent signers", i, j)
				}
			}
		}
	}

	// Reject multi-signer transactions for security reasons
	if len(allSigners) > 1 {
		return sdk.AccAddress{}, sdkerrors.Wrap(sdkerrors.ErrUnauthorized,
			"multi-signer transactions are not supported for sponsorship - please use single signer transactions or separate transactions")
	}

	// Now check FeePayer, but it must be consistent with validated signers for security
	if feeTx, ok := tx.(sdk.FeeTx); ok {
		feePayer := feeTx.FeePayer()
		if !feePayer.Empty() {
			// Security check: FeePayer must match the validated signer to prevent abuse
			// This prevents users from setting arbitrary FeePayer addresses
			if !feePayer.Equals(validatedSigner) {
				return sdk.AccAddress{}, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized,
					"FeePayer %s does not match message signer %s - potential security risk in sponsored transactions", 
					feePayer.String(), validatedSigner.String())
			}
			return feePayer, nil
		}
	}

	return validatedSigner, nil
}
