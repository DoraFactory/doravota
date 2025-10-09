package sponsor

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	ante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// Context key for sponsor payment information
type sponsorPaymentKey struct{}

// SponsorPaymentInfo holds all sponsor payment context information
type SponsorPaymentInfo struct {
	ContractAddr sdk.AccAddress
	SponsorAddr  sdk.AccAddress // The actual sponsor address that pays fees
	UserAddr     sdk.AccAddress
	Fee          sdk.Coins
	IsSponsored  bool
}

// SponsorContractTxAnteDecorator handles sponsoring contract transactions
type SponsorContractTxAnteDecorator struct {
	keeper        types.SponsorKeeperInterface
	accountKeeper authkeeper.AccountKeeper
	bankKeeper    bankkeeper.Keeper
	txFeeChecker  ante.TxFeeChecker
}

// NewSponsorContractTxAnteDecorator creates a new ante decorator for sponsored contract transactions
func NewSponsorContractTxAnteDecorator(k types.SponsorKeeperInterface, ak authkeeper.AccountKeeper, bk bankkeeper.Keeper, txFeeChecker ante.TxFeeChecker) SponsorContractTxAnteDecorator {
	if txFeeChecker == nil {
		txFeeChecker = SponsorTxFeeCheckerWithValidatorMinGasPrices
	}
	return SponsorContractTxAnteDecorator{
		keeper:        k,
		accountKeeper: ak,
		bankKeeper:    bk,
		txFeeChecker:  txFeeChecker,
	}
}

// AnteHandle implements the ante handler for sponsored contract transactions.
// Security and processing flow (audit-friendly summary):
// - Feegrant precedence: if tx sets FeeGranter, sponsorship is skipped and standard fee handling applies.
// - Transaction shape: only single-contract CosmWasm executions are considered; mixed or non-contract messages pass through and may emit a skip event.
// - Contract existence: verified up-front; in CheckTx returns error, in DeliverTx falls back to user payment and emits a skip event.
// - Global toggle: respects module params; when disabled, sponsorship is skipped with informative events/errors.
// - Signer model: single-signer only; FeePayer must match the validated signer to prevent spoofing.
// - Self-pay preference: if user has sufficient balance for the declared fee, sponsorship is skipped (see note below).
// - Policy check: runs the contract's policy query in a gas-limited context; any panic is recovered; gas used is always charged to the main context.
// - Failure handling: any policy error or nil-result is treated uniformly as a failure; emits a sponsorship_skipped event (DeliverTx only) and falls back.
// - Success path: verifies user grant limit and sponsor balance, then places SponsorPaymentInfo into context for the fee decorator to deduct.
// Notes:
// - The self-pay decision currently uses the tx-declared fee, not the min required fee from TxFeeChecker. If strict parity with validator min gas prices is needed, consider integrating TxFeeChecker here as well.
func (sctd SponsorContractTxAnteDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
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
	validation := validateSponsoredTransaction(tx)

	// If no sponsorship should be attempted, pass through with context-aware UX
	if !validation.SuggestSponsor {
		if validation.SkipReason != "" {
			// Emit event only in DeliverTx so it is indexed on-chain
			if !ctx.IsCheckTx() {
				ctx.EventManager().EmitEvent(
					sdk.NewEvent(
						types.EventTypeSponsorshipSkipped,
						sdk.NewAttribute(types.AttributeKeyReason, validation.SkipReason),
					),
				)
			}

			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"sponsorship skipped",
				"reason", validation.SkipReason,
			)
		}
		return next(ctx, tx, simulate)
	}

	contractAddr := validation.ContractAddress

	// Validate contract exists before proceeding (early exit):
	// - In CheckTx: return an error to avoid entering mempool with a non-existent contract.
	// - In DeliverTx: emit a skip event and fall back to standard fee processing.
	if err := sctd.keeper.ValidateContractExists(ctx, contractAddr); err != nil {
		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"contract not found; skipping sponsorship",
			"contract", contractAddr,
			"error", err.Error(),
		)
		if ctx.IsCheckTx() {
			return ctx, errorsmod.Wrapf(types.ErrContractNotFound, "contract address %s not found", contractAddr)
		}

		// In DeliverTx, fall back to user payment immediately to avoid extra queries
		if feeTx, ok := tx.(sdk.FeeTx); ok {
			userAddr, userErr := sctd.getUserAddressForSponsorship(tx)
			if userErr == nil {
				if !ctx.IsCheckTx() {
					ctx.EventManager().EmitEvent(
						sdk.NewEvent(
							types.EventTypeSponsorshipSkipped,
							sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
							sdk.NewAttribute(types.AttributeKeyReason, "contract_not_found"),
						),
					)
				}
				return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, "contract_not_found")
			}
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"unable to determine user address during contract-not-found fallback",
				"contract", contractAddr,
				"error", userErr,
			)
			if fee := feeTx.GetFee(); fee.IsZero() {
				return next(ctx, tx, simulate)
			}
		}

		return next(ctx, tx, simulate)
	}

	// If contract exsit, check if contract is set as a sponsor
	sponsor, found := sctd.keeper.GetSponsor(ctx, contractAddr)

	// If found and sponsored, proceed with sponsorship logic
	if found && sponsor.IsSponsored {
		// Check if sponsorship is globally enabled first
		params := sctd.keeper.GetParams(ctx)
		if !params.SponsorshipEnabled {
			// If sponsorship is globally disabled, skip all sponsor logic
			if !ctx.IsCheckTx() {
				ctx.EventManager().EmitEvent(
					sdk.NewEvent(
						types.EventTypeSponsorshipDisabled,
						sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
						sdk.NewAttribute(types.AttributeKeyReason, "global_sponsorship_disabled"),
					),
				)
			}
			ctx.Logger().With("module", "sponsor-contract-tx").Info(
				"sponsorship globally disabled, using standard fee processing",
			)

			return next(ctx, tx, simulate)
		}
		// Get the appropriate user address from the tx for policy check and fee payment
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
			return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "no signers found in transaction")
		}

		// Before any potentially expensive work in CheckTx, enforce validator min gas price
		// using the configured txFeeChecker. This rejects low-fee spam early.
		if ctx.IsCheckTx() && !simulate {
			checker := sctd.txFeeChecker
			if checker == nil {
				checker = SponsorTxFeeCheckerWithValidatorMinGasPrices
			}
			if _, _, feeErr := checker(ctx, tx); feeErr != nil {
				return ctx, feeErr
			}
		}

		// Check the tx-declared fee (does not recompute required fees via TxFeeChecker here).
		if feeTx, ok := tx.(sdk.FeeTx); ok {
			fee := feeTx.GetFee()
			// 1. Zero fee early exit: Only effective in mempool (CheckTx), does not affect simulate/DeliverTx.
			if fee.IsZero() && ctx.IsCheckTx() && !simulate {
				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"zero-fee tx; skipping sponsorship checks",
					"contract", contractAddr,
					"user", userAddr.String(),
				)
				return next(ctx, tx, simulate)
			}
			// 2. Non-zero fee and early exit allowed: Only determined when fee>0; both simulate and DeliverTx allow skipping (events are only emitted in DeliverTx)
			if !fee.IsZero() {
				feeCheck := feeTx.GetFee()
				for _, c := range feeCheck {
					if c.Denom != "peaka" {
						return ctx, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "only supports 'peaka' as fee denom; found: %s", c.Denom)
					}
				}
				userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
				if userBalance.IsAllGTE(fee) {
					ctx.Logger().With("module", "sponsor-contract-tx").Info(
						"user can self-pay; skipping sponsorship checks",
						"contract", contractAddr,
						"user", userAddr.String(),
						"user_balance", userBalance.String(),
						"required_fee", fee.String(),
					)
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeUserSelfPay,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyReason, "user has sufficient balance to pay fees themselves, skipping sponsor"),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
							),
						)
					}
					return next(ctx, tx, simulate)
				}

				// Early sponsor balance quick-check BEFORE running policy queries to avoid heavy work
				// Validate sponsor address and ensure sponsor has enough spendable balance for this fee
				sponsorAccAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
				if err != nil {
					return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid sponsor address")
				}
				sponsorBalance := sctd.bankKeeper.SpendableCoins(ctx, sponsorAccAddr)
				if !sponsorBalance.IsAllGTE(fee) {
					// Emit sponsor insufficient funds event only in DeliverTx mode
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeSponsorInsufficient,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAccAddr.String()),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
							),
						)
					}
					return ctx, errorsmod.Wrapf(sdkerrors.ErrInsufficientFunds, "user has insufficient balance and sponsor account %s also has insufficient funds: required %s, available %s", sponsorAccAddr, fee, sponsorBalance)
				}
			}
		}

		// Create a gas-limited context to prevent DoS attacks through contract queries.
		// Gas used in the limited context is always charged back to the main context
		// (both on success and failure) to ensure consistent cost accounting.
		gasLimit := params.MaxGasPerSponsorship

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"starting contract policy check with gas limit",
			"contract", contractAddr,
			"user", userAddr.String(),
			"gas_limit", gasLimit,
		)

		// Create a limited gas meter for the policy check
		limitedGasMeter := sdk.NewGasMeter(gasLimit)
		limitedCtx := ctx.WithGasMeter(limitedGasMeter)

		var policyResult *types.CheckContractPolicyResult
		var policyErr error

		// Call contract to check if user is eligible according to contract policy.
		// Use a function with named return values so the defer can convert panics to errors
		// and set result=nil in failure cases.
		policyResult, policyErr = func() (result *types.CheckContractPolicyResult, err error) {
			defer func() {
				if r := recover(); r != nil {
					gasUsedOnPanic := limitedGasMeter.GasConsumed()
					// Handle gas limit exceeded panic
					if _, ok := r.(sdk.ErrorOutOfGas); ok {
						ctx.Logger().With("module", "sponsor-contract-tx").Error(
							"contract policy check exceeded gas limit",
							"contract", contractAddr,
							"user", userAddr.String(),
							"gas_limit", gasLimit,
							"gas_used", gasUsedOnPanic,
							"gas_overflow", gasUsedOnPanic-gasLimit,
						)
						err = errorsmod.Wrapf(types.ErrGasLimitExceeded,
							"contract policy check exceeded gas limit: %d, used: %d",
							gasLimit, gasUsedOnPanic)
						result = nil // Ensure result is nil when error occurs
					} else {
						// Handle all other types of panics gracefully to prevent chain halt
						// Log the error for debugging but don't crash the node
						ctx.Logger().With("module", "sponsor-contract-tx").Error(
							"unexpected panic during contract policy check",
							"contract", contractAddr,
							"user", userAddr.String(),
							"error", r,
							"gas_used", gasUsedOnPanic,
						)
						err = errorsmod.Wrapf(types.ErrPolicyCheckFailed,
							"contract policy check failed due to unexpected error: %v", r)
						result = nil // Ensure result is nil when error occurs
					}
				}
			}()
			return sctd.keeper.CheckContractPolicy(limitedCtx, contractAddr, userAddr, tx)
		}()

		// Always read gas consumed from the limited gas meter for consistent accounting
		gasUsed := limitedGasMeter.GasConsumed()

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"contract policy check completed",
			"contract", contractAddr,
			"user", userAddr.String(),
			"gas_used", gasUsed,
			"gas_limit", gasLimit,
			"gas_remaining", gasLimit-gasUsed,
		)

		// Unified handling: treat any error or nil result as a failed policy check
		if policyErr != nil || policyResult == nil {
			// Always account for the gas burned during the policy check so low-fee
			// transactions cannot spam expensive contract queries at zero cost.
			consumeGasSafely(ctx, gasUsed, "contract policy check (failed)")

			var reasonFromError string
			if policyErr != nil {
				// Policy check failed with error (contract query failed, parsing failed, etc.)
				ctx.Logger().With("module", "sponsor-contract-tx").Error(
					"contract policy check failed",
					"contract", contractAddr,
					"user", userAddr.String(),
					"gas_used", gasUsed,
					"error", policyErr.Error(),
				)
				reasonFromError = policyErr.Error()
			} else {
				// Safety: nil result without error
				ctx.Logger().With("module", "sponsor-contract-tx").Error(
					"policy result is unexpectedly nil despite no error",
					"contract", contractAddr,
					"user", userAddr.String(),
				)
				reasonFromError = "policy check returned nil result"
			}

			// Emit a skip event for observability (DeliverTx only)
			if !ctx.IsCheckTx() {
				ctx.EventManager().EmitEvent(
					sdk.NewEvent(
						types.EventTypeSponsorshipSkipped,
						sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
						sdk.NewAttribute(types.AttributeKeyReason, reasonFromError),
					),
				)
			}
			return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, reasonFromError)
		}

		// Policy check succeeded; consume gas on the main context for consistent estimation
		consumeGasSafely(ctx, gasUsed, "contract policy check")

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"gas consumed for contract policy check",
			"contract", contractAddr,
			"user", userAddr.String(),
			"gas_consumed", gasUsed,
			"total_gas_after", ctx.GasMeter().GasConsumed(),
		)

		// check if the result is eligible
		if !policyResult.Eligible {
			// User is not eligible according to contract policy, use the specific reason from contract if provided and go back to standard fee processing
			return sctd.handleSponsorshipFallback(ctx, tx, simulate, next, contractAddr, userAddr, policyResult.Reason)
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"user is eligible for sponsored transaction according to contract policy",
			"contract", contractAddr,
			"user", userAddr.String(),
		)

		// If result is eligible, proceed with sponsorship
		// Validate sponsor address
		sponsorAccAddr, err := sdk.AccAddressFromBech32(sponsor.SponsorAddress)
		if err != nil {
			return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid sponsor address")
		}

		// Also validate contract address for context
		contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
		if err != nil {
			return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "invalid contract address")
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

					// Emit user self pay event only in DeliverTx mode
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeUserSelfPay,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyReason, "user has sufficient balance to pay fees themselves, skipping sponsor"),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
							),
						)
					}

					// Don't sponsor - let standard fee processing handle this
					return next(ctx, tx, simulate)
				}

				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"user has insufficient balance, proceeding with sponsor",
					"user", userAddr.String(),
					"user_balance", userBalance.String(),
					"required_fee", fee.String(),
				)

				// Check user's grant limit before processing the transaction and check if the current usage will overflow the max spend limit
				if err := sctd.keeper.CheckUserGrantLimit(ctx, userAddr.String(), contractAddr, fee); err != nil {
					return ctx, err
				}

				// Check if sponsor has sufficient balance
				sponsorBalance := sctd.bankKeeper.SpendableCoins(ctx, sponsorAccAddr)
				if !sponsorBalance.IsAllGTE(fee) {
					// Emit sponsor insufficient funds event only in DeliverTx mode
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeSponsorInsufficient,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeySponsorAddress, sponsorAccAddr.String()),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
							),
						)
					}
					return ctx, errorsmod.Wrapf(sdkerrors.ErrInsufficientFunds, "user has insufficient balance and sponsor account %s also has insufficient funds: required %s, available %s", sponsorAccAddr, fee, sponsorBalance)
				}

				// Store sponsor payment info in context (type-safe key) so the sponsor-aware
				// fee decorator can deduct fees from the sponsor.
				// Do not use FeeGranter here to avoid conflicting with the native feegrant module.
				sponsorPayment := SponsorPaymentInfo{
					ContractAddr: contractAccAddr,
					SponsorAddr:  sponsorAccAddr,
					UserAddr:     userAddr,
					Fee:          fee,
					IsSponsored:  true,
				}
				ctx = ctx.WithValue(sponsorPaymentKey{}, sponsorPayment)

				ctx.Logger().With("module", "sponsor-contract-tx").Info(
					"sponsor info stored in context",
					"contract", contractAccAddr.String(),
					"sponsor", sponsorAccAddr.String(),
					"user", userAddr.String(),
					"fee", fee.String(),
				)
			}
		}

		// Event will be emitted in sponsor_decorator.go after successful fee deduction
	} else if found && !sponsor.IsSponsored { // If not found or not sponsored, skip sponsorship logic
		// Sponsorship is disabled for this contract
		// Emit an informative skip event for observability (DeliverTx only)
		if !ctx.IsCheckTx() {
			ctx.EventManager().EmitEvent(
				sdk.NewEvent(
					types.EventTypeSponsorshipSkipped,
					sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
					sdk.NewAttribute(types.AttributeKeyReason, "contract_sponsorship_disabled"),
				),
			)
		}

		// If the user cannot afford the fee themselves, return a clearer error
		if feeTx, ok := tx.(sdk.FeeTx); ok {
			fee := feeTx.GetFee()
			if !fee.IsZero() {
				// Determine the effective user address (validated signer / feepayer)
				userAddr, err := sctd.getUserAddressForSponsorship(tx)
				if err == nil && !userAddr.Empty() {
					userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
					if !userBalance.IsAllGTE(fee) {
						// Provide a user-facing reason to explain lack of sponsorship
						return ctx, errorsmod.Wrapf(
							sdkerrors.ErrInsufficientFunds,
							"sponsorship disabled for contract %s; user %s has insufficient balance to pay fees. Required: %s, Available: %s",
							contractAddr,
							userAddr.String(),
							fee.String(),
							userBalance.String(),
						)
					}
					// If user can self-pay, record a helpful event in DeliverTx
					if !ctx.IsCheckTx() {
						ctx.EventManager().EmitEvent(
							sdk.NewEvent(
								types.EventTypeUserSelfPay,
								sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
								sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
								sdk.NewAttribute(types.AttributeKeyReason, "contract_sponsorship_disabled"),
								sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
							),
						)
					}
				}
			}
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"sponsorship disabled for contract; using standard fee processing",
			"contract", contractAddr,
		)
	}

	return next(ctx, tx, simulate)
}

// TransactionValidationResult holds the result of transaction validation
type TransactionValidationResult struct {
	ContractAddress string // Empty if no sponsorship should be attempted
	SuggestSponsor  bool   // Is there only one contract address?
	SkipReason      string // Reason why sponsorship was skipped (for events)
}

// validateSponsoredTransaction validates that the transaction meets sponsor requirements
// Returns validation result instead of error to allow fallback to user payment
func validateSponsoredTransaction(tx sdk.Tx) *TransactionValidationResult {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return &TransactionValidationResult{
			ContractAddress: "",
			SuggestSponsor:  false,
			SkipReason:      "",
		}
	}

	var sponsoredContract string

	// Check messages - for sponsored transactions, only allow MsgExecuteContract to the same sponsored contract
	for _, msg := range msgs {
		msgType := sdk.MsgTypeURL(msg)

		switch execMsg := msg.(type) {
		// contract execution message
		case *wasmtypes.MsgExecuteContract:
			if sponsoredContract == "" {
				// First contract message - record the contract address
				sponsoredContract = execMsg.Contract
			} else {
				// Additional contract message - must be the same contract
				if execMsg.Contract != sponsoredContract {
					return &TransactionValidationResult{
						ContractAddress: "",
						SuggestSponsor:  false,
						SkipReason:      fmt.Sprintf("transaction contains messages for multiple contracts: %s and other contract %s", sponsoredContract, execMsg.Contract),
					}
				}
			}
		default:
			// Found non-contract message firstly in the transaction, pass through(no sponsor needed)
			// If the first transaction is a non-contract transaction, it indicates a normal regular transaction.
			// We do not need to mark the event, just execute it like a regular transaction, and the user will not perceive it.
			if sponsoredContract == "" {
				return &TransactionValidationResult{
					ContractAddress: "",
					SuggestSponsor:  false,
					SkipReason:      "",
				}
			} else {
				// Found non-contract message later in the transaction - skip sponsorship
				return &TransactionValidationResult{
					ContractAddress: "",
					SuggestSponsor:  false,
					SkipReason:      fmt.Sprintf("transaction contains mixed messages: contract(%s) + non-contract (%s)", sponsoredContract, msgType),
				}
			}
		}
	}

	// If we get here, all messages are contract messages for the same contract
	return &TransactionValidationResult{
		ContractAddress: sponsoredContract,
		SuggestSponsor:  true,
		SkipReason:      "",
	}
}

// handleSponsorshipFallback handles the case when sponsorship is denied but user might pay themselves
// It checks user balance and provides clear error messages if they can't afford the fees
func (sctd SponsorContractTxAnteDecorator) handleSponsorshipFallback(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
	contractAddr string,
	userAddr sdk.AccAddress,
	reason string,
) (newCtx sdk.Context, err error) {
	// Get transaction fee to check if user can afford it
	feeTx, ok := tx.(sdk.FeeTx)
	if !ok {
		// If we can't get fee info, just proceed with standard processing
		return next(ctx, tx, simulate)
	}

	fee := feeTx.GetFee()
	if fee.IsZero() {
		// Zero fee transaction, just proceed
		return next(ctx, tx, simulate)
	}

	// Check if user has sufficient balance to pay the fee themselves
	userBalance := sctd.bankKeeper.SpendableCoins(ctx, userAddr)
	if !userBalance.IsAllGTE(fee) {
		// User cannot afford the fee and sponsorship was denied
		// Return a clear error message explaining the situation
		return ctx, errorsmod.Wrapf(
			sdkerrors.ErrInsufficientFunds,
			"sponsorship denied for contract %s (reason: %s) and user %s has insufficient balance to pay fees. Required: %s, Available: %s. User needs either sponsorship approval or sufficient balance to pay transaction fees",
			contractAddr,
			reason,
			userAddr.String(),
			fee.String(),
			userBalance.String(),
		)
	}

	// User has sufficient balance, proceed with fallback to standard fee processing
	ctx.Logger().With("module", "sponsor-contract-tx").Info(
		"sponsorship denied but user has sufficient balance, falling back to standard fee processing",
		"contract", contractAddr,
		"user", userAddr.String(),
		"reason", reason,
		"user_balance", userBalance.String(),
		"required_fee", fee.String(),
	)

	// Emit event to notify that sponsorship was attempted but user will pay themselves
	if !ctx.IsCheckTx() {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeUserSelfPay,
				sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
				sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
				sdk.NewAttribute(types.AttributeKeyReason, reason),
				sdk.NewAttribute(types.AttributeKeyFeeAmount, fee.String()),
			),
		)
	}

	return next(ctx, tx, simulate)
}

// getUserAddressForSponsorship determines the appropriate user address for sponsorship.
// Invariants enforced for auditability:
// - All messages must have signers and the signer sets must be identical across messages.
// - Multi-signer transactions are rejected for sponsorship.
// - If a FeePayer is provided by the tx, it MUST equal the validated signer to prevent spoofing.
func (sctd SponsorContractTxAnteDecorator) getUserAddressForSponsorship(tx sdk.Tx) (sdk.AccAddress, error) {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "transaction has no messages")
	}

	// First, validate all message signers are consistent for security
	var validatedSigner sdk.AccAddress
	var allSigners []sdk.AccAddress

	for i, msg := range msgs {
		msgSigners := msg.GetSigners()
		if len(msgSigners) == 0 {
			return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "message at index %d has no signers", i)
		}

		// For the first message, record all its signers
		if i == 0 {
			validatedSigner = msgSigners[0]
			allSigners = append(allSigners, msgSigners...)
		} else {
			// For subsequent messages, ensure signers match the first message
			if len(msgSigners) != len(allSigners) {
				return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrUnauthorized,
					"inconsistent signer count across messages - sponsored transactions require consistent signers")
			}

			for j, signer := range msgSigners {
				if !signer.Equals(allSigners[j]) {
					return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
						"signer mismatch at message %d, position %d - sponsored transactions require consistent signers", i, j)
				}
			}
		}
	}

	// Reject multi-signer transactions for security reasons
	if len(allSigners) > 1 {
		return sdk.AccAddress{}, errorsmod.Wrap(sdkerrors.ErrUnauthorized,
			"multi-signer transactions are not supported for sponsorship - please use single signer transactions or separate transactions")
	}

	// Now check FeePayer, but it must be consistent with validated signers for security
	if feeTx, ok := tx.(sdk.FeeTx); ok {
		feePayer := feeTx.FeePayer()
		if !feePayer.Empty() {
			// Security check: FeePayer must match the validated signer to prevent abuse
			// This prevents users from setting arbitrary FeePayer addresses
			if !feePayer.Equals(validatedSigner) {
				return sdk.AccAddress{}, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
					"FeePayer %s does not match message signer %s - potential security risk in sponsored transactions",
					feePayer.String(), validatedSigner.String())
			}
			return feePayer, nil
		}
	}

	return validatedSigner, nil
}

// consumeGasSafely attempts to consume gas on the main context and logs an error if it panics.
// This prevents a second panic during failure-path accounting from crashing the node.
func consumeGasSafely(ctx sdk.Context, gasUsed uint64, desc string) {
	if gasUsed == 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			ctx.Logger().With("module", "sponsor-contract-tx").Error(
				"failed to consume gas on main context",
				"gas_to_consume", gasUsed,
				"recovery_error", r,
			)
		}
	}()
	// consume gas on the main context for consistency with CheckTx validation
	ctx.GasMeter().ConsumeGas(gasUsed, desc)
}
