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

// Context key for sponsor information
type sponsorInfoKey struct{}

// SponsorInfo holds sponsor information
type SponsorInfo struct {
	ContractAddr string
	SponsorAddr  sdk.AccAddress
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
	sponsor, found := sctd.keeper.GetSponsor(ctx, contractAddr)

	// Only apply sponsor functionality if the contract is explicitly sponsored
	if found && sponsor.IsSponsored {
		// Get the transaction signer for policy check
		var userAddr sdk.AccAddress
		for _, msg := range tx.GetMsgs() {
			signers := msg.GetSigners()
			if len(signers) > 0 {
				userAddr = signers[0]
				break
			}
		}

		if userAddr.Empty() {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "no signers found in transaction")
		}

		// Call contract to check if user is eligible according to contract policy
		// Create a gas-limited context to prevent DoS attacks through contract queries
		params := sctd.keeper.GetParams(ctx)
		gasLimit := params.MaxGasPerSponsorship
		
		// Create a limited gas meter for the policy check
		limitedGasMeter := sdk.NewGasMeter(gasLimit)
		limitedCtx := ctx.WithGasMeter(limitedGasMeter)
		
		before := ctx.GasMeter().GasConsumed()
		ctx.Logger().Info("📌📌📌📌contract policy check gas before", "used", before)
		
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
		
		after := ctx.GasMeter().GasConsumed()
		ctx.Logger().Info("📌📌📌📌contract policy check gas after", "after", after)
		ctx.Logger().Info("📌📌📌📌contract policy check gas used", "used", gasUsed)
		if err != nil {
			// If contract query fails, log error and continue with normal validation
			// This prevents contract errors from blocking legitimate sponsored transactions
			ctx.Logger().With("module", "sponsor-contract-tx").Error(
				"❌❌❌❌❌❌Failed to check contract policy, continuing with normal validation",
				"contract", contractAddr,
				"user", userAddr.String(),
				"error", err.Error(),
			)
		} else if !eligible {
			// User is not eligible according to contract policy
			return ctx, sdkerrors.Wrapf(
				sdkerrors.ErrUnauthorized,
				"🚫🚫🚫🚫🚫🚫user %s is not eligible for sponsored transaction according to contract %s policy",
				userAddr.String(),
				contractAddr,
			)
		}

		ctx.Logger().With("module", "sponsor-contract-tx").Info(
			"user is eligible for sponsored transaction according to contract policy✅✅✅✅✅✅✅✅✅✅",
			"contract", contractAddr,
			"user", userAddr.String(),
		)

		// Validate contract address
		contractAccAddr, err := sdk.AccAddressFromBech32(contractAddr)
		if err != nil {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid contract address")
		}
		// Handle sponsored fee payment by pre-transferring funds
		feeTx, ok := tx.(sdk.FeeTx)
		if ok {
			fee := feeTx.GetFee()
			if !fee.IsZero() {
				// Get the fee payer
				feePayer := feeTx.FeePayer()
				if feePayer == nil {
					// Get signers from the transaction's messages
					var signers []sdk.AccAddress
					for _, msg := range tx.GetMsgs() {
						signers = append(signers, msg.GetSigners()...)
					}
					if len(signers) > 0 {
						feePayer = signers[0]
					} else {
						return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "no signers found")
					}
				}

				// In simulation mode, we don't need to do actual transfers
				// but we need to validate that sponsor has sufficient balance
				if simulate {
					sponsorBalance := sctd.bankKeeper.SpendableCoins(ctx, contractAccAddr)
					if !sponsorBalance.IsAllGTE(fee) {
						return ctx, sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "sponsor account %s has insufficient funds: required %s, available %s", contractAccAddr, fee, sponsorBalance)
					}
				} else {
					// Check if sponsor has sufficient balance
					sponsorBalance := sctd.bankKeeper.SpendableCoins(ctx, contractAccAddr)
					if !sponsorBalance.IsAllGTE(fee) {
						return ctx, sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "sponsor account %s has insufficient funds: required %s, available %s", contractAccAddr, fee, sponsorBalance)
					}

					// Transfer fee amount from sponsor to fee payer
					// This ensures the standard fee decorator can deduct normally
					err = sctd.bankKeeper.SendCoins(ctx, contractAccAddr, feePayer, fee)
					if err != nil {
						return ctx, sdkerrors.Wrapf(err, "failed to transfer sponsorship funds from %s to %s", contractAccAddr, feePayer)
					}

					ctx.Logger().With("module", "sponsor-contract-tx").Info(
						"Sponsorship funds transferred successfully ✅✅✅✅✅✅✅✅✅✅",
						"from", contractAccAddr.String(),
						"to", feePayer.String(),
						"amount", fee.String(),
					)
				}
			}
		}

		// Store sponsor information in context for event tracking
		sponsorInfo := SponsorInfo{
			ContractAddr: contractAddr,
			SponsorAddr:  contractAccAddr,
			IsSponsored:  true,
		}
		ctx = ctx.WithValue(sponsorInfoKey{}, sponsorInfo)

		// Add event for sponsored transaction using constants
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeSponsoredTx,
				sdk.NewAttribute(types.AttributeKeyContractAddress, contractAddr),
				sdk.NewAttribute(types.AttributeKeyUser, userAddr.String()),
				sdk.NewAttribute(types.AttributeKeyPolicyCheck, types.AttributeValueSuccess),
			),
		)
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
