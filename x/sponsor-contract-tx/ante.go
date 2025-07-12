package sponsor

import (
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
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

		// Add event for sponsored transaction
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				"sponsored_tx",
				sdk.NewAttribute("contract_address", contractAddr),
				sdk.NewAttribute("sponsor_address", contractAccAddr.String()),
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
