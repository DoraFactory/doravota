package types

import (
	"crypto/sha256"
	"encoding/hex"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

const maxPolicyTicketDigestBytes = 128

// ValidateContractSponsorState validates the self-contained invariants of a
// Sponsor record. Keeper-level validation is responsible for checking the
// current lifecycle generation and the corresponding Wasm contract.
func ValidateContractSponsorState(sponsor ContractSponsor, requireGeneration bool) error {
	if err := ValidateContractAddress(sponsor.ContractAddress); err != nil {
		return err
	}
	if sponsor.CreatorAddress == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "sponsor creator address cannot be empty")
	}
	if err := ValidateCanonicalAddress(sponsor.CreatorAddress); err != nil {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidAddress,
			"invalid sponsor creator address: %s",
			sponsor.CreatorAddress,
		)
	}
	if sponsor.SponsorAddress == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "sponsor address cannot be empty")
	}
	if err := ValidateCanonicalAddress(sponsor.SponsorAddress); err != nil {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidAddress,
			"invalid sponsor address: %s",
			sponsor.SponsorAddress,
		)
	}

	contract, _ := AccAddressFromCanonicalBech32(sponsor.ContractAddress)
	expectedSponsor := sdk.AccAddress(address.Derive(contract, []byte("sponsor")))
	storedSponsor, _ := AccAddressFromCanonicalBech32(sponsor.SponsorAddress)
	if !expectedSponsor.Equals(storedSponsor) {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidAddress,
			"sponsor address must be derived from contract address; expected %s, got %s",
			expectedSponsor.String(),
			sponsor.SponsorAddress,
		)
	}

	if sponsor.TicketIssuerAddress != "" {
		if err := ValidateCanonicalAddress(sponsor.TicketIssuerAddress); err != nil {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidAddress,
				"invalid ticket issuer address: %s",
				sponsor.TicketIssuerAddress,
			)
		}
	}
	if sponsor.CreatedAt < 0 || sponsor.UpdatedAt < 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "sponsor timestamps cannot be negative")
	}
	if sponsor.CreatedAt > sponsor.UpdatedAt {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "created_at must be <= updated_at")
	}
	if err := ValidateMaxGrantPerUserConditional(sponsor.MaxGrantPerUser, sponsor.IsSponsored); err != nil {
		return err
	}
	if requireGeneration && sponsor.Generation == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "sponsor generation must be positive")
	}
	return nil
}

// ValidatePolicyTicketState validates the self-contained invariants of a
// ticket. Expiry is allowed to be in the past because Genesis and GC retain
// historical tickets; runtime eligibility is checked separately.
func ValidatePolicyTicketState(ticket PolicyTicket, maxMethodBytes uint32, requireGeneration bool) error {
	if err := ValidateContractAddress(ticket.ContractAddress); err != nil {
		return err
	}
	if ticket.UserAddress == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidAddress, "policy ticket user address cannot be empty")
	}
	if err := ValidateCanonicalAddress(ticket.UserAddress); err != nil {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidAddress,
			"invalid policy ticket user address: %s",
			ticket.UserAddress,
		)
	}
	if ticket.Digest == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket digest cannot be empty")
	}
	if len(ticket.Digest) > maxPolicyTicketDigestBytes {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket digest is too long")
	}
	if maxMethodBytes != 0 && uint32(len(ticket.Method)) > maxMethodBytes {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket method is too long")
	}
	if ticket.Method != "" {
		expectedDigest := ComputeMethodDigestSingle(ticket.ContractAddress, ticket.Method)
		if ticket.Digest != expectedDigest {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"policy ticket digest does not match method; expected %s",
				expectedDigest,
			)
		}
	}
	if ticket.IssuedHeight > ticket.ExpiryHeight {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket issued height exceeds expiry height")
	}
	if ticket.Consumed != (ticket.UsesRemaining == 0) {
		return errorsmod.Wrap(
			sdkerrors.ErrInvalidRequest,
			"policy ticket consumed flag must match zero remaining uses",
		)
	}
	if requireGeneration && ticket.Generation == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "policy ticket generation must be positive")
	}
	return nil
}

// ValidateUserGrantUsageState validates cumulative accounting without applying
// the Sponsor's current grant limit. A later limit reduction must not make
// already-consumed historical usage invalid.
func ValidateUserGrantUsageState(usage UserGrantUsage, requireGeneration bool) error {
	if usage.UserAddress == "" {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "user grant usage user address cannot be empty")
	}
	if err := ValidateCanonicalAddress(usage.UserAddress); err != nil {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidAddress,
			"invalid user grant usage user address: %s",
			usage.UserAddress,
		)
	}
	if err := ValidateContractAddress(usage.ContractAddress); err != nil {
		return err
	}
	if usage.LastUsedTime < 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "last_used_time cannot be negative")
	}

	seenDenom := false
	for _, coin := range usage.TotalGrantUsed {
		if coin == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage coin cannot be nil")
		}
		if coin.Denom != SponsorshipDenom {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidCoins,
				"invalid denomination %q: only %q is supported",
				coin.Denom,
				SponsorshipDenom,
			)
		}
		if seenDenom {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "duplicate user grant usage denomination")
		}
		if coin.Amount.IsNegative() {
			return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, "user grant usage amount cannot be negative")
		}
		seenDenom = true
	}
	if requireGeneration && usage.Generation == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "user grant usage generation must be positive")
	}
	return nil
}

// ComputeMethodDigestSingle is the canonical digest for a single contract
// method. Keeping it in types lets state validation verify method/digest
// consistency without depending on Keeper code.
func ComputeMethodDigestSingle(contractAddr, methodName string) string {
	h := sha256.New()
	h.Write([]byte(CanonicalAddressOrOriginal(contractAddr)))
	h.Write([]byte("method:"))
	h.Write([]byte(methodName))
	return "m:" + hex.EncodeToString(h.Sum(nil))
}
