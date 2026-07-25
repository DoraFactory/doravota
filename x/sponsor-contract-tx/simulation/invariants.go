package simulation

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/keeper"
	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

const (
	InvariantSponsorConsistency    = "sponsor-consistency"
	InvariantGrantUsageConsistency = "grant-usage-consistency"
	InvariantParamsConsistency     = "params-consistency"
	InvariantBalanceConsistency    = "balance-consistency"
	InvariantStateIntegrity        = "state-integrity"
)

// AllInvariants runs all invariants for the sponsor module
func AllInvariants(k keeper.Keeper, ak types.AccountKeeper, bk types.BankKeeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		res, stop := keeper.LifecycleInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = keeper.ParamsInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = SponsorConsistencyInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = GrantUsageConsistencyInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = BalanceConsistencyInvariant(k, bk)(ctx)
		if stop {
			return res, stop
		}

		res, stop = StateIntegrityInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		return "", false
	}
}

// SponsorConsistencyInvariant checks that all sponsor states are consistent
func SponsorConsistencyInvariant(k keeper.Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var (
			broken bool
			msg    string
		)

		sponsors := k.GetAllSponsors(ctx)

		// Check 1: No duplicate contract addresses
		contractAddrs := make(map[string]bool)
		for _, sponsor := range sponsors {
			if contractAddrs[sponsor.ContractAddress] {
				broken = true
				msg += fmt.Sprintf("duplicate sponsor found for contract %s\n", sponsor.ContractAddress)
			}
			contractAddrs[sponsor.ContractAddress] = true
		}

		// Check 2: Sponsored contracts must have valid MaxGrantPerUser
		for _, sponsor := range sponsors {
			if sponsor.IsSponsored {
				if len(sponsor.MaxGrantPerUser) == 0 {
					broken = true
					msg += fmt.Sprintf("sponsored contract %s has empty MaxGrantPerUser\n", sponsor.ContractAddress)
				} else {
					// Validate MaxGrantPerUser contains only peaka and positive amounts
					for _, coin := range sponsor.MaxGrantPerUser {
						if coin == nil {
							broken = true
							msg += fmt.Sprintf("sponsored contract %s has nil coin in MaxGrantPerUser\n", sponsor.ContractAddress)
							continue
						}
						if coin.Denom != types.SponsorshipDenom {
							broken = true
							msg += fmt.Sprintf("sponsored contract %s has invalid denom %s in MaxGrantPerUser\n", sponsor.ContractAddress, coin.Denom)
						}
						if !coin.Amount.IsPositive() {
							broken = true
							msg += fmt.Sprintf("sponsored contract %s has non-positive amount %s in MaxGrantPerUser\n", sponsor.ContractAddress, coin.Amount.String())
						}
					}
				}
			}
		}

		// Check 3: addresses must be canonical and the sponsor account must be
		// derived from the contract address.
		for _, sponsor := range sponsors {
			contractAddress, err := types.AccAddressFromCanonicalBech32(sponsor.ContractAddress)
			if err != nil {
				broken = true
				msg += fmt.Sprintf("sponsor has invalid contract address %q\n", sponsor.ContractAddress)
				continue
			}
			if err := types.ValidateCanonicalAddress(sponsor.CreatorAddress); err != nil {
				broken = true
				msg += fmt.Sprintf("sponsor for contract %s has invalid creator address\n", sponsor.ContractAddress)
			}
			if err := types.ValidateCanonicalAddress(sponsor.SponsorAddress); err != nil {
				broken = true
				msg += fmt.Sprintf("sponsor for contract %s has invalid sponsor address\n", sponsor.ContractAddress)
				continue
			}
			expected := sdk.AccAddress(address.Derive(contractAddress, []byte("sponsor"))).String()
			if sponsor.SponsorAddress != expected {
				broken = true
				msg += fmt.Sprintf(
					"sponsor address mismatch for contract %s: expected %s, got %s\n",
					sponsor.ContractAddress,
					expected,
					sponsor.SponsorAddress,
				)
			}
		}

		return sdk.FormatInvariant(types.ModuleName, InvariantSponsorConsistency, msg), broken
	}
}

// GrantUsageConsistencyInvariant checks user grant usage consistency
func GrantUsageConsistencyInvariant(k keeper.Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var (
			broken bool
			msg    string
		)

		k.IterateUserGrantUsages(ctx, func(usage types.UserGrantUsage) bool {
			if err := types.ValidateCanonicalAddress(usage.UserAddress); err != nil {
				broken = true
				msg += fmt.Sprintf("grant usage has invalid user address %q\n", usage.UserAddress)
			}
			if err := types.ValidateContractAddress(usage.ContractAddress); err != nil {
				broken = true
				msg += fmt.Sprintf("grant usage has invalid contract address %q\n", usage.ContractAddress)
			}
			for _, coin := range usage.TotalGrantUsed {
				switch {
				case coin == nil:
					broken = true
					msg += fmt.Sprintf("grant usage for %s/%s has nil coin\n", usage.ContractAddress, usage.UserAddress)
				case coin.Denom != types.SponsorshipDenom:
					broken = true
					msg += fmt.Sprintf("grant usage for %s/%s has invalid denom %s\n", usage.ContractAddress, usage.UserAddress, coin.Denom)
				case coin.Amount.IsNegative():
					broken = true
					msg += fmt.Sprintf("grant usage for %s/%s has negative amount\n", usage.ContractAddress, usage.UserAddress)
				}
			}
			return false
		})

		return sdk.FormatInvariant(types.ModuleName, InvariantGrantUsageConsistency, msg), broken
	}
}

// ParamsConsistencyInvariant checks module parameters consistency
func ParamsConsistencyInvariant(k keeper.Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var (
			broken bool
			msg    string
		)

		params := k.GetParams(ctx)

		// Parameter validation
		if err := params.Validate(); err != nil {
			broken = true
			msg += fmt.Sprintf("parameter validation failed: %v\n", err)
		}

		return sdk.FormatInvariant(types.ModuleName, InvariantParamsConsistency, msg), broken
	}
}

// BalanceConsistencyInvariant checks balance-related consistency
func BalanceConsistencyInvariant(k keeper.Keeper, bk types.BankKeeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var (
			broken bool
			msg    string
		)

		sponsors := k.GetAllSponsors(ctx)
		if bk == nil {
			return sdk.FormatInvariant(types.ModuleName, InvariantBalanceConsistency, msg), broken
		}
		for _, sponsor := range sponsors {
			sponsorAddress, err := types.AccAddressFromCanonicalBech32(sponsor.SponsorAddress)
			if err != nil {
				continue
			}
			spendable := bk.SpendableCoins(ctx, sponsorAddress)
			if !spendable.IsValid() || spendable.IsAnyNegative() {
				broken = true
				msg += fmt.Sprintf("sponsor %s has invalid spendable balance %s\n", sponsor.ContractAddress, spendable)
			}
		}

		return sdk.FormatInvariant(types.ModuleName, InvariantBalanceConsistency, msg), broken
	}
}

// StateIntegrityInvariant checks overall state integrity
func StateIntegrityInvariant(k keeper.Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var (
			broken bool
			msg    string
		)

		// Check 1: All sponsors should be retrievable by their contract address
		sponsors := k.GetAllSponsors(ctx)
		for _, sponsor := range sponsors {
			retrievedSponsor, found := k.GetSponsor(ctx, sponsor.ContractAddress)
			if !found {
				broken = true
				msg += fmt.Sprintf("sponsor for contract %s exists in GetAllSponsors but not retrievable via GetSponsor\n", sponsor.ContractAddress)
				continue
			}

			// Check consistency of retrieved sponsor
			if retrievedSponsor.ContractAddress != sponsor.ContractAddress {
				broken = true
				msg += fmt.Sprintf("sponsor contract address mismatch: expected %s, got %s\n", sponsor.ContractAddress, retrievedSponsor.ContractAddress)
			}
			if retrievedSponsor.CreatorAddress != sponsor.CreatorAddress {
				broken = true
				msg += fmt.Sprintf("sponsor creator address mismatch for contract %s: expected %s, got %s\n", sponsor.ContractAddress, sponsor.CreatorAddress, retrievedSponsor.CreatorAddress)
			}
			if retrievedSponsor.IsSponsored != sponsor.IsSponsored {
				broken = true
				msg += fmt.Sprintf("sponsor IsSponsored mismatch for contract %s: expected %t, got %t\n", sponsor.ContractAddress, sponsor.IsSponsored, retrievedSponsor.IsSponsored)
			}
		}

		// Check 2: IsSponsored consistency
		for _, sponsor := range sponsors {
			isSponsored := k.IsSponsored(ctx, sponsor.ContractAddress)
			if isSponsored != sponsor.IsSponsored {
				broken = true
				msg += fmt.Sprintf("IsSponsored mismatch for contract %s: sponsor.IsSponsored=%t, k.IsSponsored=%t\n", sponsor.ContractAddress, sponsor.IsSponsored, isSponsored)
			}
		}

		// Note: Store consistency checking would require direct store access
		// For now, we'll perform basic consistency checks using available keeper methods

		return sdk.FormatInvariant(types.ModuleName, InvariantStateIntegrity, msg), broken
	}
}

// Helper functions to identify key types
func isSponsorKey(key []byte) bool {
	return len(key) > 0 && key[0] == types.SponsorKeyPrefix[0]
}

func isUserGrantUsageKey(key []byte) bool {
	return len(key) > 0 && key[0] == types.UserGrantUsageKeyPrefix[0]
}

func isParamsKey(key []byte) bool {
	return len(key) > 0 && key[0] == types.ParamsKey[0]
}
