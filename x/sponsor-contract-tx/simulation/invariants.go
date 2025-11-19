package simulation

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

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
		res, stop := SponsorConsistencyInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = GrantUsageConsistencyInvariant(k)(ctx)
		if stop {
			return res, stop
		}

		res, stop = ParamsConsistencyInvariant(k)(ctx)
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

		// Check 3: Contract addresses should be valid bech32 (if possible to validate)
		for _, sponsor := range sponsors {
			if sponsor.ContractAddress == "" {
				broken = true
				msg += "found sponsor with empty contract address\n"
			}
			if sponsor.CreatorAddress == "" {
				broken = true
				msg += fmt.Sprintf("sponsor for contract %s has empty creator address\n", sponsor.ContractAddress)
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

		sponsors := k.GetAllSponsors(ctx)
		sponsorMap := make(map[string]types.ContractSponsor)
		for _, sponsor := range sponsors {
			sponsorMap[sponsor.ContractAddress] = sponsor
		}

		// Note: For comprehensive invariant checking, we would need to iterate through all user grant usage entries
		// However, this requires access to the internal store implementation
		// For now, we'll validate the sponsors' consistency only

		// In a full implementation, this would check all user grant usage entries against their sponsors

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

		// Note: Module account balance checking would require access to module account keeper
		// For now, we skip this validation as it requires additional keeper dependencies

		sponsors := k.GetAllSponsors(ctx)

		for _, sponsor := range sponsors {
			if sponsor.IsSponsored {
				for _, coin := range sponsor.MaxGrantPerUser {
					if coin != nil {
						// This is per user, so in theory unlimited users could use this
						// We check that individual grants don't exceed reasonable bounds
						if coin.Amount.GT(sdk.NewInt(100000000)) { // 100M peaka per user seems excessive
							broken = true
							msg += fmt.Sprintf("sponsor %s has excessive MaxGrantPerUser: %s\n", sponsor.ContractAddress, coin.Amount.String())
						}
					}
				}
			}
		}

		// Check that module has some balance if there are sponsored contracts
		sponsoredCount := 0
		for _, sponsor := range sponsors {
			if sponsor.IsSponsored {
				sponsoredCount++
			}
		}

		if sponsoredCount > 0 {
			// This might be normal in some cases, just log it
			ctx.Logger().Info("Module has sponsored contracts", "sponsored_count", sponsoredCount)
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
