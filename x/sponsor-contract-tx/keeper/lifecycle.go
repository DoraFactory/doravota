package keeper

import (
	"encoding/binary"
	"math"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

// GetSponsorGeneration returns the persistent lifecycle generation for a
// contract. The generation record survives Sponsor deletion.
func (k Keeper) GetSponsorGeneration(ctx sdk.Context, contractAddr string) uint64 {
	bz := ctx.KVStore(k.storeKey).Get(types.GetSponsorGenerationKey(contractAddr))
	if len(bz) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(bz)
}

func (k Keeper) setSponsorGeneration(ctx sdk.Context, contractAddr string, generation uint64) error {
	if generation == 0 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "sponsor generation must be positive")
	}
	ctx.KVStore(k.storeKey).Set(
		types.GetSponsorGenerationKey(contractAddr),
		types.EncodeUint64BigEndian(generation),
	)
	return nil
}

// SetSponsorGenerationForGenesis restores a generation derived from exported
// Sponsor state. It must be called before importing sponsors, tickets, or usage.
func (k Keeper) SetSponsorGenerationForGenesis(ctx sdk.Context, contractAddr string, generation uint64) error {
	current := k.GetSponsorGeneration(ctx, contractAddr)
	if current != 0 && current != generation {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"conflicting sponsor generation for contract %s: have %d, got %d",
			contractAddr,
			current,
			generation,
		)
	}
	return k.setSponsorGeneration(ctx, contractAddr, generation)
}

// bindSponsorGeneration assigns the persistent current generation to a new
// Sponsor or verifies that an update cannot change it.
func (k Keeper) bindSponsorGeneration(ctx sdk.Context, sponsor *types.ContractSponsor) error {
	current := k.GetSponsorGeneration(ctx, sponsor.ContractAddress)
	existing, found := k.GetSponsor(ctx, sponsor.ContractAddress)

	if found {
		existingGeneration := existing.Generation
		if existingGeneration == 0 {
			existingGeneration = current
			if existingGeneration == 0 {
				existingGeneration = 1
			}
		}
		if current != 0 && current != existingGeneration {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"sponsor generation state mismatch for contract %s",
				sponsor.ContractAddress,
			)
		}
		if sponsor.Generation == 0 {
			sponsor.Generation = existingGeneration
		}
		if sponsor.Generation != existingGeneration {
			return errorsmod.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"cannot change sponsor generation from %d to %d",
				existingGeneration,
				sponsor.Generation,
			)
		}
		if current == 0 {
			return k.setSponsorGeneration(ctx, sponsor.ContractAddress, existingGeneration)
		}
		return nil
	}

	if current == 0 {
		current = sponsor.Generation
		if current == 0 {
			current = 1
		}
		if err := k.setSponsorGeneration(ctx, sponsor.ContractAddress, current); err != nil {
			return err
		}
	}
	if sponsor.Generation == 0 {
		sponsor.Generation = current
	}
	if sponsor.Generation != current {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"sponsor generation %d does not match current generation %d",
			sponsor.Generation,
			current,
		)
	}
	return nil
}

// rotateSponsorGeneration permanently invalidates state from the deleted
// Sponsor lifecycle without scanning tickets or usage records.
func (k Keeper) rotateSponsorGeneration(ctx sdk.Context, sponsor types.ContractSponsor) error {
	generation := sponsor.Generation
	current := k.GetSponsorGeneration(ctx, sponsor.ContractAddress)
	if generation == 0 {
		generation = current
		if generation == 0 {
			generation = 1
		}
	}
	if current != 0 && current != generation {
		return errorsmod.Wrapf(
			sdkerrors.ErrInvalidRequest,
			"sponsor generation state mismatch for contract %s",
			sponsor.ContractAddress,
		)
	}
	if generation == math.MaxUint64 {
		return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "sponsor generation exhausted")
	}
	return k.setSponsorGeneration(ctx, sponsor.ContractAddress, generation+1)
}
