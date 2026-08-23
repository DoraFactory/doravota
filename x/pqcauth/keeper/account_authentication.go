package keeper

import (
	"context"
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func (k Keeper) AccountAuthentication(
	ctx context.Context,
	owner sdk.AccAddress,
) (types.AccountAuthentication, error) {
	account := k.accountKeeper.GetAccount(ctx, owner)
	if account == nil {
		return types.AccountAuthenticationUnsupported, errorsmod.Wrap(
			types.ErrUnauthorized,
			"pqcauth owner account not found",
		)
	}
	return types.ClassifyAccountAuthentication(account.GetPubKey()), nil
}

func (k Keeper) RequireClassicAccount(ctx context.Context, owner sdk.AccAddress) error {
	authentication, err := k.AccountAuthentication(ctx, owner)
	if err != nil {
		return err
	}
	switch authentication {
	case types.AccountAuthenticationClassic:
		return nil
	case types.AccountAuthenticationNativePQC:
		return errorsmod.Wrap(
			types.ErrIneligibleAccount,
			"native ML-DSA accounts use SDK authentication and cannot register pqcauth",
		)
	default:
		return fmt.Errorf(
			"%w: unsupported or composite SDK account public key",
			types.ErrIneligibleAccount,
		)
	}
}
