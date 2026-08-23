package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"

	"github.com/DoraFactory/doravota/x/pqcauth/internal/execution"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// CaptureRegistrationStateDecorator runs immediately before the SDK
// SetPubKeyDecorator. It preserves whether an exact top-level registration is
// the account's first ordered outgoing transaction and whether the classic
// public key had never previously been stored on chain.
type CaptureRegistrationStateDecorator struct {
	accountKeeper authante.AccountKeeper
}

func NewCaptureRegistrationStateDecorator(
	accountKeeper authante.AccountKeeper,
) CaptureRegistrationStateDecorator {
	return CaptureRegistrationStateDecorator{accountKeeper: accountKeeper}
}

func (d CaptureRegistrationStateDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	if len(tx.GetMsgs()) != 1 {
		return next(ctx, tx, simulate)
	}
	message, ok := tx.GetMsgs()[0].(*types.MsgRegisterKey)
	if !ok {
		return next(ctx, tx, simulate)
	}

	fresh := false
	if owner, err := sdk.AccAddressFromBech32(message.Owner); err == nil {
		account := d.accountKeeper.GetAccount(ctx, owner)
		fresh = account != nil &&
			account.GetSequence() == 0 &&
			account.GetPubKey() == nil
	}
	if unordered, ok := tx.(sdk.TxWithUnordered); ok && unordered.GetUnordered() {
		// Unordered transactions do not consume account sequence, so they cannot
		// establish the one-time freshness property used by this gate.
		fresh = false
	}

	var err error
	ctx, err = execution.CaptureRegistrationCandidate(ctx, message, fresh)
	if err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}
