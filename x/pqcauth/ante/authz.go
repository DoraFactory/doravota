package ante

import (
	"context"
	"fmt"

	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/gogoproto/proto"

	pqckeeper "github.com/DoraFactory/doravota/x/pqcauth/keeper"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const maxNestedAuthzDepth = 8

// AuthzGrantReader is deliberately narrower than the authz keeper. The
// granter-indexed query lets Ante test for an existing capability without a
// consensus-path scan over every grant in the chain.
type AuthzGrantReader interface {
	GranterGrants(
		context.Context,
		*authz.QueryGranterGrantsRequest,
	) (*authz.QueryGranterGrantsResponse, error)
}

// AuthzPQCDecorator closes the capability gap between account-level PQC
// enforcement and x/authz. It preserves authz delegation: a granter does not
// re-sign every MsgExec, but a protected granter may only delegate to an
// account whose own transactions are already PQC-enforced.
type AuthzPQCDecorator struct {
	keeper        pqckeeper.Keeper
	accountKeeper authante.AccountKeeper
	authzKeeper   AuthzGrantReader
	codec         codec.Codec
}

func NewAuthzPQCDecorator(
	moduleKeeper pqckeeper.Keeper,
	accountKeeper authante.AccountKeeper,
	authzKeeper AuthzGrantReader,
	appCodec codec.Codec,
) AuthzPQCDecorator {
	return AuthzPQCDecorator{
		keeper:        moduleKeeper,
		accountKeeper: accountKeeper,
		authzKeeper:   authzKeeper,
		codec:         appCodec,
	}
}

func (d AuthzPQCDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	stateCtx := pqcStateContext(ctx, simulate)
	params := d.keeper.GetParams(stateCtx).Effective(stateCtx.BlockHeight())

	for _, message := range tx.GetMsgs() {
		switch msg := message.(type) {
		case *types.MsgRegisterKey:
			if err := d.requireNoExistingGrants(stateCtx, msg.Owner); err != nil {
				return ctx, err
			}
		case *types.MsgSetProtection:
			if msg.Enabled && d.enablesProtection(stateCtx, msg.Owner) {
				if err := d.requireNoExistingGrants(stateCtx, msg.Owner); err != nil {
					return ctx, err
				}
			}
		case *authz.MsgGrant:
			if err := d.validateGrant(stateCtx, params, msg); err != nil {
				return ctx, err
			}
		case *authz.MsgExec:
			if err := d.validateExec(stateCtx, params, msg); err != nil {
				return ctx, err
			}
		}
	}

	return next(ctx, tx, simulate)
}

func (d AuthzPQCDecorator) requireNoExistingGrants(ctx sdk.Context, granter string) error {
	response, err := d.authzKeeper.GranterGrants(
		sdk.WrapSDKContext(ctx),
		&authz.QueryGranterGrantsRequest{
			Granter: granter,
			Pagination: &query.PageRequest{
				Limit: 1,
			},
		},
	)
	if err != nil {
		return errorsmod.Wrap(types.ErrUnsafeAuthorization, err.Error())
	}
	if response != nil && len(response.Grants) != 0 {
		return errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"account %s must revoke all existing authz grants before enabling pqcauth protection",
			granter,
		)
	}
	return nil
}

func (d AuthzPQCDecorator) enablesProtection(ctx sdk.Context, owner string) bool {
	address, err := d.accountKeeper.AddressCodec().StringToBytes(owner)
	if err != nil {
		return true
	}
	policy, found := d.keeper.GetAccountPolicy(ctx, sdk.AccAddress(address))
	if !found {
		return true
	}
	return !policy.Effective(ctx.BlockHeight()).SelfEnforced
}

func (d AuthzPQCDecorator) validateGrant(
	ctx sdk.Context,
	params types.Params,
	message *authz.MsgGrant,
) error {
	granter, err := d.accountAddress(message.Granter)
	if err != nil {
		return err
	}
	protected, pending := d.accountProtection(ctx, params, granter)
	if pending {
		return errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"granter %s has pending PQC protection; grants are frozen until activation",
			message.Granter,
		)
	}
	if !protected {
		return nil
	}

	grantee, err := d.accountAddress(message.Grantee)
	if err != nil {
		return err
	}
	if !d.accountIsPQCEnforced(ctx, params, grantee) {
		return errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"protected granter %s cannot delegate to non-PQC grantee %s",
			message.Granter,
			message.Grantee,
		)
	}
	return nil
}

func (d AuthzPQCDecorator) validateExec(
	ctx sdk.Context,
	params types.Params,
	message *authz.MsgExec,
) error {
	executor, err := d.accountAddress(message.Grantee)
	if err != nil {
		return err
	}
	messages, err := message.GetMessages()
	if err != nil {
		return errorsmod.Wrap(types.ErrUnsafeAuthorization, err.Error())
	}
	return d.validateExecutedMessages(ctx, params, executor, messages, 0)
}

func (d AuthzPQCDecorator) validateExecutedMessages(
	ctx sdk.Context,
	params types.Params,
	executor sdk.AccAddress,
	messages []sdk.Msg,
	depth int,
) error {
	if depth > maxNestedAuthzDepth {
		return errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"nested MsgExec depth exceeds %d",
			maxNestedAuthzDepth,
		)
	}

	for _, message := range messages {
		switch nested := message.(type) {
		case *authz.MsgGrant:
			if err := d.validateGrant(ctx, params, nested); err != nil {
				return err
			}
		case *authz.MsgExec:
			nestedMessages, err := nested.GetMessages()
			if err != nil {
				return errorsmod.Wrap(types.ErrUnsafeAuthorization, err.Error())
			}
			if err := d.validateExecutedMessages(
				ctx,
				params,
				executor,
				nestedMessages,
				depth+1,
			); err != nil {
				return err
			}
		}

		protoMessage, ok := message.(proto.Message)
		if !ok {
			return errorsmod.Wrapf(
				types.ErrUnsafeAuthorization,
				"cannot resolve signer for %T",
				message,
			)
		}
		signers, _, err := d.codec.GetMsgV1Signers(protoMessage)
		if err != nil {
			return errorsmod.Wrap(types.ErrUnsafeAuthorization, err.Error())
		}
		if len(signers) != 1 {
			return errorsmod.Wrapf(
				types.ErrUnsafeAuthorization,
				"authz message %s has %d signers",
				sdk.MsgTypeURL(message),
				len(signers),
			)
		}

		granter := sdk.AccAddress(signers[0])
		protected, _ := d.accountProtection(ctx, params, granter)
		if protected && !d.accountIsPQCEnforced(ctx, params, executor) {
			return errorsmod.Wrapf(
				types.ErrUnsafeAuthorization,
				"PQC-protected granter %s cannot be executed by non-PQC grantee %s",
				granter.String(),
				executor.String(),
			)
		}
	}
	return nil
}

func (d AuthzPQCDecorator) accountProtection(
	ctx sdk.Context,
	params types.Params,
	address sdk.AccAddress,
) (protected bool, pending bool) {
	account := d.accountKeeper.GetAccount(ctx, address)
	if account != nil && types.ClassifyAccountAuthentication(account.GetPubKey()) == types.AccountAuthenticationNativePQC {
		return true, false
	}

	policy, found := d.keeper.GetAccountPolicy(ctx, address)
	if !found {
		return params.EnforcementMode == types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED, false
	}
	effective := policy.Effective(ctx.BlockHeight())
	registered := effective.CurrentSigningKeyId != 0
	protected = pqcRequiredForClassicAccount(params.EnforcementMode, effective, registered)
	pending = policy.PendingEffectiveHeight > uint64(ctx.BlockHeight()) && policy.PendingSelfEnforced
	return protected || pending, pending
}

func (d AuthzPQCDecorator) accountIsPQCEnforced(
	ctx sdk.Context,
	params types.Params,
	address sdk.AccAddress,
) bool {
	account := d.accountKeeper.GetAccount(ctx, address)
	if account == nil {
		return false
	}
	switch types.ClassifyAccountAuthentication(account.GetPubKey()) {
	case types.AccountAuthenticationNativePQC:
		return true
	case types.AccountAuthenticationClassic:
		_, policy, active := d.keeper.GetActiveSigningKey(ctx, address)
		return active && pqcRequiredForClassicAccount(params.EnforcementMode, policy, true)
	default:
		return false
	}
}

func (d AuthzPQCDecorator) accountAddress(encoded string) (sdk.AccAddress, error) {
	address, err := d.accountKeeper.AddressCodec().StringToBytes(encoded)
	if err != nil {
		return nil, errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"invalid account address %q: %v",
			encoded,
			err,
		)
	}
	if len(address) == 0 {
		return nil, fmt.Errorf("%w: empty account address", types.ErrUnsafeAuthorization)
	}
	return sdk.AccAddress(address), nil
}
