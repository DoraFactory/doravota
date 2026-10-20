package ante

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"

	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

// validateNoNestedLifecycleMessages moves the rejection of pqcauth lifecycle
// operations embedded in executable SDK containers to transaction admission.
// The message-server fingerprint remains the authoritative second boundary,
// including for opaque Wasm payloads that Ante cannot generically decode.
func validateNoNestedLifecycleMessages(messages []sdk.Msg, depth int) error {
	if depth > maxNestedAuthzDepth {
		return errorsmod.Wrapf(
			types.ErrUnsafeAuthorization,
			"indirect message depth exceeds %d",
			maxNestedAuthzDepth,
		)
	}

	for _, message := range messages {
		var (
			nested    []sdk.Msg
			container string
			err       error
		)
		switch typed := message.(type) {
		case *authz.MsgExec:
			container = "authz MsgExec"
			if typed == nil {
				err = fmt.Errorf("nil MsgExec")
			} else {
				nested, err = typed.GetMessages()
			}
		case *group.MsgSubmitProposal:
			container = "group proposal"
			if typed == nil {
				err = fmt.Errorf("nil group proposal")
			} else {
				nested, err = typed.GetMsgs()
			}
		case *govv1.MsgSubmitProposal:
			container = "governance proposal"
			if typed == nil {
				err = fmt.Errorf("nil governance proposal")
			} else {
				nested, err = typed.GetMsgs()
			}
		default:
			continue
		}
		if err != nil {
			return errorsmod.Wrapf(
				types.ErrUnsafeAuthorization,
				"cannot inspect %s messages: %v",
				container,
				err,
			)
		}
		for _, inner := range nested {
			if isPQCAuthLifecycleMessage(inner) {
				return errorsmod.Wrapf(
					types.ErrNestedLifecycle,
					"%T cannot be embedded in %s",
					inner,
					container,
				)
			}
		}
		if err := validateNoNestedLifecycleMessages(nested, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func isPQCAuthLifecycleMessage(message sdk.Msg) bool {
	switch message.(type) {
	case *types.MsgRegisterKey,
		*types.MsgRotateKey,
		*types.MsgRotateRecoveryKey,
		*types.MsgSetProtection,
		*types.MsgRevokeKey,
		*types.MsgRecoverKey,
		*types.MsgCancelRecovery:
		return true
	default:
		return false
	}
}
