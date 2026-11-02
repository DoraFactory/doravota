package execution

import (
	"crypto/sha256"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type authorizedLifecycleMessageKey struct{}

type lifecycleMessageFingerprint [sha256.Size]byte

// AuthorizeLifecycleMessage binds the Ante authorization to one exact
// top-level lifecycle message. The unexported context key and Go internal
// package boundary prevent unrelated modules from manufacturing the marker.
func AuthorizeLifecycleMessage(ctx sdk.Context, msg sdk.Msg) (sdk.Context, error) {
	fingerprint, err := fingerprintLifecycleMessage(msg)
	if err != nil {
		return ctx, err
	}
	return ctx.WithValue(authorizedLifecycleMessageKey{}, fingerprint), nil
}

// RequireLifecycleMessage rejects lifecycle messages routed by authz, group,
// wasm, governance, or another module because those messages were not the
// exact top-level message authorized by the pqcauth Ante decorator.
func RequireLifecycleMessage(ctx sdk.Context, msg sdk.Msg) error {
	expected, ok := ctx.Value(authorizedLifecycleMessageKey{}).(lifecycleMessageFingerprint)
	if !ok {
		return types.ErrNestedLifecycle
	}
	actual, err := fingerprintLifecycleMessage(msg)
	if err != nil {
		return err
	}
	if actual != expected {
		return types.ErrNestedLifecycle
	}
	return nil
}

func fingerprintLifecycleMessage(msg sdk.Msg) (lifecycleMessageFingerprint, error) {
	if msg == nil {
		return lifecycleMessageFingerprint{}, types.ErrNestedLifecycle.Wrap("nil lifecycle message")
	}
	messageBytes, err := proto.Marshal(msg)
	if err != nil {
		return lifecycleMessageFingerprint{}, types.ErrNestedLifecycle.Wrapf(
			"cannot encode %s: %v",
			sdk.MsgTypeURL(msg),
			err,
		)
	}
	typeURL := sdk.MsgTypeURL(msg)
	if typeURL == "" {
		return lifecycleMessageFingerprint{}, types.ErrNestedLifecycle.Wrap(
			"lifecycle message has no type URL",
		)
	}
	payload := make([]byte, 0, len(typeURL)+1+len(messageBytes))
	payload = append(payload, typeURL...)
	payload = append(payload, 0)
	payload = append(payload, messageBytes...)
	return sha256.Sum256(payload), nil
}
