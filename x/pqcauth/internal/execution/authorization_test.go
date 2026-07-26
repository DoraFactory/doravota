package execution

import (
	"bytes"
	"context"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

func TestLifecycleAuthorizationRequiresExactMessage(t *testing.T) {
	ctx := sdk.Context{}.WithContext(context.Background())
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x41}, 20)).String()
	message := &types.MsgSetProtection{Owner: owner, Enabled: true}

	require.ErrorIs(
		t,
		RequireLifecycleMessage(ctx, message),
		types.ErrNestedLifecycle,
	)
	_, err := AuthorizeLifecycleMessage(ctx, nil)
	require.ErrorIs(t, err, types.ErrNestedLifecycle)

	authorized, err := AuthorizeLifecycleMessage(ctx, message)
	require.NoError(t, err)
	require.NoError(t, RequireLifecycleMessage(authorized, message))
	require.ErrorIs(
		t,
		RequireLifecycleMessage(
			authorized,
			&types.MsgSetProtection{Owner: owner, Enabled: false},
		),
		types.ErrNestedLifecycle,
	)
}
