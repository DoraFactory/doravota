package ante

import (
	"testing"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestRecheckKeepsAuthorizationGasAndKeyChecks(t *testing.T) {
	for _, state := range []string{"valid", "revoked", "expired", "policy-version"} {
		t.Run(state, func(t *testing.T) {
			ctx, k, accounts, config, secret := setupAnteTest(t)
			_, tx := buildProtectedTx(t, ctx, k, accounts, config, secret)
			owner := accounts.account.GetAddress()
			if state == "revoked" || state == "expired" {
				key, found := k.GetKey(ctx, owner, 1)
				require.True(t, found)
				if state == "revoked" {
					key.Status = types.KeyStatus_KEY_STATUS_REVOKED
				} else {
					key.InactiveFromHeight = uint64(ctx.BlockHeight())
				}
				require.NoError(t, k.SetKey(ctx, owner, key))
			} else if state == "policy-version" {
				p, _ := k.GetAccountPolicy(ctx, owner)
				p.PolicyVersion++
				require.NoError(t, k.SetAccountPolicy(ctx, owner, p))
			}
			for _, recheck := range []bool{false, true} {
				meter := newRecordingGasMeter()
				_, err := NewVerifyPQCDecorator(k, accounts).AnteHandle(ctx.WithIsReCheckTx(recheck).WithGasMeter(meter), tx, false, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return ctx, nil })
				if state != "valid" {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				charges := meter.chargesFor("pqcauth transaction signature verification")
				require.Len(t, charges, 1)
				require.EqualValues(t, 750, charges[0].amount)
			}
		})
	}
}
