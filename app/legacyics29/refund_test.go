package legacyics29

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

type testBank struct {
	key  *storetypes.KVStoreKey
	fail sdk.AccAddress
}

func (b testBank) GetAllBalances(ctx context.Context, a sdk.AccAddress) sdk.Coins {
	raw := sdk.UnwrapSDKContext(ctx).KVStore(b.key).Get(a)
	if raw == nil {
		return sdk.NewCoins()
	}
	var coins sdk.Coins
	if err := json.Unmarshal(raw, &coins); err != nil {
		panic(err)
	}
	return coins
}
func (b testBank) set(ctx sdk.Context, a sdk.AccAddress, coins sdk.Coins) {
	raw, err := json.Marshal(coins)
	if err != nil {
		panic(err)
	}
	ctx.KVStore(b.key).Set(a, raw)
}
func (b testBank) BlockedAddr(a sdk.AccAddress) bool {
	return a.Equals(authtypes.NewModuleAddress("feeibc"))
}
func (b testBank) SendCoins(goCtx context.Context, from, to sdk.AccAddress, coins sdk.Coins) error {
	if to.Equals(b.fail) {
		return fmt.Errorf("injected bank failure")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	remaining, negative := b.GetAllBalances(ctx, from).SafeSub(coins...)
	if negative {
		return fmt.Errorf("insufficient funds")
	}
	b.set(ctx, from, remaining)
	b.set(ctx, to, b.GetAllBalances(ctx, to).Add(coins...))
	return nil
}

type testChannels struct{}

func (testChannels) GetChannel(sdk.Context, string, string) (channeltypes.Channel, bool) {
	return channeltypes.Channel{Version: `{"fee_version":"ics29-1","app_version":"ics721-1"}`}, true
}
func fixture(t *testing.T) (sdk.Context, *storetypes.KVStoreKey, testBank) {
	t.Helper()
	keys := storetypes.NewKVStoreKeys(StoreKey, "testbank")
	return testutil.DefaultContextWithKeys(keys, nil, nil), keys[StoreKey], testBank{key: keys["testbank"]}
}
func field(n protowire.Number, b []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
}

// Encode the published ibc-go/v7 v7.3.0 fee.proto layout independently of the
// migration decoder. Each fee component is deliberately nonzero and different.
func packetFee(t *testing.T, address sdk.AccAddress) []byte {
	t.Helper()
	var fee []byte
	for i, amount := range []int64{2, 3, 7} {
		coin := sdk.NewInt64Coin("peaka", amount)
		raw, err := coin.Marshal()
		require.NoError(t, err)
		fee = append(fee, field(protowire.Number(i+1), raw)...)
	}
	return field(1, append(field(1, fee), field(2, []byte(address.String()))...))
}
func TestRefundAndRetire(t *testing.T) {
	a, b := sdk.AccAddress(make([]byte, 20)), sdk.AccAddress(append(make([]byte, 19), 1))
	for _, name := range []string{"empty", "metadata only", "refund", "insufficient", "excess", "second refund fails", "locked", "unknown key", "malformed protobuf"} {
		t.Run(name, func(t *testing.T) {
			ctx, key, bank := fixture(t)
			store := ctx.KVStore(key)
			source := authtypes.NewModuleAddress("feeibc")
			if name != "empty" {
				store.Set(feeKey("transfer", "channel-0"), []byte{1})
			}
			packetKey := []byte("feesInEscrow/transfer/channel-0/1")
			needsFees := name != "empty" && name != "metadata only"
			if needsFees {
				store.Set(packetKey, append(packetFee(t, a), packetFee(t, b)...))
				bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 24)))
			}
			switch name {
			case "insufficient":
				bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 23)))
			case "excess":
				bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 25)))
			case "second refund fails":
				bank.fail = b
			case "locked":
				store.Set([]byte("locked"), []byte{1})
			case "unknown key":
				store.Set([]byte("futureLedger"), []byte{1})
			case "malformed protobuf":
				store.Set(packetKey, []byte{10, 255})
			}
			before := bank.GetAllBalances(ctx, source)
			beforeLedger := append([]byte(nil), store.Get(packetKey)...)
			err := RefundAndRetire(ctx, key, bank, testChannels{})
			if name != "empty" && name != "metadata only" && name != "refund" {
				require.Error(t, err)
				require.Equal(t, before, bank.GetAllBalances(ctx, source))
				require.Equal(t, beforeLedger, store.Get(packetKey))
				require.True(t, bank.GetAllBalances(ctx, a).IsZero())
				return
			}
			require.NoError(t, err)
			require.True(t, bank.GetAllBalances(ctx, source).IsZero())
			require.False(t, store.Has(packetKey))
			if name != "empty" {
				require.True(t, store.Has(feeKey("transfer", "channel-0")))
			}
			if name == "refund" {
				require.Equal(t, "12peaka", bank.GetAllBalances(ctx, a).String())
				require.Equal(t, "12peaka", bank.GetAllBalances(ctx, b).String())
			}
			// Re-reading a cleaned ledger must not pay anybody twice.
			require.NoError(t, RefundAndRetire(ctx, key, bank, testChannels{}))
			if name == "refund" {
				require.Equal(t, "12peaka", bank.GetAllBalances(ctx, a).String())
			}
		})
	}
}
func TestOrphanBalanceIsNotDiscarded(t *testing.T) {
	ctx, key, bank := fixture(t)
	source := authtypes.NewModuleAddress("feeibc")
	bank.set(ctx, source, sdk.NewCoins(sdk.NewInt64Coin("peaka", 1)))
	require.ErrorContains(t, RefundAndRetire(ctx, key, bank, testChannels{}), "does not equal")
	require.Equal(t, "1peaka", bank.GetAllBalances(ctx, source).String())
}
func TestGenesisPreservesWireStateButRejectsFeeLiabilities(t *testing.T) {
	ctx, key, _ := fixture(t)
	m := Module{Key: key}
	a := sdk.AccAddress(make([]byte, 20))
	store := ctx.KVStore(key)
	store.Set(feeKey("transfer", "channel-0"), []byte{1})
	store.Set([]byte("counterpartyPayee/"+a.String()+"/channel-0"), []byte("foreign-payee"))
	raw := m.ExportGenesis(ctx, nil)
	require.NoError(t, (Basic{}).ValidateGenesis(nil, nil, raw))
	other, otherKey, _ := fixture(t)
	otherModule := Module{Key: otherKey}
	otherModule.InitGenesis(other, nil, raw)
	require.JSONEq(t, string(raw), string(otherModule.ExportGenesis(other, nil)))
	invalid, err := json.Marshal([]Entry{{[]byte("feesInEscrow/transfer/channel-0/1"), packetFee(t, a)}})
	require.NoError(t, err)
	require.Error(t, (Basic{}).ValidateGenesis(nil, nil, invalid))
}
