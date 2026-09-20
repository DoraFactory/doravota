package app_test

import (
	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRemovedGroupRetainsHistoricalCodecOnly(t *testing.T) {
	a := policyTestApp(t)
	require.Nil(t, a.GetKey("group"))
	require.NotContains(t, a.ModuleManager().Modules, "group")
	msg := &group.MsgCreateGroup{Admin: sdk.AccAddress([]byte("legacy-group-admin!!")).String()}
	encoded, err := codectypes.NewAnyWithValue(msg)
	require.NoError(t, err)
	var decoded sdk.Msg
	require.NoError(t, a.AppCodec().UnpackAny(encoded, &decoded))
	require.IsType(t, msg, decoded)
	require.Nil(t, a.MsgServiceRouter().Handler(decoded))
}
