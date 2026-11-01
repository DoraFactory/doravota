package types

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestEmergencyIntentWireJSONAndSignBytes(t *testing.T) {
	request := MsgUpdateParams{Authority: sdk.AccAddress(make([]byte, 20)).String(), Params: DefaultParams()}
	request.Params.EmergencyMode = EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	require.NoError(t, request.ValidateBasic())
	fullWire, err := request.Marshal()
	require.NoError(t, err)
	fullSignBytes := request.GetSignBytes()
	request.EmergencyOnly = true
	require.NoError(t, request.ValidateBasic())
	emergencyWire, err := request.Marshal()
	require.NoError(t, err)
	require.NotEqual(t, fullWire, emergencyWire)
	require.NotEqual(t, fullSignBytes, request.GetSignBytes(), "intent must be part of the signed message")
	var decoded MsgUpdateParams
	require.NoError(t, decoded.Unmarshal(emergencyWire))
	require.Equal(t, request, decoded)
	json := ModuleCdc.MustMarshalJSON(&request)
	decoded = MsgUpdateParams{}
	require.NoError(t, ModuleCdc.UnmarshalJSON(json, &decoded))
	require.Equal(t, request, decoded)
	// Legacy/default messages retain full-update intent on decode.
	decoded = MsgUpdateParams{}
	require.NoError(t, decoded.Unmarshal(fullWire))
	require.False(t, decoded.EmergencyOnly)
	state := emergencyScheduleFixture()
	response := MsgUpdateParamsResponse{ActivationHeight: 102, ResultingParams: state}
	wire, err := response.Marshal()
	require.NoError(t, err)
	var decodedResponse MsgUpdateParamsResponse
	require.NoError(t, decodedResponse.Unmarshal(wire))
	require.Equal(t, response, decodedResponse)
	json = ModuleCdc.MustMarshalJSON(&response)
	decodedResponse = MsgUpdateParamsResponse{}
	require.NoError(t, ModuleCdc.UnmarshalJSON(json, &decodedResponse))
	require.Equal(t, response, decodedResponse)
}
