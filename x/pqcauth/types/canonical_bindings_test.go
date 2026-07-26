package types_test

import (
	"bytes"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sponsortypes "github.com/DoraFactory/doravota/x/sponsor-contract-tx/types"
)

func TestPQCSignDocBindsSponsorMessageFields(t *testing.T) {
	creator := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20)).String()
	contract := sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20)).String()
	enabled := &sponsortypes.MsgSetSponsor{
		Creator:         creator,
		ContractAddress: contract,
		IsSponsored:     true,
	}
	disabled := &sponsortypes.MsgSetSponsor{
		Creator:         creator,
		ContractAddress: contract,
		IsSponsored:     false,
	}

	enabledBytes := canonicalBytesForMessage(t, enabled, "")
	disabledBytes := canonicalBytesForMessage(t, disabled, "")
	require.NotEqual(t, enabledBytes, disabledBytes)
}

func TestPQCSignDocBindsFeeGranter(t *testing.T) {
	signer := sdk.AccAddress(bytes.Repeat([]byte{0x33}, 20))
	message := banktypes.NewMsgSend(
		signer,
		sdk.AccAddress(bytes.Repeat([]byte{0x44}, 20)),
		sdk.NewCoins(sdk.NewInt64Coin("udora", 7)),
	)
	firstGranter := sdk.AccAddress(bytes.Repeat([]byte{0x55}, 20)).String()
	secondGranter := sdk.AccAddress(bytes.Repeat([]byte{0x66}, 20)).String()

	firstBytes := canonicalBytesForMessage(t, message, firstGranter)
	secondBytes := canonicalBytesForMessage(t, message, secondGranter)
	require.NotEqual(t, firstBytes, secondBytes)
}

func TestPQCSignDocBindsNestedAuthzExecution(t *testing.T) {
	grantee := sdk.AccAddress(bytes.Repeat([]byte{0x77}, 20))
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x88}, 20))
	firstRecipient := sdk.AccAddress(bytes.Repeat([]byte{0x99}, 20))
	secondRecipient := sdk.AccAddress(bytes.Repeat([]byte{0xaa}, 20))
	first := authz.NewMsgExec(grantee, []sdk.Msg{banktypes.NewMsgSend(
		granter,
		firstRecipient,
		sdk.NewCoins(sdk.NewInt64Coin("udora", 5)),
	)})
	second := authz.NewMsgExec(grantee, []sdk.Msg{banktypes.NewMsgSend(
		granter,
		secondRecipient,
		sdk.NewCoins(sdk.NewInt64Coin("udora", 5)),
	)})

	firstBytes := canonicalBytesForMessage(t, &first, "")
	secondBytes := canonicalBytesForMessage(t, &second, "")
	require.NotEqual(t, firstBytes, secondBytes)
}

func TestCanonicalTransactionHelpersRejectMalformedInputs(t *testing.T) {
	_, _, err := types.CanonicalBodyBytesWithoutPQCAuth(nil)
	require.ErrorContains(t, err, "transaction body is missing")
	_, err = types.CanonicalAuthInfoBytes(nil)
	require.ErrorContains(t, err, "transaction auth info is missing")
	_, err = types.NewCanonicalPQCTransaction(&txtypes.Tx{
		Body: &txtypes.TxBody{
			ExtensionOptions: []*codectypes.Any{
				{TypeUrl: types.ExtensionPQCAuthTypeURL},
				{TypeUrl: types.ExtensionPQCAuthTypeURL},
			},
		},
		AuthInfo: &txtypes.AuthInfo{},
	})
	require.ErrorContains(t, err, "multiple pqcauth extensions")

	_, err = types.CanonicalRecoveryBodyBytes(nil)
	require.ErrorContains(t, err, "transaction body is missing")
	_, err = types.CanonicalRecoveryBodyBytes(&txtypes.Tx{
		Body: &txtypes.TxBody{},
	})
	require.ErrorContains(t, err, "one top-level MsgRecoverKey")
	_, err = types.CanonicalRecoveryBodyBytes(&txtypes.Tx{
		Body: &txtypes.TxBody{Messages: []*codectypes.Any{{
			TypeUrl: "/doravota.pqcauth.v1.MsgRecoverKey",
			Value:   []byte{0xff},
		}}},
	})
	require.ErrorContains(t, err, "decode recovery message")
}

func canonicalBytesForMessage(t *testing.T, message sdk.Msg, feeGranter string) []byte {
	t.Helper()
	messageAny, err := codectypes.NewAnyWithValue(message)
	require.NoError(t, err)
	tx := &txtypes.Tx{
		Body: &txtypes.TxBody{Messages: []*codectypes.Any{messageAny}},
		AuthInfo: &txtypes.AuthInfo{
			Fee: &txtypes.Fee{
				Granter:  feeGranter,
				GasLimit: 200_000,
			},
		},
	}
	doc, err := types.NewPQCSignDocV1(
		tx,
		[]byte("binding-test-network"),
		"binding-test-1",
		1,
		2,
		0,
		sdk.AccAddress(bytes.Repeat([]byte{0xbb}, 20)).String(),
		3,
		types.Algorithm_ALGORITHM_ML_DSA_65,
		4,
	)
	require.NoError(t, err)
	signBytes, err := types.MarshalPQCSignDocV1(doc)
	require.NoError(t, err)
	return signBytes
}
