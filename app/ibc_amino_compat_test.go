package app_test

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	gogoproto "github.com/cosmos/gogoproto/proto"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	"github.com/stretchr/testify/require"
	protov2 "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestIBCCompatDescriptorOnlyChange(t *testing.T) {
	decode := func(raw []byte) *descriptorpb.FileDescriptorProto {
		r, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		defer r.Close()
		bz, err := io.ReadAll(r)
		require.NoError(t, err)
		var fd descriptorpb.FileDescriptorProto
		require.NoError(t, protov2.Unmarshal(bz, &fd))
		return &fd
	}
	baseline, err := os.ReadFile("testdata/ibc-amino-compat/baseline-tx-descriptor.gz")
	require.NoError(t, err)
	before := decode(baseline)
	after := decode(gogoproto.FileDescriptor("ibc/applications/transfer/v1/tx.proto"))
	field := before.MessageType[0].Field[9]
	require.Equal(t, "use_aliasing", field.GetName())
	require.EqualValues(t, 10, field.GetNumber())
	options, err := protov2.Marshal(field.Options)
	require.NoError(t, err)
	// Only extension 11110005 (amino.dont_omitempty), boolean true.
	require.Equal(t, []byte{0xa8, 0xe7, 0xb0, 0x2a, 0x01}, options)
	field.Options = nil
	require.True(t, protov2.Equal(before, after), "unexpected protobuf descriptor change beyond dont_omitempty")
}

// Public deterministic test key only; never use it to hold funds.
func ibcCompatKey() *secp256k1.PrivKey {
	return secp256k1.GenPrivKeyFromSecret([]byte("vota-ibc-amino-public-regression-fixture"))
}

func ibcCompatMsg(alias bool) *transfertypes.MsgTransfer {
	key := ibcCompatKey()
	return &transfertypes.MsgTransfer{
		SourcePort: "transfer", SourceChannel: "channel-0",
		Token:         sdk.NewInt64Coin(sdk.DefaultBondDenom, 7),
		Sender:        sdk.AccAddress(key.PubKey().Address()).String(),
		Receiver:      "osmo1ch6xyn85japqc7vpdwk6jgkmyunlf2dmtzwx70",
		TimeoutHeight: clienttypes.ZeroHeight(), TimeoutTimestamp: 2000000000000000000,
		UseAliasing: alias,
	}
}

func ibcCompatBuilder(t *testing.T, cfg client.TxConfig, mode signingtypes.SignMode, msgs ...sdk.Msg) client.TxBuilder {
	t.Helper()
	b := cfg.NewTxBuilder()
	require.NoError(t, b.SetMsgs(msgs...))
	b.SetGasLimit(300000)
	b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)))
	require.NoError(t, b.SetSignatures(signingtypes.SignatureV2{
		PubKey: ibcCompatKey().PubKey(), Data: &signingtypes.SingleSignatureData{SignMode: mode},
	}))
	return b
}

func ibcCompatSignBytes(t *testing.T, cfg client.TxConfig, b client.TxBuilder, mode signingtypes.SignMode, account uint64) []byte {
	t.Helper()
	key := ibcCompatKey()
	bz, err := authsigning.GetSignBytesAdapter(t.Context(), cfg.SignModeHandler(), mode,
		authsigning.SignerData{Address: sdk.AccAddress(key.PubKey().Address()).String(),
			ChainID: "policy-test", AccountNumber: account, PubKey: key.PubKey()}, b.GetTx())
	require.NoError(t, err)
	return bz
}

// Exercise the actual application's signing configuration, not a replacement encoder.
func TestIBCCompatAminoEncoding(t *testing.T) {
	cfg := app.MakeEncodingConfig().TxConfig
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprint(alias), func(t *testing.T) {
			msg := ibcCompatMsg(alias)
			require.NoError(t, msg.ValidateBasic())
			b := ibcCompatBuilder(t, cfg, signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, msg)
			bz := ibcCompatSignBytes(t, cfg, b, signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, 17)
			if alias {
				require.Contains(t, string(bz), `"use_aliasing":true`)
			} else {
				require.NotContains(t, string(bz), `use_aliasing`)
			}
			// Protobuf round-trip retains the field and its value.
			raw, err := cfg.TxEncoder()(b.GetTx())
			require.NoError(t, err)
			decoded, err := cfg.TxDecoder()(raw)
			require.NoError(t, err)
			require.Equal(t, alias, decoded.GetMsgs()[0].(*transfertypes.MsgTransfer).UseAliasing)
		})
	}
}

// These fixtures are captured against the unmodified v1.0.0 dependency.
// IBC_CAPTURE_FIXTURES is an explicit maintainer-only fixture generation mode.
func TestIBCCompatUnchangedSignBytes(t *testing.T) {
	cfg := app.MakeEncodingConfig().TxConfig
	key := ibcCompatKey()
	bank := banktypes.NewMsgSend(sdk.AccAddress(key.PubKey().Address()), sdk.AccAddress(make([]byte, 20)), sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)))
	cases := []struct {
		name string
		mode signingtypes.SignMode
		msg  sdk.Msg
	}{
		{"direct-false", signingtypes.SignMode_SIGN_MODE_DIRECT, ibcCompatMsg(false)},
		{"direct-true", signingtypes.SignMode_SIGN_MODE_DIRECT, ibcCompatMsg(true)},
		{"amino-true", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, ibcCompatMsg(true)},
		{"amino-bank", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, bank},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := ibcCompatBuilder(t, cfg, tc.mode, tc.msg)
			bz := ibcCompatSignBytes(t, cfg, b, tc.mode, 17)
			path := "testdata/ibc-amino-compat/" + tc.name + ".hex"
			if os.Getenv("IBC_CAPTURE_FIXTURES") == "1" {
				require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(bz)), 0644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, string(want), hex.EncodeToString(bz))
		})
	}
}

// CheckTx invokes the real AnteHandler and verifier. No IBC counterparty is
// created here: this tests signature acceptance, not packet delivery.
func TestIBCCompatCheckTx(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		mode                                         signingtypes.SignMode
		alias, injectFalse, omitTrue, tamper, wantOK bool
	}{
		{"keplr-omitted-false", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, false, false, false, false, true},
		{"amino-explicit-true", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, true, false, false, false, true},
		{"old-amino-explicit-false-rejected", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, false, true, false, false, false},
		{"true-must-be-signed", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, true, false, true, false, false},
		{"tampered-alias-rejected", signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON, false, false, false, true, false},
		{"direct-false", signingtypes.SignMode_SIGN_MODE_DIRECT, false, false, false, false, true},
		{"direct-true", signingtypes.SignMode_SIGN_MODE_DIRECT, true, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := policyTestApp(t)
			key := ibcCompatKey()
			sender := sdk.AccAddress(key.PubKey().Address())
			val := ed25519.GenPrivKey().PubKey()
			cp := tmtypes.DefaultConsensusParams().ToProto()
			genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()),
				tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(val, 1)}),
				[]authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(sender)},
				banktypes.Balance{Address: sender.String(), Coins: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))})
			require.NoError(t, err)
			raw, err := json.Marshal(genesis)
			require.NoError(t, err)
			stamp := time.Unix(1700000000, 0)
			_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
			require.NoError(t, err)
			_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: stamp.Add(time.Second)})
			require.NoError(t, err)
			_, err = a.Commit()
			require.NoError(t, err)
			msg := ibcCompatMsg(tc.alias)
			cfg := a.TxConfig()
			b := ibcCompatBuilder(t, cfg, tc.mode, msg)
			acc := a.AccountKeeper.GetAccount(a.NewContext(true), sender)
			bz := ibcCompatSignBytes(t, cfg, b, tc.mode, acc.GetAccountNumber())
			if tc.mode == signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON && (!tc.alias || tc.omitTrue) {
				var doc map[string]any
				require.NoError(t, json.Unmarshal(bz, &doc))
				value := doc["msgs"].([]any)[0].(map[string]any)["value"].(map[string]any)
				if tc.injectFalse {
					value["use_aliasing"] = false
				} else {
					delete(value, "use_aliasing")
				}
				bz, err = json.Marshal(doc)
				require.NoError(t, err)
			}
			sig, err := key.Sign(bz)
			require.NoError(t, err)
			if tc.tamper {
				msg.UseAliasing = !msg.UseAliasing
				require.NoError(t, b.SetMsgs(msg))
			}
			require.NoError(t, b.SetSignatures(signingtypes.SignatureV2{PubKey: key.PubKey(), Data: &signingtypes.SingleSignatureData{SignMode: tc.mode, Signature: sig}}))
			raw, err = cfg.TxEncoder()(b.GetTx())
			require.NoError(t, err)
			result, err := a.CheckTx(&abci.RequestCheckTx{Tx: raw})
			require.NoError(t, err)
			if tc.wantOK {
				require.Zero(t, result.Code, result.Log)
			} else {
				require.NotZero(t, result.Code)
				require.Contains(t, result.Log, "signature verification failed")
			}
		})
	}
}
