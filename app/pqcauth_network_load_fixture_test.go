package app_test

// An opt-in fixture generator for scripts/rehearse-pqcauth-capacity.py, not a
// production signing command. All keys below are PUBLIC, deterministic test
// keys. Only synthetic chains prefixed pqc-isolated- are accepted.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
)

func TestPQCAuthGenerateNetworkLoad(t *testing.T) {
	dir := os.Getenv("PQC_NETWORK_LOAD_DIR")
	if dir == "" {
		t.Skip("opt-in isolated network fixture generator")
	}
	sdk.GetConfig().SetBech32PrefixForAccount("dora", "dorapub")
	generatePQCNetworkLoad(t, dir)
}

func generatePQCNetworkLoad(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "load-config.json"))
	require.NoError(t, err)
	var cfg struct {
		ChainID        string            `json:"chain_id"`
		Kind           string            `json:"kind"`
		Phase          string            `json:"phase"`
		Count          int               `json:"count"`
		Params         json.RawMessage   `json:"params"`
		AccountNumbers map[string]uint64 `json:"account_numbers"`
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))
	require.True(t, strings.HasPrefix(cfg.ChainID, "pqc-isolated-"))
	require.Contains(t, []string{"hybrid", "classic", "native"}, cfg.Kind)
	require.Greater(t, cfg.Count, 0)
	require.LessOrEqual(t, cfg.Count, 5000)
	a := policyTestApp(t)
	p := pqctypes.DefaultParams()
	require.NoError(t, a.AppCodec().UnmarshalJSON(cfg.Params, &p))
	require.NoError(t, p.Validate())
	genesis := pqctypes.GenesisState{Params: p}
	keys := make([]cryptotypes.PrivKey, 7)
	addresses := make([]string, 7)
	factorKeys := make([][]byte, 7)
	for i := range keys {
		seed := sha256.Sum256([]byte(fmt.Sprintf("PUBLIC SYNTHETIC PQC LOAD ONLY/%s/%d", cfg.Kind, i)))
		keys[i] = secp256k1.GenPrivKeyFromSecret(seed[:])
		if cfg.Kind == "native" {
			k, e := mldsa65.GenPrivKeyFromSeed(seed[:])
			require.NoError(t, e)
			keys[i] = &k
		}
		owner := sdk.AccAddress(keys[i].PubKey().Address()).String()
		addresses[i] = owner
		if cfg.Kind == "hybrid" {
			for role := 1; role <= 2; role++ {
				fs := sha256.Sum256([]byte(fmt.Sprintf("PUBLIC SYNTHETIC FACTOR ONLY/%d/%d", i, role)))
				pub, priv, e := pqccrypto.GenerateMLDSA65Key(bytes.NewReader(fs[:]))
				require.NoError(t, e)
				if role == 1 {
					factorKeys[i] = priv
				}
				genesis.Keys = append(genesis.Keys, pqctypes.PQCKeyRecord{Owner: owner, KeyId: uint64(role), Algorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, PublicKey: pub, Role: pqctypes.KeyRole(role), Status: pqctypes.KeyStatus_KEY_STATUS_LIVE, CreatedHeight: 1, EffectiveHeight: 1})
			}
			genesis.Policies = append(genesis.Policies, pqctypes.AccountPolicy{Owner: owner, CurrentSigningKeyId: 1, RecoveryKeyId: 2, SelfEnforced: true, PolicyVersion: 1})
			genesis.KeySequences = append(genesis.KeySequences, pqctypes.AccountKeySequence{Owner: owner, NextKeyId: 3})
		}
	}
	require.NoError(t, pqctypes.ValidateGenesis(genesis))
	if cfg.Phase == "prepare" {
		publicKeys := make(map[string]json.RawMessage, len(keys))
		for i, key := range keys {
			encoded, e := a.AppCodec().MarshalInterfaceJSON(key.PubKey())
			require.NoError(t, e)
			publicKeys[addresses[i]] = encoded
		}
		out, e := json.Marshal(struct {
			Addresses  []string                   `json:"addresses"`
			PQC        json.RawMessage            `json:"pqcauth"`
			PublicKeys map[string]json.RawMessage `json:"account_public_keys"`
		}{addresses, a.AppCodec().MustMarshalJSON(&genesis), publicKeys})
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "load-genesis.json"), out, 0600))
		return
	}
	require.Equal(t, "sign", cfg.Phase)
	file, err := os.OpenFile(filepath.Join(dir, "load-txs.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err)
	defer file.Close()
	enc := json.NewEncoder(file)
	for n := 0; n < cfg.Count; n++ {
		b := a.TxConfig().NewTxBuilder()
		msgs := make([]sdk.Msg, 7)
		sigs := make([]signing.SignatureV2, 7)
		for i, key := range keys {
			owner := sdk.AccAddress(key.PubKey().Address())
			to := sdk.AccAddress(keys[(i+1)%7].PubKey().Address())
			msgs[i] = banktypes.NewMsgSend(owner, to, sdk.NewCoins(sdk.NewInt64Coin("peaka", 1)))
			sigs[i] = signing.SignatureV2{PubKey: key.PubKey(), Sequence: uint64(n), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
		}
		require.NoError(t, b.SetMsgs(msgs...))
		b.SetGasLimit(3_000_000)
		b.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("peaka", 1000)))
		require.NoError(t, b.SetSignatures(sigs...))
		if cfg.Kind == "hybrid" {
			tx := b.(interface{ GetProtoTx() *txtypes.Tx }).GetProtoTx()
			ext := pqctypes.ExtensionPQCAuth{FormatVersion: 1}
			for i := range keys {
				number, ok := cfg.AccountNumbers[addresses[i]]
				require.True(t, ok)
				doc, e := pqctypes.NewPQCSignDocV1(tx, p.NetworkId, cfg.ChainID, number, uint64(n), uint32(i), addresses[i], 1, pqctypes.Algorithm_ALGORITHM_ML_DSA_65, 1)
				require.NoError(t, e)
				bz, e := pqctypes.MarshalPQCSignDocV1(doc)
				require.NoError(t, e)
				sig, e := pqccrypto.SignMLDSA65(factorKeys[i], bz, []byte(pqctypes.TxSignatureContext), false)
				require.NoError(t, e)
				ext.Signatures = append(ext.Signatures, pqctypes.SignerPQCSignature{SignerIndex: uint32(i), Signer: addresses[i], KeyId: 1, Algorithm: pqctypes.Algorithm_ALGORITHM_ML_DSA_65, PolicyVersion: 1, Signature: sig})
			}
			any, e := codectypes.NewAnyWithValue(&ext)
			require.NoError(t, e)
			b.(sdkclient.ExtendedTxBuilder).SetExtensionOptions(any)
		}
		for i, key := range keys {
			number, ok := cfg.AccountNumbers[addresses[i]]
			require.True(t, ok)
			sigs[i], err = sdktx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: addresses[i], ChainID: cfg.ChainID, AccountNumber: number, Sequence: uint64(n), PubKey: key.PubKey()}, b, key, a.TxConfig(), uint64(n))
			require.NoError(t, err)
		}
		require.NoError(t, b.SetSignatures(sigs...))
		bz, e := a.TxConfig().TxEncoder()(b.GetTx())
		require.NoError(t, e)
		hash := sha256.Sum256(bz)
		require.NoError(t, enc.Encode(map[string]any{"tx": base64.StdEncoding.EncodeToString(bz), "hash": strings.ToUpper(hex.EncodeToString(hash[:])), "bytes": len(bz)}))
	}
}
