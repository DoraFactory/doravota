// pqcload creates deterministic, test-only genesis fixtures and independently
// signed transactions for pqcauth block-capacity measurements.
//
// It deliberately uses one funded account per transaction. Cosmos SDK's
// ordered mempool does not persist sequence increments between CheckTx calls,
// so a single account cannot reliably preload a block with many consecutive
// transactions. Independent accounts keep the benchmark focused on bytes,
// gas, signature verification, and consensus throughput.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	"github.com/DoraFactory/doravota/app"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	pqctypes "github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	defaultAccountNumberBase = uint64(1_000_000)
	defaultBalance           = uint64(1_000_000_000)
	defaultFee               = int64(1_000)
	defaultTransfer          = int64(1)
)

var configureSDKOnce sync.Once

type extensionOptionsBuilder interface {
	sdkclient.TxBuilder
	SetExtensionOptions(...*codectypes.Any)
}

type protoTxProvider interface {
	GetProtoTx() *txtypes.Tx
}

type fixtureConfig struct {
	ChainID           string `json:"chain_id"`
	Denom             string `json:"denom"`
	Recipient         string `json:"recipient"`
	Seed              string `json:"seed"`
	ClassicCount      int    `json:"classic_count"`
	HybridCount       int    `json:"hybrid_count"`
	NativeCount       int    `json:"native_count"`
	InvalidPQCCount   int    `json:"invalid_pqc_count"`
	OversizedCount    int    `json:"oversized_count"`
	NonCanonicalCount int    `json:"noncanonical_count"`
	BadSequenceCount  int    `json:"bad_sequence_count"`
	ClassicGas        uint64 `json:"classic_gas_limit"`
	HybridGas         uint64 `json:"hybrid_gas_limit"`
	NativeGas         uint64 `json:"native_gas_limit"`
	OversizedGas      uint64 `json:"oversized_gas_limit"`
	Balance           uint64 `json:"balance_per_account"`
	Fee               int64  `json:"fee_per_transaction"`
	Transfer          int64  `json:"transfer_per_transaction"`
}

type genesisPatch struct {
	NetworkIDBase64 string                 `json:"network_id_base64"`
	AuthAccounts    []map[string]any       `json:"auth_accounts"`
	BankBalances    []map[string]any       `json:"bank_balances"`
	SupplyDelta     map[string]string      `json:"supply_delta"`
	PQCKeys         []map[string]any       `json:"pqc_keys"`
	PQCPolicies     []map[string]any       `json:"pqc_policies"`
	PQCKeySequences []map[string]any       `json:"pqc_key_sequences"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type txRecord struct {
	Mode          string `json:"mode"`
	Index         int    `json:"index"`
	Address       string `json:"address"`
	AccountNumber uint64 `json:"account_number"`
	Sequence      uint64 `json:"sequence"`
	GasLimit      uint64 `json:"gas_limit"`
	SizeBytes     int    `json:"size_bytes"`
	Hash          string `json:"hash"`
	TxBase64      string `json:"tx_base64"`
}

type modeSummary struct {
	Count      int    `json:"count"`
	TotalBytes int64  `json:"total_bytes"`
	MinBytes   int    `json:"min_bytes"`
	MaxBytes   int    `json:"max_bytes"`
	MeanBytes  int64  `json:"mean_bytes"`
	GasLimit   uint64 `json:"gas_limit"`
}

type manifest struct {
	GeneratedAtUTC   string                 `json:"generated_at_utc"`
	Generator        string                 `json:"generator"`
	Config           fixtureConfig          `json:"config"`
	NetworkIDBase64  string                 `json:"network_id_base64"`
	AccountNumberMin uint64                 `json:"account_number_min"`
	AccountNumberMax uint64                 `json:"account_number_max"`
	Modes            map[string]modeSummary `json:"modes"`
}

type modeWriter struct {
	file    *os.File
	buffer  *bufio.Writer
	summary modeSummary
}

func main() {
	configureSDK()
	if len(os.Args) < 2 {
		fatalf("usage: pqcload <generate|broadcast> [flags]")
	}
	switch os.Args[1] {
	case "generate":
		generate(os.Args[2:])
	case "broadcast":
		broadcast(os.Args[2:])
	default:
		fatalf("unknown command %q; use generate or broadcast", os.Args[1])
	}
}

func generate(arguments []string) {
	flags := flag.NewFlagSet("generate", flag.ExitOnError)
	outDir := flags.String("out", "", "new output directory")
	chainID := flags.String("chain-id", "pqcauth-capacity-1", "chain ID")
	denom := flags.String("denom", "peaka", "fee and transfer denomination")
	recipientText := flags.String("recipient", "", "recipient bech32 address")
	seed := flags.String("seed", "pqcauth-two-node-capacity-v1", "deterministic test seed")
	classicCount := flags.Int("classic-count", 1_250, "number of classic transactions")
	hybridCount := flags.Int("hybrid-count", 300, "number of pqcauth hybrid transactions")
	nativeCount := flags.Int("native-count", 480, "number of native ML-DSA transactions")
	invalidPQCCount := flags.Int("invalid-pqc-count", 0, "number of hybrid transactions with a correct-length invalid ML-DSA signature")
	oversizedCount := flags.Int("oversized-count", 0, "number of transactions with an oversized canonical pqcauth extension")
	nonCanonicalCount := flags.Int("noncanonical-count", 0, "number of transactions with a non-canonical pqcauth extension encoding")
	badSequenceCount := flags.Int("bad-sequence-count", 0, "number of validly signed transactions whose sequence does not match genesis")
	classicGas := flags.Uint64("classic-gas", 120_000, "gas limit per classic transaction")
	hybridGas := flags.Uint64("hybrid-gas", 400_000, "gas limit per hybrid transaction")
	nativeGas := flags.Uint64("native-gas", 320_000, "gas limit per native transaction")
	oversizedGas := flags.Uint64("oversized-gas", 2_000_000, "gas limit for oversized-extension rejection fixtures")
	balance := flags.Uint64("balance", defaultBalance, "genesis balance per generated account")
	fee := flags.Int64("fee", defaultFee, "fee amount per transaction")
	transfer := flags.Int64("transfer", defaultTransfer, "transfer amount per transaction")
	accountNumberBase := flags.Uint64("account-number-base", defaultAccountNumberBase, "first generated account number")
	if err := flags.Parse(arguments); err != nil {
		fatalf("parse flags: %v", err)
	}
	if *outDir == "" || *recipientText == "" {
		fatalf("--out and --recipient are required")
	}
	if *classicCount < 0 || *hybridCount < 0 || *nativeCount < 0 ||
		*invalidPQCCount < 0 || *oversizedCount < 0 || *nonCanonicalCount < 0 || *badSequenceCount < 0 ||
		*classicCount+*hybridCount+*nativeCount+*invalidPQCCount+*oversizedCount+*nonCanonicalCount+*badSequenceCount == 0 ||
		*classicGas == 0 || *hybridGas == 0 || *nativeGas == 0 || *oversizedGas == 0 ||
		*balance == 0 || *fee < 0 || *transfer <= 0 ||
		uint64(*fee)+uint64(*transfer) > *balance {
		fatalf("invalid count, gas, balance, fee, or transfer argument")
	}
	recipient, err := sdk.AccAddressFromBech32(*recipientText)
	if err != nil || recipient.String() != *recipientText {
		fatalf("invalid canonical recipient: %q", *recipientText)
	}
	if _, err := os.Stat(*outDir); !os.IsNotExist(err) {
		fatalf("output directory must not already exist: %s", *outDir)
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fatalf("create output directory: %v", err)
	}

	config := fixtureConfig{
		ChainID: *chainID, Denom: *denom, Recipient: recipient.String(), Seed: *seed,
		ClassicCount: *classicCount, HybridCount: *hybridCount, NativeCount: *nativeCount,
		InvalidPQCCount: *invalidPQCCount, OversizedCount: *oversizedCount,
		NonCanonicalCount: *nonCanonicalCount, BadSequenceCount: *badSequenceCount,
		ClassicGas: *classicGas, HybridGas: *hybridGas, NativeGas: *nativeGas,
		OversizedGas: *oversizedGas,
		Balance:      *balance, Fee: *fee, Transfer: *transfer,
	}
	encoding := app.MakeEncodingConfig()
	networkID := pqctypes.NetworkIDForChain(*chainID)
	patch := genesisPatch{
		NetworkIDBase64: base64.StdEncoding.EncodeToString(networkID),
		SupplyDelta: map[string]string{
			*denom: fmt.Sprintf("%d", uint64(
				*classicCount+*hybridCount+*nativeCount+*invalidPQCCount+
					*oversizedCount+*nonCanonicalCount+*badSequenceCount,
			)**balance),
		},
		Metadata: map[string]interface{}{
			"test_only":                   true,
			"account_number_base":         fmt.Sprintf("%d", *accountNumberBase),
			"one_transaction_per_account": true,
		},
	}

	writers := map[string]*modeWriter{}
	for _, mode := range []string{
		"classic", "hybrid", "native", "invalid-pqc", "oversized", "noncanonical", "bad-sequence",
	} {
		path := filepath.Join(*outDir, mode+".txs.jsonl")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fatalf("create %s transactions: %v", mode, err)
		}
		writers[mode] = &modeWriter{file: file, buffer: bufio.NewWriterSize(file, 1024*1024)}
	}
	defer closeWriters(writers)

	recoveryKey := deriveMLDSA65(*seed, "hybrid-recovery", 0)
	accountNumber := *accountNumberBase
	generateMode("classic", *classicCount, *classicGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["classic"])
	generateMode("hybrid", *hybridCount, *hybridGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["hybrid"])
	generateMode("native", *nativeCount, *nativeGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["native"])
	generateMode("invalid-pqc", *invalidPQCCount, *hybridGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["invalid-pqc"])
	generateMode("oversized", *oversizedCount, *oversizedGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["oversized"])
	generateMode("noncanonical", *nonCanonicalCount, *hybridGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["noncanonical"])
	generateMode("bad-sequence", *badSequenceCount, *classicGas, &accountNumber, config, networkID, recoveryKey, recipient, encoding.TxConfig, &patch, writers["bad-sequence"])
	closeWriters(writers)

	if err := writeJSON(filepath.Join(*outDir, "genesis-patch.json"), patch, 0o600); err != nil {
		fatalf("write genesis patch: %v", err)
	}
	summaries := make(map[string]modeSummary, len(writers))
	for mode, writer := range writers {
		summary := writer.summary
		if summary.Count > 0 {
			summary.MeanBytes = summary.TotalBytes / int64(summary.Count)
		}
		summaries[mode] = summary
	}
	result := manifest{
		GeneratedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		Generator:        "tests/performance/pqcauth-two-node/cmd/pqcload",
		Config:           config,
		NetworkIDBase64:  base64.StdEncoding.EncodeToString(networkID),
		AccountNumberMin: *accountNumberBase,
		AccountNumberMax: accountNumber - 1,
		Modes:            summaries,
	}
	if err := writeJSON(filepath.Join(*outDir, "manifest.json"), result, 0o644); err != nil {
		fatalf("write manifest: %v", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fatalf("print manifest: %v", err)
	}
}

func generateMode(
	mode string,
	count int,
	gasLimit uint64,
	accountNumber *uint64,
	config fixtureConfig,
	networkID []byte,
	recoveryKey mldsa65.PrivKey,
	recipient sdk.AccAddress,
	txConfig sdkclient.TxConfig,
	patch *genesisPatch,
	writer *modeWriter,
) {
	writer.summary.GasLimit = gasLimit
	for index := 0; index < count; index++ {
		var classical cryptotypes.PrivKey
		var native cryptotypes.PrivKey
		var hybridSigning mldsa65.PrivKey
		switch mode {
		case "classic", "hybrid", "invalid-pqc", "oversized", "noncanonical", "bad-sequence":
			classical = secp256k1.GenPrivKeyFromSecret(deriveSeed(config.Seed, mode+"-classic", index))
		case "native":
			key := deriveMLDSA65(config.Seed, "native", index)
			native = &key
		default:
			fatalf("unsupported mode %q", mode)
		}
		usesHybrid := mode == "hybrid" || mode == "invalid-pqc" || mode == "oversized" || mode == "noncanonical"
		if usesHybrid {
			hybridSigning = deriveMLDSA65(config.Seed, mode+"-signing", index)
		}
		privateKey := classical
		if mode == "native" {
			privateKey = native
		}
		address := sdk.AccAddress(privateKey.PubKey().Address())
		var genesisPublicKey cryptotypes.PubKey
		if usesHybrid {
			// Registered pqcauth accounts have already persisted their classic
			// public key. Genesis validation deliberately rejects an unclassified
			// account, so mirror that state only for the hybrid fixtures.
			genesisPublicKey = privateKey.PubKey()
		}
		appendGenesisAccount(
			patch, address, genesisPublicKey, *accountNumber, config.Denom, config.Balance,
		)
		if usesHybrid {
			appendHybridGenesis(patch, address, hybridSigning.PubKey().Bytes(), recoveryKey.PubKey().Bytes())
		}
		sequence := uint64(0)
		if mode == "bad-sequence" {
			sequence = 1
		}
		raw := buildTransaction(
			mode,
			privateKey,
			hybridSigning.Bytes(),
			address,
			recipient,
			*accountNumber,
			gasLimit,
			sequence,
			config,
			networkID,
			txConfig,
		)
		hash := sha256.Sum256(raw)
		record := txRecord{
			Mode: mode, Index: index, Address: address.String(), AccountNumber: *accountNumber,
			Sequence: sequence, GasLimit: gasLimit, SizeBytes: len(raw), Hash: hex.EncodeToString(hash[:]),
			TxBase64: base64.StdEncoding.EncodeToString(raw),
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			fatalf("encode %s transaction %d: %v", mode, index, err)
		}
		if _, err := writer.buffer.Write(append(encoded, '\n')); err != nil {
			fatalf("write %s transaction %d: %v", mode, index, err)
		}
		writer.summary.Count++
		writer.summary.TotalBytes += int64(len(raw))
		if writer.summary.MinBytes == 0 || len(raw) < writer.summary.MinBytes {
			writer.summary.MinBytes = len(raw)
		}
		if len(raw) > writer.summary.MaxBytes {
			writer.summary.MaxBytes = len(raw)
		}
		*accountNumber++
	}
}

func appendGenesisAccount(
	patch *genesisPatch,
	address sdk.AccAddress,
	publicKey cryptotypes.PubKey,
	accountNumber uint64,
	denom string,
	balance uint64,
) {
	var encodedPublicKey any
	if publicKey != nil {
		switch key := publicKey.(type) {
		case *secp256k1.PubKey:
			encodedPublicKey = map[string]any{
				"@type": "/cosmos.crypto.secp256k1.PubKey",
				"key":   base64.StdEncoding.EncodeToString(key.Bytes()),
			}
		default:
			fatalf("unsupported fixture genesis public key type %T", publicKey)
		}
	}
	patch.AuthAccounts = append(patch.AuthAccounts, map[string]any{
		"@type":          "/cosmos.auth.v1beta1.BaseAccount",
		"address":        address.String(),
		"pub_key":        encodedPublicKey,
		"account_number": fmt.Sprintf("%d", accountNumber),
		"sequence":       "0",
	})
	patch.BankBalances = append(patch.BankBalances, map[string]any{
		"address": address.String(),
		"coins":   []map[string]string{{"denom": denom, "amount": fmt.Sprintf("%d", balance)}},
	})
}

func appendHybridGenesis(patch *genesisPatch, owner sdk.AccAddress, signingPublicKey, recoveryPublicKey []byte) {
	ownerText := owner.String()
	patch.PQCKeys = append(patch.PQCKeys,
		map[string]any{
			"owner": ownerText, "key_id": "1", "algorithm": "ALGORITHM_ML_DSA_65",
			"public_key": base64.StdEncoding.EncodeToString(signingPublicKey),
			"role":       "KEY_ROLE_SIGNING", "status": "KEY_STATUS_LIVE",
			"created_height": "0", "effective_height": "0", "inactive_from_height": "0",
		},
		map[string]any{
			"owner": ownerText, "key_id": "2", "algorithm": "ALGORITHM_ML_DSA_65",
			"public_key": base64.StdEncoding.EncodeToString(recoveryPublicKey),
			"role":       "KEY_ROLE_RECOVERY", "status": "KEY_STATUS_LIVE",
			"created_height": "0", "effective_height": "0", "inactive_from_height": "0",
		},
	)
	patch.PQCPolicies = append(patch.PQCPolicies, map[string]any{
		"owner":                    ownerText,
		"current_signing_key_id":   "1",
		"pending_signing_key_id":   "0",
		"pending_effective_height": "0",
		"self_enforced":            true,
		"pending_self_enforced":    false,
		"policy_version":           "1",
		"pending_policy_version":   "0",
		"recovery_key_id":          "2",
		"pending_recovery_key_id":  "0",
		"pending_change_kind":      "POLICY_CHANGE_KIND_UNSPECIFIED",
		"pending_created_height":   "0",
	})
	patch.PQCKeySequences = append(patch.PQCKeySequences, map[string]any{
		"owner": ownerText, "next_key_id": "3",
	})
}

func buildTransaction(
	mode string,
	privateKey cryptotypes.PrivKey,
	hybridPrivateKey []byte,
	signer sdk.AccAddress,
	recipient sdk.AccAddress,
	accountNumber uint64,
	gasLimit uint64,
	sequence uint64,
	config fixtureConfig,
	networkID []byte,
	txConfig sdkclient.TxConfig,
) []byte {
	builder := txConfig.NewTxBuilder()
	message := banktypes.NewMsgSend(signer, recipient, sdk.NewCoins(sdk.NewInt64Coin(config.Denom, config.Transfer)))
	if err := builder.SetMsgs(message); err != nil {
		fatalf("set %s message: %v", mode, err)
	}
	builder.SetGasLimit(gasLimit)
	builder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(config.Denom, config.Fee)))
	placeholder := txsigning.SignatureV2{
		PubKey:   privateKey.PubKey(),
		Data:     &txsigning.SingleSignatureData{SignMode: txsigning.SignMode_SIGN_MODE_DIRECT},
		Sequence: sequence,
	}
	if err := builder.SetSignatures(placeholder); err != nil {
		fatalf("set %s placeholder signature: %v", mode, err)
	}

	usesHybrid := mode == "hybrid" || mode == "invalid-pqc" || mode == "oversized" || mode == "noncanonical"
	if usesHybrid {
		provider, ok := builder.GetTx().(protoTxProvider)
		if !ok || provider.GetProtoTx() == nil {
			fatalf("hybrid transaction builder does not expose protobuf transaction")
		}
		doc, err := pqctypes.NewPQCSignDocV1(
			provider.GetProtoTx(), networkID, config.ChainID, accountNumber, sequence, 0,
			signer.String(), 1, pqctypes.Algorithm_ALGORITHM_ML_DSA_65, 1,
		)
		if err != nil {
			fatalf("build hybrid sign document: %v", err)
		}
		signBytes, err := pqctypes.MarshalPQCSignDocV1(doc)
		if err != nil {
			fatalf("marshal hybrid sign document: %v", err)
		}
		pqcSignature, err := pqccrypto.SignMLDSA65(
			hybridPrivateKey, signBytes, []byte(pqctypes.TxSignatureContext), false,
		)
		if err != nil {
			fatalf("sign hybrid transaction: %v", err)
		}
		if mode == "invalid-pqc" {
			pqcSignature[0] ^= 0x01
		}
		entryCount := 1
		if mode == "oversized" {
			// 32 ML-DSA-65 entries exceed the protocol extension-byte cap.
			// The extension remains canonical so the structure size check is
			// exercised before semantic signer validation.
			entryCount = 32
		}
		entries := make([]pqctypes.SignerPQCSignature, 0, entryCount)
		for index := 0; index < entryCount; index++ {
			entries = append(entries, pqctypes.SignerPQCSignature{
				Signer: signer.String(), SignerIndex: uint32(index), KeyId: 1,
				Algorithm:     pqctypes.Algorithm_ALGORITHM_ML_DSA_65,
				PolicyVersion: 1, Signature: pqcSignature,
			})
		}
		extension, err := codectypes.NewAnyWithValue(&pqctypes.ExtensionPQCAuth{
			FormatVersion: pqctypes.FormatVersionV1,
			Signatures:    entries,
		})
		if err != nil {
			fatalf("encode hybrid extension: %v", err)
		}
		extended, ok := builder.(extensionOptionsBuilder)
		if !ok {
			fatalf("transaction builder does not support critical extension options")
		}
		extended.SetExtensionOptions(extension)
	}

	signerData := authsigning.SignerData{
		ChainID: config.ChainID, AccountNumber: accountNumber, Sequence: sequence,
		PubKey: privateKey.PubKey(), Address: signer.String(),
	}
	signBytes, err := authsigning.GetSignBytesAdapter(
		context.Background(), txConfig.SignModeHandler(), txsigning.SignMode_SIGN_MODE_DIRECT,
		signerData, builder.GetTx(),
	)
	if err != nil {
		fatalf("build %s direct sign bytes: %v", mode, err)
	}
	signature, err := privateKey.Sign(signBytes)
	if err != nil {
		fatalf("sign %s transaction: %v", mode, err)
	}
	finalSignature := txsigning.SignatureV2{
		PubKey: privateKey.PubKey(),
		Data: &txsigning.SingleSignatureData{
			SignMode: txsigning.SignMode_SIGN_MODE_DIRECT, Signature: signature,
		},
		Sequence: sequence,
	}
	if err := builder.SetSignatures(finalSignature); err != nil {
		fatalf("set %s final signature: %v", mode, err)
	}
	raw, err := txConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		fatalf("encode %s transaction: %v", mode, err)
	}
	if mode == "noncanonical" {
		// Append a duplicate format_version field to the embedded extension.
		// Protobuf accepts it, but deterministic re-marshalling removes the
		// duplicate, so CanonicalPQCAuthTxDecoder must reject the wire bytes.
		var txRaw txtypes.TxRaw
		if err := txRaw.Unmarshal(raw); err != nil {
			fatalf("decode noncanonical raw transaction: %v", err)
		}
		var body txtypes.TxBody
		if err := body.Unmarshal(txRaw.BodyBytes); err != nil {
			fatalf("decode noncanonical body: %v", err)
		}
		if len(body.ExtensionOptions) == 0 {
			fatalf("noncanonical transaction has no extension")
		}
		option := body.ExtensionOptions[len(body.ExtensionOptions)-1]
		option.Value = append(option.Value, 0x08, byte(pqctypes.FormatVersionV1))
		bodyBytes, err := body.Marshal()
		if err != nil {
			fatalf("marshal noncanonical body: %v", err)
		}
		txRaw.BodyBytes = bodyBytes
		raw, err = txRaw.Marshal()
		if err != nil {
			fatalf("marshal noncanonical raw transaction: %v", err)
		}
	}
	return raw
}

func deriveSeed(seed, role string, index int) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", seed, role, index)))
	return sum[:]
}

func deriveMLDSA65(seed, role string, index int) mldsa65.PrivKey {
	key, err := mldsa65.GenPrivKeyFromSeed(deriveSeed(seed, role, index))
	if err != nil {
		fatalf("derive ML-DSA-65 %s key %d: %v", role, index, err)
	}
	return key
}

func closeWriters(writers map[string]*modeWriter) {
	for mode, writer := range writers {
		if writer.file == nil {
			continue
		}
		if err := writer.buffer.Flush(); err != nil {
			fatalf("flush %s transactions: %v", mode, err)
		}
		if err := writer.file.Close(); err != nil {
			fatalf("close %s transactions: %v", mode, err)
		}
		writer.file = nil
	}
}

func writeJSON(path string, value any, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func configureSDK() {
	configureSDKOnce.Do(func() {
		config := sdk.GetConfig()
		config.SetBech32PrefixForAccount(app.AccountAddressPrefix, app.AccountAddressPrefix+"pub")
		config.SetBech32PrefixForValidator(app.AccountAddressPrefix+"valoper", app.AccountAddressPrefix+"valoperpub")
		config.SetBech32PrefixForConsensusNode(app.AccountAddressPrefix+"valcons", app.AccountAddressPrefix+"valconspub")
		config.Seal()
	})
}

func fatalf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "pqcload: "+format+"\n", arguments...)
	os.Exit(1)
}
