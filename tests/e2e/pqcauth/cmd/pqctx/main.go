// pqctx is a test-only adversarial transaction factory.
//
// It starts from a valid offline PQC sign bundle, deliberately mutates the
// consensus extension, and then creates a valid classical signature over the
// mutated body. This lets real-node E2E tests reach the PQC Ante checks instead
// of being rejected earlier by classical signature verification.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"

	"github.com/DoraFactory/doravota/app"
	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const maxInputBytes = pqcauthclient.MaxPQCSignBundleBytes

type extensionOptionsBuilder interface {
	sdkclient.TxBuilder
	SetExtensionOptions(...*codectypes.Any)
	SetNonCriticalExtensionOptions(...*codectypes.Any)
}

func main() {
	var bundlePath string
	var variant string
	var from string
	var keyringHome string
	var outputPath string
	flag.StringVar(&bundlePath, "bundle", "", "valid signed PQC bundle")
	flag.StringVar(&variant, "variant", "", "adversarial mutation variant")
	flag.StringVar(&from, "from", "", "classical key name")
	flag.StringVar(&keyringHome, "keyring-home", "", "test keyring home")
	flag.StringVar(&outputPath, "output", "", "new signed transaction as base64 protobuf")
	flag.Parse()
	if bundlePath == "" || variant == "" || from == "" || keyringHome == "" || outputPath == "" {
		fail("--bundle, --variant, --from, --keyring-home and --output are required")
	}

	configureSDK()
	encoding := app.MakeEncodingConfig()
	bundleBytes, err := readBounded(bundlePath, maxInputBytes)
	if err != nil {
		fail("read signed bundle: %v", err)
	}
	bundle, summary, err := pqcauthclient.UnmarshalPQCSignBundle(
		encoding.TxConfig,
		bundleBytes,
		true,
	)
	if err != nil {
		fail("validate signed bundle: %v", err)
	}
	decoded, err := encoding.TxConfig.TxDecoder()(bundle.UnsignedTx)
	if err != nil {
		fail("decode bundled transaction: %v", err)
	}
	builder, err := encoding.TxConfig.WrapTxBuilder(decoded)
	if err != nil {
		fail("wrap bundled transaction: %v", err)
	}
	extended, ok := builder.(extensionOptionsBuilder)
	if !ok {
		fail("transaction builder does not support extension options")
	}

	entry := types.SignerPQCSignature{
		Signer:        summary.Signer,
		SignerIndex:   0,
		KeyId:         summary.KeyID,
		Algorithm:     summary.Algorithm,
		PolicyVersion: summary.PolicyVersion,
		Signature:     append([]byte(nil), bundle.Signature...),
	}
	extension := &types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures:    []types.SignerPQCSignature{entry},
	}
	applyEntryMutation(variant, extension)
	extensionAny, err := codectypes.NewAnyWithValue(extension)
	if err != nil {
		fail("encode PQC extension: %v", err)
	}

	switch variant {
	case "noncritical":
		extended.SetExtensionOptions()
		extended.SetNonCriticalExtensionOptions(extensionAny)
	case "not-last":
		extended.SetExtensionOptions(extensionAny, cloneAny(extensionAny))
	case "noncanonical":
		extensionAny.Value = append(extensionAny.Value, 0x08, 0x01)
		extended.SetExtensionOptions(extensionAny)
	case "oversized":
		extended.SetExtensionOptions(extensionAny)
	default:
		extended.SetExtensionOptions(extensionAny)
	}

	keybase, err := keyring.New(
		sdk.KeyringServiceName(),
		keyring.BackendTest,
		keyringHome,
		nil,
		encoding.Marshaler,
	)
	if err != nil {
		fail("open classical test keyring: %v", err)
	}
	info, err := keybase.Key(from)
	if err != nil {
		fail("load classical key %q: %v", from, err)
	}
	publicKey, err := info.GetPubKey()
	if err != nil {
		fail("load classical public key: %v", err)
	}
	if signer := sdk.AccAddress(publicKey.Address()).String(); signer != summary.Signer {
		fail("classical key signer %s does not match bundle signer %s", signer, summary.Signer)
	}

	txf := sdktx.Factory{}.
		WithTxConfig(encoding.TxConfig).
		WithKeybase(keybase).
		WithChainID(summary.ChainID).
		WithAccountNumber(summary.AccountNumber).
		WithSequence(summary.Sequence).
		WithSignMode(txsigning.SignMode_SIGN_MODE_DIRECT)
	if err := sdktx.Sign(context.Background(), txf, from, builder, true); err != nil {
		fail("classically sign adversarial transaction: %v", err)
	}
	encoded, err := encoding.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		fail("encode adversarial transaction: %v", err)
	}
	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail("create output without overwrite: %v", err)
	}
	if _, err := file.Write(append([]byte(encodedBase64), '\n')); err != nil {
		_ = file.Close()
		fail("write output: %v", err)
	}
	if err := file.Close(); err != nil {
		fail("close output: %v", err)
	}
}

func applyEntryMutation(variant string, extension *types.ExtensionPQCAuth) {
	entry := &extension.Signatures[0]
	switch variant {
	case "invalid-signature":
		if len(entry.Signature) == 0 {
			fail("valid bundle has an empty signature")
		}
		entry.Signature[0] ^= 0x01
	case "wrong-signer":
		entry.Signer = sdk.AccAddress(make([]byte, 20)).String()
	case "wrong-key":
		entry.KeyId++
	case "wrong-policy":
		entry.PolicyVersion++
	case "out-of-range-signer":
		entry.SignerIndex = 1
	case "unknown-algorithm":
		entry.Algorithm = types.Algorithm(99)
	case "short-signature":
		entry.Signature = []byte{1}
	case "empty-entries":
		extension.Signatures = nil
	case "oversized":
		template := *entry
		for extension.Size() <= int(types.DefaultMaxPQCAuthBytes) {
			extension.Signatures = append(extension.Signatures, template)
		}
	case "valid", "noncritical", "not-last", "noncanonical":
		// The mutation is applied to the encoded Any or its placement.
	default:
		fail("unsupported variant %q", variant)
	}
}

func cloneAny(value *codectypes.Any) *codectypes.Any {
	return &codectypes.Any{
		TypeUrl: value.TypeUrl,
		Value:   append([]byte(nil), value.Value...),
	}
}

func configureSDK() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(app.AccountAddressPrefix, app.AccountAddressPrefix+"pub")
	config.SetBech32PrefixForValidator(app.AccountAddressPrefix+"valoper", app.AccountAddressPrefix+"valoperpub")
	config.SetBech32PrefixForConsensusNode(app.AccountAddressPrefix+"valcons", app.AccountAddressPrefix+"valconspub")
	config.Seal()
}

func readBounded(path string, max int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(max) {
		return nil, fmt.Errorf("input must be a regular file between 1 and %d bytes", max)
	}
	return os.ReadFile(path)
}

func fail(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "pqctx: "+format+"\n", args...)
	os.Exit(1)
}
