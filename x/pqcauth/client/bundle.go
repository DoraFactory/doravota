package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	// PQCSignBundleFormatV1 identifies the JSON transport envelope. Consensus
	// verification continues to use the protobuf PQCSignDocV1 contained within.
	PQCSignBundleFormatV1 = "doravota.pqcauth/sign-bundle/v1"

	MaxPQCSignBundleBytes  = 32 << 20
	MaxUnsignedTxJSONBytes = 32 << 20
	maxUnsignedTxBytes     = 16 << 20
	maxPQCSignDocBytes     = 16 << 20
)

// PQCSignBundleV1 is a transport-only envelope for taking one unsigned,
// single-signer transaction across an offline ML-DSA signing boundary.
//
// []byte fields use standard base64 when encoded as JSON. The two hashes are
// redundant by design: they make accidental or malicious substitution visible
// before a signature is produced.
type PQCSignBundleV1 struct {
	Format           string `json:"format"`
	UnsignedTx       []byte `json:"unsigned_tx_base64"`
	UnsignedTxSHA256 []byte `json:"unsigned_tx_sha256_base64"`
	SignDoc          []byte `json:"sign_doc_base64"`
	SignDocSHA256    []byte `json:"sign_doc_sha256_base64"`
	OnChainPublicKey []byte `json:"on_chain_public_key_base64"`
	Signature        []byte `json:"signature_base64,omitempty"`
}

// PQCSignBundleSummary contains the fields an offline operator should review.
type PQCSignBundleSummary struct {
	ChainID       string
	NetworkID     []byte
	Signer        string
	AccountNumber uint64
	Sequence      uint64
	KeyID         uint64
	Algorithm     types.Algorithm
	PolicyVersion uint64
	TxSHA256      []byte
	SignDocSHA256 []byte
	Signed        bool
}

// DecodeUnsignedTxJSONForPQCBundle accepts the standard Cosmos SDK
// --generate-only JSON form and rejects inputs that are already signed or
// already carry a PQC extension.
func DecodeUnsignedTxJSONForPQCBundle(
	txConfig sdkclient.TxConfig,
	encoded []byte,
) (sdkclient.TxBuilder, error) {
	if txConfig == nil {
		return nil, fmt.Errorf("transaction config is required")
	}
	if len(encoded) == 0 || len(encoded) > MaxUnsignedTxJSONBytes {
		return nil, fmt.Errorf(
			"unsigned transaction JSON length must be between 1 and %d bytes",
			MaxUnsignedTxJSONBytes,
		)
	}
	decodedTx, err := txConfig.TxJSONDecoder()(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode unsigned transaction JSON: %w", err)
	}
	if len(decodedTx.GetMsgs()) == 0 {
		return nil, fmt.Errorf("unsigned transaction must contain at least one message")
	}
	for _, message := range decodedTx.GetMsgs() {
		validator, ok := message.(sdk.HasValidateBasic)
		if ok {
			if err := validator.ValidateBasic(); err != nil {
				return nil, fmt.Errorf("unsigned transaction message failed basic validation: %w", err)
			}
		}
	}
	provider, ok := decodedTx.(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return nil, fmt.Errorf("protobuf transaction is required")
	}
	protoTx := provider.GetProtoTx()
	if protoTx.AuthInfo == nil || protoTx.Body == nil {
		return nil, fmt.Errorf("unsigned transaction body or auth info is missing")
	}
	if len(protoTx.AuthInfo.SignerInfos) != 0 || len(protoTx.Signatures) != 0 {
		return nil, fmt.Errorf("input transaction must not contain signer info or classical signatures")
	}
	_, removed, err := types.CanonicalBodyBytesWithoutPQCAuth(protoTx)
	if err != nil {
		return nil, err
	}
	if removed != 0 {
		return nil, fmt.Errorf("input transaction must not already contain PQC authorization")
	}
	builder, err := txConfig.WrapTxBuilder(decodedTx)
	if err != nil {
		return nil, fmt.Errorf("wrap unsigned transaction JSON: %w", err)
	}
	return builder, nil
}

// MarshalPQCSignBundle encodes a validated bundle as stable, indented JSON.
func MarshalPQCSignBundle(
	txConfig sdkclient.TxConfig,
	bundle *PQCSignBundleV1,
	requireSignature bool,
) ([]byte, error) {
	if _, err := ValidatePQCSignBundle(txConfig, bundle, requireSignature); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode PQC sign bundle: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxPQCSignBundleBytes {
		return nil, fmt.Errorf("PQC sign bundle exceeds %d bytes", MaxPQCSignBundleBytes)
	}
	return encoded, nil
}

// UnmarshalPQCSignBundle strictly decodes and validates a JSON bundle.
func UnmarshalPQCSignBundle(
	txConfig sdkclient.TxConfig,
	encoded []byte,
	requireSignature bool,
) (*PQCSignBundleV1, PQCSignBundleSummary, error) {
	if len(encoded) == 0 || len(encoded) > MaxPQCSignBundleBytes {
		return nil, PQCSignBundleSummary{}, fmt.Errorf(
			"PQC sign bundle length must be between 1 and %d bytes",
			MaxPQCSignBundleBytes,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle PQCSignBundleV1
	if err := decoder.Decode(&bundle); err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("decode PQC sign bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, PQCSignBundleSummary{}, fmt.Errorf("decode PQC sign bundle: multiple JSON values")
		}
		return nil, PQCSignBundleSummary{}, fmt.Errorf("decode PQC sign bundle: %w", err)
	}
	summary, err := ValidatePQCSignBundle(txConfig, &bundle, requireSignature)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	return &bundle, summary, nil
}

// PreparePQCSignBundle freezes the unsigned transaction and the effective
// on-chain key/policy into a bundle. No PQC private key is needed online.
func PreparePQCSignBundle(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
) (*PQCSignBundleV1, PQCSignBundleSummary, error) {
	prepared, err := preparePQCSignDoc(ctx, clientCtx, txf, builder)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	unsignedTx, err := clientCtx.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("encode unsigned transaction: %w", err)
	}
	txHash := sha256.Sum256(unsignedTx)
	signDocHash := sha256.Sum256(prepared.signBytes)
	bundle := &PQCSignBundleV1{
		Format:           PQCSignBundleFormatV1,
		UnsignedTx:       unsignedTx,
		UnsignedTxSHA256: append([]byte(nil), txHash[:]...),
		SignDoc:          append([]byte(nil), prepared.signBytes...),
		SignDocSHA256:    append([]byte(nil), signDocHash[:]...),
		OnChainPublicKey: append([]byte(nil), prepared.key.PublicKey...),
	}
	summary, err := ValidatePQCSignBundle(clientCtx.TxConfig, bundle, false)
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("validate prepared PQC sign bundle: %w", err)
	}
	return bundle, summary, nil
}

// SignPQCSignBundle validates every offline-verifiable field, confirms that the
// signer owns the on-chain public key carried by the bundle, and returns a
// signed copy. The input bundle is never mutated.
func SignPQCSignBundle(
	ctx context.Context,
	txConfig sdkclient.TxConfig,
	bundle *PQCSignBundleV1,
	signerBackend PQCSigner,
) (*PQCSignBundleV1, PQCSignBundleSummary, error) {
	if signerBackend == nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("PQC signer is required")
	}
	if len(bundle.GetSignature()) != 0 {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("PQC sign bundle is already signed")
	}
	summary, err := ValidatePQCSignBundle(txConfig, bundle, false)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	if signerBackend.Algorithm() != summary.Algorithm {
		return nil, PQCSignBundleSummary{}, fmt.Errorf(
			"PQC signer algorithm %d does not match bundle algorithm %d",
			signerBackend.Algorithm(),
			summary.Algorithm,
		)
	}
	publicKey, err := signerBackend.PublicKey(ctx)
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("load PQC signer public key: %w", err)
	}
	if !constantTimeBytesEqual(publicKey, bundle.OnChainPublicKey) {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("PQC signer does not match bundle on-chain public key")
	}
	signature, err := signerBackend.Sign(ctx, bundle.SignDoc, []byte(types.TxSignatureContext))
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("sign PQC bundle: %w", err)
	}
	algorithm, err := types.CryptoAlgorithm(summary.Algorithm)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	if err := pqccrypto.Verify(
		algorithm,
		bundle.OnChainPublicKey,
		bundle.SignDoc,
		[]byte(types.TxSignatureContext),
		signature,
	); err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("PQC signer returned an invalid signature: %w", err)
	}
	signed := clonePQCSignBundle(bundle)
	signed.Signature = append([]byte(nil), signature...)
	summary, err = ValidatePQCSignBundle(txConfig, signed, true)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	return signed, summary, nil
}

// SignPQCSignBundleWithPrivateKey is the local-file convenience wrapper for
// SignPQCSignBundle. Callers remain responsible for clearing privateKey.
func SignPQCSignBundleWithPrivateKey(
	ctx context.Context,
	txConfig sdkclient.TxConfig,
	bundle *PQCSignBundleV1,
	privateKey []byte,
) (*PQCSignBundleV1, PQCSignBundleSummary, error) {
	return SignPQCSignBundle(
		ctx,
		txConfig,
		bundle,
		localMLDSA65Signer{privateKey: privateKey},
	)
}

// AttachPQCSignBundle re-queries the latest account state and attaches a
// previously offline-produced signature only when the transaction, account,
// sequence, key, policy, network, and signature still match.
func AttachPQCSignBundle(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	bundle *PQCSignBundleV1,
) (sdkclient.TxBuilder, PQCSignBundleSummary, error) {
	summary, err := ValidatePQCSignBundle(clientCtx.TxConfig, bundle, true)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	decodedTx, err := clientCtx.TxConfig.TxDecoder()(bundle.UnsignedTx)
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("decode bundled unsigned transaction: %w", err)
	}
	builder, err := clientCtx.TxConfig.WrapTxBuilder(decodedTx)
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("wrap bundled unsigned transaction: %w", err)
	}
	prepared, err := preparePQCSignDoc(ctx, clientCtx, txf, builder)
	if err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	if !bytes.Equal(prepared.signBytes, bundle.SignDoc) {
		return nil, PQCSignBundleSummary{}, fmt.Errorf(
			"PQC bundle is stale: current chain key, policy, account, sequence, or network changed",
		)
	}
	if !constantTimeBytesEqual(prepared.key.PublicKey, bundle.OnChainPublicKey) {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("PQC bundle is stale: active on-chain public key changed")
	}
	reencoded, err := clientCtx.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("re-encode bundled unsigned transaction: %w", err)
	}
	if !bytes.Equal(reencoded, bundle.UnsignedTx) {
		return nil, PQCSignBundleSummary{}, fmt.Errorf("bundled unsigned transaction changed during online revalidation")
	}
	if err := verifyPQCSignature(
		prepared.key.Algorithm,
		prepared.key.PublicKey,
		prepared.signBytes,
		bundle.Signature,
	); err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	if err := attachPQCSignature(builder, prepared, bundle.Signature); err != nil {
		return nil, PQCSignBundleSummary{}, err
	}
	return builder, summary, nil
}

// ValidatePQCSignBundle performs all checks that do not require a live chain.
func ValidatePQCSignBundle(
	txConfig sdkclient.TxConfig,
	bundle *PQCSignBundleV1,
	requireSignature bool,
) (PQCSignBundleSummary, error) {
	if txConfig == nil {
		return PQCSignBundleSummary{}, fmt.Errorf("transaction config is required")
	}
	if bundle == nil {
		return PQCSignBundleSummary{}, fmt.Errorf("PQC sign bundle is required")
	}
	if bundle.Format != PQCSignBundleFormatV1 {
		return PQCSignBundleSummary{}, fmt.Errorf("unsupported PQC sign bundle format %q", bundle.Format)
	}
	if len(bundle.UnsignedTx) == 0 || len(bundle.UnsignedTx) > maxUnsignedTxBytes {
		return PQCSignBundleSummary{}, fmt.Errorf(
			"bundled unsigned transaction length must be between 1 and %d bytes",
			maxUnsignedTxBytes,
		)
	}
	if len(bundle.SignDoc) == 0 || len(bundle.SignDoc) > maxPQCSignDocBytes {
		return PQCSignBundleSummary{}, fmt.Errorf(
			"bundled sign document length must be between 1 and %d bytes",
			maxPQCSignDocBytes,
		)
	}
	txHash := sha256.Sum256(bundle.UnsignedTx)
	if !constantTimeBytesEqual(bundle.UnsignedTxSHA256, txHash[:]) {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled unsigned transaction SHA-256 mismatch")
	}
	signDocHash := sha256.Sum256(bundle.SignDoc)
	if !constantTimeBytesEqual(bundle.SignDocSHA256, signDocHash[:]) {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled sign document SHA-256 mismatch")
	}

	var signDoc types.PQCSignDocV1
	if err := signDoc.Unmarshal(bundle.SignDoc); err != nil {
		return PQCSignBundleSummary{}, fmt.Errorf("decode bundled PQC sign document: %w", err)
	}
	canonicalSignDoc, err := types.MarshalPQCSignDocV1(signDoc)
	if err != nil {
		return PQCSignBundleSummary{}, err
	}
	if !bytes.Equal(canonicalSignDoc, bundle.SignDoc) {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled PQC sign document is not canonical")
	}
	if signDoc.SignerIndex != 0 {
		return PQCSignBundleSummary{}, fmt.Errorf("only signer index 0 is supported by PQC sign bundles")
	}
	signer, err := sdk.AccAddressFromBech32(signDoc.Signer)
	if err != nil || signer.String() != signDoc.Signer {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled signer address is invalid")
	}

	decodedTx, err := txConfig.TxDecoder()(bundle.UnsignedTx)
	if err != nil {
		return PQCSignBundleSummary{}, fmt.Errorf("decode bundled unsigned transaction: %w", err)
	}
	reencoded, err := txConfig.TxEncoder()(decodedTx)
	if err != nil {
		return PQCSignBundleSummary{}, fmt.Errorf("re-encode bundled unsigned transaction: %w", err)
	}
	if !bytes.Equal(reencoded, bundle.UnsignedTx) {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled unsigned transaction is not canonical")
	}
	provider, ok := decodedTx.(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return PQCSignBundleSummary{}, fmt.Errorf("protobuf transaction is required")
	}
	if validator, ok := decodedTx.(sdk.HasValidateBasic); ok {
		if err := validator.ValidateBasic(); err != nil {
			return PQCSignBundleSummary{}, fmt.Errorf("bundled unsigned transaction failed basic validation: %w", err)
		}
	}
	protoTx := provider.GetProtoTx()
	if err := validateUnsignedSingleSignerTx(protoTx, decodedTx, signer, signDoc.Sequence); err != nil {
		return PQCSignBundleSummary{}, err
	}
	reconstructed, err := types.NewPQCSignDocV1(
		protoTx,
		signDoc.NetworkId,
		signDoc.ChainId,
		signDoc.AccountNumber,
		signDoc.Sequence,
		signDoc.SignerIndex,
		signDoc.Signer,
		signDoc.KeyId,
		signDoc.Algorithm,
		signDoc.PolicyVersion,
	)
	if err != nil {
		return PQCSignBundleSummary{}, err
	}
	reconstructedBytes, err := types.MarshalPQCSignDocV1(reconstructed)
	if err != nil {
		return PQCSignBundleSummary{}, err
	}
	if !bytes.Equal(reconstructedBytes, bundle.SignDoc) {
		return PQCSignBundleSummary{}, fmt.Errorf("bundled sign document does not match bundled unsigned transaction")
	}

	algorithm, err := types.CryptoAlgorithm(signDoc.Algorithm)
	if err != nil {
		return PQCSignBundleSummary{}, err
	}
	publicKeySize, signatureSize, err := pqccrypto.Sizes(algorithm)
	if err != nil {
		return PQCSignBundleSummary{}, err
	}
	if len(bundle.OnChainPublicKey) != publicKeySize {
		return PQCSignBundleSummary{}, fmt.Errorf(
			"bundled on-chain public key length %d, want %d",
			len(bundle.OnChainPublicKey),
			publicKeySize,
		)
	}
	if requireSignature && len(bundle.Signature) == 0 {
		return PQCSignBundleSummary{}, fmt.Errorf("PQC sign bundle has no signature")
	}
	if len(bundle.Signature) != 0 {
		if len(bundle.Signature) != signatureSize {
			return PQCSignBundleSummary{}, fmt.Errorf(
				"bundled PQC signature length %d, want %d",
				len(bundle.Signature),
				signatureSize,
			)
		}
		if err := verifyPQCSignature(
			signDoc.Algorithm,
			bundle.OnChainPublicKey,
			bundle.SignDoc,
			bundle.Signature,
		); err != nil {
			return PQCSignBundleSummary{}, err
		}
	}

	return PQCSignBundleSummary{
		ChainID:       signDoc.ChainId,
		NetworkID:     append([]byte(nil), signDoc.NetworkId...),
		Signer:        signDoc.Signer,
		AccountNumber: signDoc.AccountNumber,
		Sequence:      signDoc.Sequence,
		KeyID:         signDoc.KeyId,
		Algorithm:     signDoc.Algorithm,
		PolicyVersion: signDoc.PolicyVersion,
		TxSHA256:      append([]byte(nil), txHash[:]...),
		SignDocSHA256: append([]byte(nil), signDocHash[:]...),
		Signed:        len(bundle.Signature) != 0,
	}, nil
}

func validateUnsignedSingleSignerTx(
	protoTx *txtypes.Tx,
	decodedTx sdk.Tx,
	expectedSigner sdk.AccAddress,
	expectedSequence uint64,
) error {
	if protoTx.Body == nil || protoTx.AuthInfo == nil {
		return fmt.Errorf("bundled unsigned transaction body or auth info is missing")
	}
	_, removed, err := types.CanonicalBodyBytesWithoutPQCAuth(protoTx)
	if err != nil {
		return err
	}
	if removed != 0 {
		return fmt.Errorf("bundled unsigned transaction must not already contain PQC authorization")
	}
	if len(protoTx.AuthInfo.SignerInfos) != 1 {
		return fmt.Errorf("PQC sign bundles require exactly one signer info")
	}
	signerInfo := protoTx.AuthInfo.SignerInfos[0]
	if signerInfo == nil || signerInfo.ModeInfo == nil ||
		signerInfo.ModeInfo.GetSingle() == nil ||
		signerInfo.ModeInfo.GetSingle().Mode != txsigning.SignMode_SIGN_MODE_DIRECT {
		return types.ErrUnsupportedSignMode
	}
	if signerInfo.Sequence != expectedSequence {
		return fmt.Errorf("bundled signer sequence does not match sign document")
	}
	if len(protoTx.Signatures) != 1 || len(protoTx.Signatures[0]) != 0 {
		return fmt.Errorf("bundled transaction must contain exactly one empty classical signature")
	}
	signatureTx, ok := decodedTx.(authsigning.SigVerifiableTx)
	if !ok {
		return fmt.Errorf("bundled transaction does not expose signers")
	}
	rawSigners, err := signatureTx.GetSigners()
	if err != nil {
		return fmt.Errorf("extract bundled transaction signers: %w", err)
	}
	signers := make([]sdk.AccAddress, len(rawSigners))
	for index := range rawSigners {
		signers[index] = sdk.AccAddress(rawSigners[index])
	}
	if len(signers) != 1 || !signers[0].Equals(expectedSigner) {
		return fmt.Errorf("bundled transaction signer does not match sign document")
	}
	return nil
}

func verifyPQCSignature(
	algorithmType types.Algorithm,
	publicKey []byte,
	signBytes []byte,
	signature []byte,
) error {
	algorithm, err := types.CryptoAlgorithm(algorithmType)
	if err != nil {
		return err
	}
	if err := pqccrypto.Verify(
		algorithm,
		publicKey,
		signBytes,
		[]byte(types.TxSignatureContext),
		signature,
	); err != nil {
		return fmt.Errorf("invalid bundled PQC signature: %w", err)
	}
	return nil
}

func constantTimeBytesEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func clonePQCSignBundle(bundle *PQCSignBundleV1) *PQCSignBundleV1 {
	if bundle == nil {
		return nil
	}
	return &PQCSignBundleV1{
		Format:           bundle.Format,
		UnsignedTx:       append([]byte(nil), bundle.UnsignedTx...),
		UnsignedTxSHA256: append([]byte(nil), bundle.UnsignedTxSHA256...),
		SignDoc:          append([]byte(nil), bundle.SignDoc...),
		SignDocSHA256:    append([]byte(nil), bundle.SignDocSHA256...),
		OnChainPublicKey: append([]byte(nil), bundle.OnChainPublicKey...),
		Signature:        append([]byte(nil), bundle.Signature...),
	}
}

func (b *PQCSignBundleV1) GetSignature() []byte {
	if b == nil {
		return nil
	}
	return b.Signature
}
