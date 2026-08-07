package client

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	RecoverySignBundleFormatV1 = "doravota.pqcauth/recovery-sign-bundle/v1"
	MaxRecoverySignBundleBytes = 32 << 20
)

// RecoverySignBundleV1 freezes the complete unsigned recovery transaction and
// the transaction-bound recovery sign document for transport to an offline
// recovery signer.
type RecoverySignBundleV1 struct {
	Format                   string          `json:"format"`
	UnsignedTx               []byte          `json:"unsigned_tx_base64"`
	UnsignedTxSHA256         []byte          `json:"unsigned_tx_sha256_base64"`
	SignDoc                  []byte          `json:"sign_doc_base64"`
	SignDocSHA256            []byte          `json:"sign_doc_sha256_base64"`
	RecoveryAlgorithm        types.Algorithm `json:"recovery_algorithm"`
	OnChainRecoveryPublicKey []byte          `json:"on_chain_recovery_public_key_base64"`
	RecoverySignature        []byte          `json:"recovery_signature_base64,omitempty"`
}

type RecoverySignBundleSummary struct {
	ChainID              string
	NetworkID            []byte
	Owner                string
	AccountNumber        uint64
	Sequence             uint64
	RecoveryKeyID        uint64
	ProposedSigningKeyID uint64
	RecoveryAlgorithm    types.Algorithm
	ProposedAlgorithm    types.Algorithm
	PolicyVersion        uint64
	TxSHA256             []byte
	SignDocSHA256        []byte
	Signed               bool
}

// PrepareRecoverySignBundle freezes an unsigned, single-signer MsgRecoverKey
// transaction whose recovery_signature contains a correctly sized all-zero
// placeholder. It queries and binds the effective recovery policy and key.
func PrepareRecoverySignBundle(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
) (*RecoverySignBundleV1, RecoverySignBundleSummary, error) {
	signer, err := prepareSingleDirectSigner(clientCtx, txf, builder)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	message, err := recoveryMessageFromTx(builder.GetTx())
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if message.Owner != signer.String() {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("recovery owner does not match classical signer")
	}

	policy, recoveryKey, params, err := queryRecoveryState(
		ctx,
		clientCtx,
		message.Owner,
		message.RecoveryKeyId,
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if err := validateRecoveryPlaceholder(message, recoveryKey.Algorithm); err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}

	provider, ok := builder.GetTx().(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("protobuf transaction builder is required")
	}
	signDoc, err := types.NewRecoverySignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		txf.ChainID(),
		txf.AccountNumber(),
		txf.Sequence(),
		0,
		signer.String(),
		message.Owner,
		message.RecoveryKeyId,
		message.ExpectedNewSigningKeyId,
		message.NewSigningAlgorithm,
		message.NewSigningPublicKey,
		policy.PolicyVersion,
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	signBytes, err := types.MarshalRecoverySignDocV1(signDoc)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	unsignedTx, err := clientCtx.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("encode unsigned recovery transaction: %w", err)
	}
	txHash := sha256.Sum256(unsignedTx)
	signDocHash := sha256.Sum256(signBytes)
	bundle := &RecoverySignBundleV1{
		Format:                   RecoverySignBundleFormatV1,
		UnsignedTx:               unsignedTx,
		UnsignedTxSHA256:         append([]byte(nil), txHash[:]...),
		SignDoc:                  signBytes,
		SignDocSHA256:            append([]byte(nil), signDocHash[:]...),
		RecoveryAlgorithm:        recoveryKey.Algorithm,
		OnChainRecoveryPublicKey: append([]byte(nil), recoveryKey.PublicKey...),
	}
	summary, err := ValidateRecoverySignBundle(clientCtx.TxConfig, bundle, false)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("validate prepared recovery bundle: %w", err)
	}
	return bundle, summary, nil
}

func SignRecoverySignBundle(
	ctx context.Context,
	txConfig sdkclient.TxConfig,
	bundle *RecoverySignBundleV1,
	signerBackend PQCSigner,
) (*RecoverySignBundleV1, RecoverySignBundleSummary, error) {
	if signerBackend == nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("recovery signer is required")
	}
	if bundle == nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("recovery sign bundle is required")
	}
	if len(bundle.RecoverySignature) != 0 {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("recovery sign bundle is already signed")
	}
	summary, err := ValidateRecoverySignBundle(txConfig, bundle, false)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if signerBackend.Algorithm() != bundle.RecoveryAlgorithm {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery signer algorithm %d does not match bundle algorithm %d",
			signerBackend.Algorithm(),
			bundle.RecoveryAlgorithm,
		)
	}
	publicKey, err := signerBackend.PublicKey(ctx)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("load recovery signer public key: %w", err)
	}
	if !constantTimeBytesEqual(publicKey, bundle.OnChainRecoveryPublicKey) {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery signer does not match on-chain recovery key",
		)
	}
	signature, err := signerBackend.Sign(
		ctx,
		bundle.SignDoc,
		[]byte(types.RecoverySignatureContext),
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("sign recovery bundle: %w", err)
	}
	if err := verifyRecoveryBundleSignature(bundle, signature); err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery signer returned an invalid signature: %w",
			err,
		)
	}
	signed := cloneRecoverySignBundle(bundle)
	signed.RecoverySignature = append([]byte(nil), signature...)
	summary, err = ValidateRecoverySignBundle(txConfig, signed, true)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	return signed, summary, nil
}

func SignRecoverySignBundleWithPrivateKey(
	ctx context.Context,
	txConfig sdkclient.TxConfig,
	bundle *RecoverySignBundleV1,
	privateKey []byte,
) (*RecoverySignBundleV1, RecoverySignBundleSummary, error) {
	return SignRecoverySignBundle(
		ctx,
		txConfig,
		bundle,
		localMLDSA65Signer{privateKey: privateKey},
	)
}

// AttachRecoverySignBundle revalidates all mutable chain state, attaches the
// offline recovery signature to MsgRecoverKey, and confirms that clearing the
// attached signature reconstructs the exact signed document.
func AttachRecoverySignBundle(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	bundle *RecoverySignBundleV1,
) (sdkclient.TxBuilder, RecoverySignBundleSummary, error) {
	summary, err := ValidateRecoverySignBundle(clientCtx.TxConfig, bundle, true)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	decodedTx, err := clientCtx.TxConfig.TxDecoder()(bundle.UnsignedTx)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("decode bundled recovery transaction: %w", err)
	}
	builder, err := clientCtx.TxConfig.WrapTxBuilder(decodedTx)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("wrap bundled recovery transaction: %w", err)
	}
	signer, err := prepareSingleDirectSigner(clientCtx, txf, builder)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if signer.String() != summary.Owner ||
		txf.AccountNumber() != summary.AccountNumber ||
		txf.Sequence() != summary.Sequence ||
		txf.ChainID() != summary.ChainID {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery bundle is stale: signer, account, sequence, or chain changed",
		)
	}
	message, err := recoveryMessageFromTx(builder.GetTx())
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	policy, recoveryKey, params, err := queryRecoveryState(
		ctx,
		clientCtx,
		message.Owner,
		message.RecoveryKeyId,
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if policy.PolicyVersion != summary.PolicyVersion ||
		!constantTimeBytesEqual(params.NetworkId, summary.NetworkID) ||
		recoveryKey.Algorithm != bundle.RecoveryAlgorithm ||
		!constantTimeBytesEqual(recoveryKey.PublicKey, bundle.OnChainRecoveryPublicKey) {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery bundle is stale: policy, recovery key, or network changed",
		)
	}
	provider, ok := builder.GetTx().(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("protobuf transaction builder is required")
	}
	reconstructed, err := types.NewRecoverySignDocV1(
		provider.GetProtoTx(),
		params.NetworkId,
		txf.ChainID(),
		txf.AccountNumber(),
		txf.Sequence(),
		0,
		signer.String(),
		message.Owner,
		message.RecoveryKeyId,
		message.ExpectedNewSigningKeyId,
		message.NewSigningAlgorithm,
		message.NewSigningPublicKey,
		policy.PolicyVersion,
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	reconstructedBytes, err := types.MarshalRecoverySignDocV1(reconstructed)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if !bytes.Equal(reconstructedBytes, bundle.SignDoc) {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery bundle does not match current transaction or chain state",
		)
	}
	if err := verifyRecoveryBundleSignature(bundle, bundle.RecoverySignature); err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}

	recoveredMessage := *message
	recoveredMessage.RecoverySignature = append([]byte(nil), bundle.RecoverySignature...)
	if err := builder.SetMsgs(&recoveredMessage); err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("attach recovery signature: %w", err)
	}
	attachedProvider, ok := builder.GetTx().(protoTxProvider)
	if !ok || attachedProvider.GetProtoTx() == nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("protobuf transaction builder is required")
	}
	attachedDoc, err := types.NewRecoverySignDocV1(
		attachedProvider.GetProtoTx(),
		params.NetworkId,
		txf.ChainID(),
		txf.AccountNumber(),
		txf.Sequence(),
		0,
		signer.String(),
		recoveredMessage.Owner,
		recoveredMessage.RecoveryKeyId,
		recoveredMessage.ExpectedNewSigningKeyId,
		recoveredMessage.NewSigningAlgorithm,
		recoveredMessage.NewSigningPublicKey,
		policy.PolicyVersion,
	)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	attachedBytes, err := types.MarshalRecoverySignDocV1(attachedDoc)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	if !bytes.Equal(attachedBytes, bundle.SignDoc) {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"attached recovery signature changed the signed transaction intent",
		)
	}
	return builder, summary, nil
}

func MarshalRecoverySignBundle(
	txConfig sdkclient.TxConfig,
	bundle *RecoverySignBundleV1,
	requireSignature bool,
) ([]byte, error) {
	if _, err := ValidateRecoverySignBundle(txConfig, bundle, requireSignature); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode recovery sign bundle: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxRecoverySignBundleBytes {
		return nil, fmt.Errorf("recovery sign bundle exceeds %d bytes", MaxRecoverySignBundleBytes)
	}
	return encoded, nil
}

func UnmarshalRecoverySignBundle(
	txConfig sdkclient.TxConfig,
	encoded []byte,
	requireSignature bool,
) (*RecoverySignBundleV1, RecoverySignBundleSummary, error) {
	if len(encoded) == 0 || len(encoded) > MaxRecoverySignBundleBytes {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery sign bundle length must be between 1 and %d bytes",
			MaxRecoverySignBundleBytes,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle RecoverySignBundleV1
	if err := decoder.Decode(&bundle); err != nil {
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("decode recovery sign bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, RecoverySignBundleSummary{}, fmt.Errorf(
				"decode recovery sign bundle: multiple JSON values",
			)
		}
		return nil, RecoverySignBundleSummary{}, fmt.Errorf("decode recovery sign bundle: %w", err)
	}
	summary, err := ValidateRecoverySignBundle(txConfig, &bundle, requireSignature)
	if err != nil {
		return nil, RecoverySignBundleSummary{}, err
	}
	return &bundle, summary, nil
}

func ValidateRecoverySignBundle(
	txConfig sdkclient.TxConfig,
	bundle *RecoverySignBundleV1,
	requireSignature bool,
) (RecoverySignBundleSummary, error) {
	if txConfig == nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("transaction config is required")
	}
	if bundle == nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("recovery sign bundle is required")
	}
	if bundle.Format != RecoverySignBundleFormatV1 {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"unsupported recovery sign bundle format %q",
			bundle.Format,
		)
	}
	if len(bundle.UnsignedTx) == 0 || len(bundle.UnsignedTx) > maxUnsignedTxBytes {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled unsigned recovery transaction length must be between 1 and %d bytes",
			maxUnsignedTxBytes,
		)
	}
	if len(bundle.SignDoc) == 0 || len(bundle.SignDoc) > maxPQCSignDocBytes {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery sign document length must be between 1 and %d bytes",
			maxPQCSignDocBytes,
		)
	}
	txHash := sha256.Sum256(bundle.UnsignedTx)
	if !constantTimeBytesEqual(bundle.UnsignedTxSHA256, txHash[:]) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery transaction SHA-256 mismatch",
		)
	}
	signDocHash := sha256.Sum256(bundle.SignDoc)
	if !constantTimeBytesEqual(bundle.SignDocSHA256, signDocHash[:]) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery sign document SHA-256 mismatch",
		)
	}

	var signDoc types.RecoverySignDocV1
	if err := signDoc.Unmarshal(bundle.SignDoc); err != nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("decode bundled recovery sign document: %w", err)
	}
	canonicalSignDoc, err := types.MarshalRecoverySignDocV1(signDoc)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	if !bytes.Equal(canonicalSignDoc, bundle.SignDoc) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery sign document is not canonical",
		)
	}
	if signDoc.SignerIndex != 0 || signDoc.Signer != signDoc.Owner {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery bundle requires owner at signer index 0",
		)
	}
	signer, err := sdk.AccAddressFromBech32(signDoc.Signer)
	if err != nil || signer.String() != signDoc.Signer {
		return RecoverySignBundleSummary{}, fmt.Errorf("bundled recovery signer address is invalid")
	}

	decodedTx, err := txConfig.TxDecoder()(bundle.UnsignedTx)
	if err != nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("decode bundled recovery transaction: %w", err)
	}
	reencoded, err := txConfig.TxEncoder()(decodedTx)
	if err != nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("re-encode bundled recovery transaction: %w", err)
	}
	if !bytes.Equal(reencoded, bundle.UnsignedTx) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled unsigned recovery transaction is not canonical",
		)
	}
	message, err := recoveryMessageFromTx(decodedTx)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	if err := message.ValidateBasic(); err != nil {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery message failed basic validation: %w",
			err,
		)
	}
	if err := validateRecoveryPlaceholder(message, bundle.RecoveryAlgorithm); err != nil {
		return RecoverySignBundleSummary{}, err
	}
	if message.Owner != signDoc.Owner ||
		message.RecoveryKeyId != signDoc.RecoveryKeyId ||
		message.ExpectedNewSigningKeyId != signDoc.ProposedSigningKeyId ||
		message.NewSigningAlgorithm != signDoc.ProposedAlgorithm ||
		!constantTimeBytesEqual(message.NewSigningPublicKey, signDoc.ProposedPublicKey) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery message does not match sign document",
		)
	}

	provider, ok := decodedTx.(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil {
		return RecoverySignBundleSummary{}, fmt.Errorf("protobuf transaction is required")
	}
	protoTx := provider.GetProtoTx()
	if _, removed, err := types.CanonicalBodyBytesWithoutPQCAuth(protoTx); err != nil {
		return RecoverySignBundleSummary{}, err
	} else if removed != 0 {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"recovery bundle must not contain PQC transaction authorization",
		)
	}
	if err := validateUnsignedRecoverySigner(
		protoTx,
		decodedTx,
		signer,
		signDoc.Sequence,
	); err != nil {
		return RecoverySignBundleSummary{}, err
	}
	reconstructed, err := types.NewRecoverySignDocV1(
		protoTx,
		signDoc.NetworkId,
		signDoc.ChainId,
		signDoc.AccountNumber,
		signDoc.Sequence,
		signDoc.SignerIndex,
		signDoc.Signer,
		signDoc.Owner,
		signDoc.RecoveryKeyId,
		signDoc.ProposedSigningKeyId,
		signDoc.ProposedAlgorithm,
		signDoc.ProposedPublicKey,
		signDoc.CurrentPolicyVersion,
	)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	reconstructedBytes, err := types.MarshalRecoverySignDocV1(reconstructed)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	if !bytes.Equal(reconstructedBytes, bundle.SignDoc) {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery sign document does not match bundled transaction",
		)
	}

	recoveryAlgorithm, err := types.CryptoAlgorithm(bundle.RecoveryAlgorithm)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	publicKeySize, signatureSize, err := pqccrypto.Sizes(recoveryAlgorithm)
	if err != nil {
		return RecoverySignBundleSummary{}, err
	}
	if len(bundle.OnChainRecoveryPublicKey) != publicKeySize {
		return RecoverySignBundleSummary{}, fmt.Errorf(
			"bundled recovery public key length %d, want %d",
			len(bundle.OnChainRecoveryPublicKey),
			publicKeySize,
		)
	}
	if requireSignature && len(bundle.RecoverySignature) == 0 {
		return RecoverySignBundleSummary{}, fmt.Errorf("recovery sign bundle has no signature")
	}
	if len(bundle.RecoverySignature) != 0 {
		if len(bundle.RecoverySignature) != signatureSize {
			return RecoverySignBundleSummary{}, fmt.Errorf(
				"bundled recovery signature length %d, want %d",
				len(bundle.RecoverySignature),
				signatureSize,
			)
		}
		if err := verifyRecoveryBundleSignature(bundle, bundle.RecoverySignature); err != nil {
			return RecoverySignBundleSummary{}, err
		}
	}

	return RecoverySignBundleSummary{
		ChainID:              signDoc.ChainId,
		NetworkID:            append([]byte(nil), signDoc.NetworkId...),
		Owner:                signDoc.Owner,
		AccountNumber:        signDoc.AccountNumber,
		Sequence:             signDoc.Sequence,
		RecoveryKeyID:        signDoc.RecoveryKeyId,
		ProposedSigningKeyID: signDoc.ProposedSigningKeyId,
		RecoveryAlgorithm:    bundle.RecoveryAlgorithm,
		ProposedAlgorithm:    signDoc.ProposedAlgorithm,
		PolicyVersion:        signDoc.CurrentPolicyVersion,
		TxSHA256:             append([]byte(nil), txHash[:]...),
		SignDocSHA256:        append([]byte(nil), signDocHash[:]...),
		Signed:               len(bundle.RecoverySignature) != 0,
	}, nil
}

func queryRecoveryState(
	ctx context.Context,
	clientCtx sdkclient.Context,
	owner string,
	recoveryKeyID uint64,
) (types.AccountPolicy, types.PQCKeyRecord, types.Params, error) {
	queryClient := types.NewQueryClient(clientCtx)
	accountResponse, err := queryClient.Account(ctx, &types.QueryAccountRequest{Owner: owner})
	if err != nil {
		return types.AccountPolicy{}, types.PQCKeyRecord{}, types.Params{},
			fmt.Errorf("query recovery account policy: %w", err)
	}
	if accountResponse.Policy.RecoveryKeyId == 0 ||
		accountResponse.Policy.RecoveryKeyId != recoveryKeyID {
		return types.AccountPolicy{}, types.PQCKeyRecord{}, types.Params{},
			fmt.Errorf("recovery key does not match effective account policy")
	}
	keyResponse, err := queryClient.Key(ctx, &types.QueryKeyRequest{
		Owner: owner,
		KeyId: recoveryKeyID,
	})
	if err != nil {
		return types.AccountPolicy{}, types.PQCKeyRecord{}, types.Params{},
			fmt.Errorf("query recovery key: %w", err)
	}
	if keyResponse.Key.Role != types.KeyRole_KEY_ROLE_RECOVERY ||
		keyResponse.Key.Status != types.KeyStatus_KEY_STATUS_LIVE {
		return types.AccountPolicy{}, types.PQCKeyRecord{}, types.Params{},
			fmt.Errorf("configured recovery key is not live recovery material")
	}
	paramsResponse, err := queryClient.Params(ctx, &types.QueryParamsRequest{})
	if err != nil {
		return types.AccountPolicy{}, types.PQCKeyRecord{}, types.Params{},
			fmt.Errorf("query PQC params for recovery: %w", err)
	}
	return accountResponse.Policy, keyResponse.Key, paramsResponse.Params, nil
}

func recoveryMessageFromTx(tx sdk.Tx) (*types.MsgRecoverKey, error) {
	if tx == nil || len(tx.GetMsgs()) != 1 {
		return nil, fmt.Errorf("recovery bundle requires exactly one message")
	}
	message, ok := tx.GetMsgs()[0].(*types.MsgRecoverKey)
	if !ok || message == nil {
		return nil, fmt.Errorf("recovery bundle requires one top-level MsgRecoverKey")
	}
	return message, nil
}

func validateRecoveryPlaceholder(message *types.MsgRecoverKey, algorithm types.Algorithm) error {
	cryptoAlgorithm, err := types.CryptoAlgorithm(algorithm)
	if err != nil {
		return err
	}
	_, signatureSize, err := pqccrypto.Sizes(cryptoAlgorithm)
	if err != nil {
		return err
	}
	if len(message.RecoverySignature) != signatureSize {
		return fmt.Errorf(
			"recovery signature placeholder length %d, want %d",
			len(message.RecoverySignature),
			signatureSize,
		)
	}
	for _, value := range message.RecoverySignature {
		if value != 0 {
			return fmt.Errorf("unsigned recovery transaction must contain an all-zero signature placeholder")
		}
	}
	return nil
}

func validateUnsignedRecoverySigner(
	protoTx *txtypes.Tx,
	decodedTx sdk.Tx,
	expectedSigner sdk.AccAddress,
	expectedSequence uint64,
) error {
	if protoTx.Body == nil || protoTx.AuthInfo == nil {
		return fmt.Errorf("bundled recovery transaction body or auth info is missing")
	}
	if len(protoTx.AuthInfo.SignerInfos) != 1 {
		return fmt.Errorf("recovery sign bundles require exactly one signer info")
	}
	signerInfo := protoTx.AuthInfo.SignerInfos[0]
	if signerInfo == nil || signerInfo.ModeInfo == nil ||
		signerInfo.ModeInfo.GetSingle() == nil ||
		signerInfo.ModeInfo.GetSingle().Mode != txsigning.SignMode_SIGN_MODE_DIRECT {
		return types.ErrUnsupportedSignMode
	}
	if signerInfo.Sequence != expectedSequence {
		return fmt.Errorf("bundled recovery signer sequence does not match sign document")
	}
	if len(protoTx.Signatures) != 1 || len(protoTx.Signatures[0]) != 0 {
		return fmt.Errorf("bundled recovery transaction must contain one empty classical signature")
	}
	signatureTx, ok := decodedTx.(authsigning.SigVerifiableTx)
	if !ok {
		return fmt.Errorf("bundled recovery transaction does not expose signers")
	}
	signers := signatureTx.GetSigners()
	if len(signers) != 1 || !signers[0].Equals(expectedSigner) {
		return fmt.Errorf("bundled recovery signer does not match sign document")
	}
	return nil
}

func verifyRecoveryBundleSignature(bundle *RecoverySignBundleV1, signature []byte) error {
	algorithm, err := types.CryptoAlgorithm(bundle.RecoveryAlgorithm)
	if err != nil {
		return err
	}
	if err := pqccrypto.Verify(
		algorithm,
		bundle.OnChainRecoveryPublicKey,
		bundle.SignDoc,
		[]byte(types.RecoverySignatureContext),
		signature,
	); err != nil {
		return fmt.Errorf("invalid bundled recovery signature: %w", err)
	}
	return nil
}

func cloneRecoverySignBundle(bundle *RecoverySignBundleV1) *RecoverySignBundleV1 {
	if bundle == nil {
		return nil
	}
	return &RecoverySignBundleV1{
		Format:                   bundle.Format,
		UnsignedTx:               append([]byte(nil), bundle.UnsignedTx...),
		UnsignedTxSHA256:         append([]byte(nil), bundle.UnsignedTxSHA256...),
		SignDoc:                  append([]byte(nil), bundle.SignDoc...),
		SignDocSHA256:            append([]byte(nil), bundle.SignDocSHA256...),
		RecoveryAlgorithm:        bundle.RecoveryAlgorithm,
		OnChainRecoveryPublicKey: append([]byte(nil), bundle.OnChainRecoveryPublicKey...),
		RecoverySignature:        append([]byte(nil), bundle.RecoverySignature...),
	}
}
