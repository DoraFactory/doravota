package client

import (
	"context"
	"fmt"
	"io"
	"os"

	sdkclient "github.com/cosmos/cosmos-sdk/client"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type protoTxProvider interface {
	GetProtoTx() *txtypes.Tx
}

// PQCSigner is the transport-neutral boundary used by local keys, remote
// signers, HSMs, and hardware wallets. Implementations must return encoded
// public keys and signatures for their declared consensus algorithm.
type PQCSigner interface {
	Algorithm() types.Algorithm
	PublicKey(context.Context) ([]byte, error)
	Sign(context.Context, []byte, []byte) ([]byte, error)
}

type localMLDSA65Signer struct {
	privateKey []byte
}

type pqcSignPreparation struct {
	signer    sdk.AccAddress
	key       types.PQCKeyRecord
	policy    types.AccountPolicy
	signBytes []byte
}

// BuildPQCAuthSimulationExtension constructs a state-bound, correctly sized
// placeholder authorization for gas simulation. Its all-zero signature is
// never valid for delivery; the pqcauth Ante decorator accepts it only when
// simulate=true after validating signer, key, algorithm, and policy metadata.
func BuildPQCAuthSimulationExtension(
	ctx context.Context,
	clientCtx sdkclient.Context,
) (*codectypes.Any, error) {
	signer := clientCtx.GetFromAddress()
	if len(signer) == 0 {
		return nil, fmt.Errorf("simulation signer address is required")
	}
	queryClient := types.NewQueryClient(clientCtx)
	accountResponse, err := queryClient.Account(ctx, &types.QueryAccountRequest{
		Owner: signer.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("query PQC account policy for simulation: %w", err)
	}
	if accountResponse.ActiveSigningKey == nil {
		return nil, types.ErrKeyNotFound
	}
	paramsResponse, err := queryClient.Params(ctx, &types.QueryParamsRequest{})
	if err != nil {
		return nil, fmt.Errorf("query PQC params for simulation: %w", err)
	}
	if paramsResponse.EffectiveEmergencyMode ==
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return nil, types.ErrEmergencyPause
	}
	key := accountResponse.ActiveSigningKey
	if !paramsResponse.Params.IsAlgorithmAllowed(key.Algorithm) {
		return nil, fmt.Errorf("%w: %d", types.ErrUnsupportedAlgorithm, key.Algorithm)
	}
	algorithm, err := types.CryptoAlgorithm(key.Algorithm)
	if err != nil {
		return nil, err
	}
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	if err != nil {
		return nil, err
	}
	extension, err := codectypes.NewAnyWithValue(&types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures: []types.SignerPQCSignature{{
			Signer:        signer.String(),
			SignerIndex:   0,
			KeyId:         key.KeyId,
			Algorithm:     key.Algorithm,
			PolicyVersion: accountResponse.Policy.PolicyVersion,
			Signature:     make([]byte, signatureSize),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("encode PQC simulation extension: %w", err)
	}
	return extension, nil
}

func (localMLDSA65Signer) Algorithm() types.Algorithm {
	return types.Algorithm_ALGORITHM_ML_DSA_65
}

func (s localMLDSA65Signer) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pqccrypto.MLDSA65PublicKeyFromPrivate(s.privateKey)
}

func (s localMLDSA65Signer) Sign(
	ctx context.Context,
	message []byte,
	signatureContext []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pqccrypto.SignMLDSA65(s.privateKey, message, signatureContext, true)
}

// LoadPrivateKeyFile loads an encoded ML-DSA private key and rejects files
// readable by group or other users.
func LoadPrivateKeyFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PQC private key file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect PQC private key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("PQC private key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("PQC private key file permissions must not grant group or other access")
	}
	expectedSize, err := pqccrypto.PrivateKeySize(pqccrypto.AlgorithmMLDSA65)
	if err != nil {
		return nil, err
	}
	privateKey, err := io.ReadAll(io.LimitReader(file, int64(expectedSize+1)))
	if err != nil {
		return nil, fmt.Errorf("read PQC private key file: %w", err)
	}
	if len(privateKey) != expectedSize {
		clear(privateKey)
		return nil, fmt.Errorf(
			"PQC private key file length %d, want %d",
			len(privateKey),
			expectedSize,
		)
	}
	return privateKey, nil
}

// AttachPQCAuth queries the effective on-chain policy, creates the signer info
// needed by canonical AuthInfo, signs the PQC document, and attaches the unique
// critical extension. Classical signing must happen after this function.
func AttachPQCAuth(
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
	privateKey []byte,
) error {
	return AttachPQCAuthWithPrivateKey(
		context.Background(),
		clientCtx,
		txf,
		builder,
		privateKey,
	)
}

// AttachPQCAuthWithPrivateKey is the context-aware local-key form used by
// interactive clients.
func AttachPQCAuthWithPrivateKey(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
	privateKey []byte,
) error {
	return AttachPQCAuthWithSigner(
		ctx,
		clientCtx,
		txf,
		builder,
		localMLDSA65Signer{privateKey: privateKey},
	)
}

// AttachPQCAuthWithSigner builds the signer-specific canonical document and
// delegates only the final ML-DSA operation through PQCSigner. It verifies the
// signer's public key and returned signature locally before mutating TxBody.
func AttachPQCAuthWithSigner(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
	signerBackend PQCSigner,
) error {
	if signerBackend == nil {
		return fmt.Errorf("PQC signer is required")
	}
	prepared, err := preparePQCSignDoc(ctx, clientCtx, txf, builder)
	if err != nil {
		return err
	}
	signerAlgorithm := signerBackend.Algorithm()
	if signerAlgorithm != prepared.key.Algorithm {
		return fmt.Errorf(
			"PQC signer algorithm %d does not match active on-chain algorithm %d",
			signerAlgorithm,
			prepared.key.Algorithm,
		)
	}
	signerPublicKey, err := signerBackend.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("load PQC signer public key: %w", err)
	}
	if !constantTimeBytesEqual(signerPublicKey, prepared.key.PublicKey) {
		return fmt.Errorf("PQC signer does not match active on-chain key")
	}
	signature, err := signerBackend.Sign(
		ctx,
		prepared.signBytes,
		[]byte(types.TxSignatureContext),
	)
	if err != nil {
		return err
	}
	if err := verifyPQCSignature(
		prepared.key.Algorithm,
		prepared.key.PublicKey,
		prepared.signBytes,
		signature,
	); err != nil {
		return fmt.Errorf("PQC signer returned an invalid signature: %w", err)
	}
	return attachPQCSignature(builder, prepared, signature)
}

func preparePQCSignDoc(
	ctx context.Context,
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
) (pqcSignPreparation, error) {
	signer, err := prepareSingleDirectSigner(clientCtx, txf, builder)
	if err != nil {
		return pqcSignPreparation{}, err
	}

	queryClient := types.NewQueryClient(clientCtx)
	accountResponse, err := queryClient.Account(ctx, &types.QueryAccountRequest{
		Owner: signer.String(),
	})
	if err != nil {
		return pqcSignPreparation{}, fmt.Errorf("query PQC account policy: %w", err)
	}
	paramsResponse, err := queryClient.Params(ctx, &types.QueryParamsRequest{})
	if err != nil {
		return pqcSignPreparation{}, fmt.Errorf("query PQC params: %w", err)
	}
	if accountResponse.ActiveSigningKey == nil {
		return pqcSignPreparation{}, types.ErrKeyNotFound
	}
	key := accountResponse.ActiveSigningKey
	policy := accountResponse.Policy
	if paramsResponse.EffectiveEmergencyMode ==
		types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS {
		return pqcSignPreparation{}, types.ErrEmergencyPause
	}

	provider, ok := builder.GetTx().(protoTxProvider)
	if !ok {
		return pqcSignPreparation{}, fmt.Errorf("protobuf transaction builder is required")
	}
	signDoc, err := types.NewPQCSignDocV1(
		provider.GetProtoTx(),
		paramsResponse.Params.NetworkId,
		txf.ChainID(),
		txf.AccountNumber(),
		txf.Sequence(),
		0,
		signer.String(),
		key.KeyId,
		key.Algorithm,
		policy.PolicyVersion,
	)
	if err != nil {
		return pqcSignPreparation{}, err
	}
	signBytes, err := types.MarshalPQCSignDocV1(signDoc)
	if err != nil {
		return pqcSignPreparation{}, err
	}
	return pqcSignPreparation{
		signer:    signer,
		key:       *key,
		policy:    policy,
		signBytes: signBytes,
	}, nil
}

func prepareSingleDirectSigner(
	clientCtx sdkclient.Context,
	txf sdktx.Factory,
	builder sdkclient.TxBuilder,
) (sdk.AccAddress, error) {
	signMode := txf.SignMode()
	if signMode == txsigning.SignMode_SIGN_MODE_UNSPECIFIED {
		var err error
		signMode, err = authsigning.APISignModeToInternal(
			clientCtx.TxConfig.SignModeHandler().DefaultMode(),
		)
		if err != nil {
			return nil, fmt.Errorf("resolve default sign mode: %w", err)
		}
	}
	if signMode != txsigning.SignMode_SIGN_MODE_DIRECT {
		return nil, types.ErrUnsupportedSignMode
	}
	if txf.Keybase() == nil {
		return nil, fmt.Errorf("classical keyring is required")
	}
	keyInfo, err := txf.Keybase().Key(clientCtx.FromName)
	if err != nil {
		return nil, fmt.Errorf("load classical key: %w", err)
	}
	publicKey, err := keyInfo.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("load classical public key: %w", err)
	}
	signer := sdk.AccAddress(publicKey.Address())
	if !signer.Equals(clientCtx.GetFromAddress()) {
		return nil, fmt.Errorf("classical key does not match --from address")
	}

	if err := builder.SetSignatures(txsigning.SignatureV2{
		PubKey: publicKey,
		Data: &txsigning.SingleSignatureData{
			SignMode: signMode,
		},
		Sequence: txf.Sequence(),
	}); err != nil {
		return nil, fmt.Errorf("prepare signer info: %w", err)
	}
	return signer, nil
}

func attachPQCSignature(
	builder sdkclient.TxBuilder,
	prepared pqcSignPreparation,
	signature []byte,
) error {
	extensionAny, err := codectypes.NewAnyWithValue(&types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures: []types.SignerPQCSignature{{
			Signer:        prepared.signer.String(),
			SignerIndex:   0,
			KeyId:         prepared.key.KeyId,
			Algorithm:     prepared.key.Algorithm,
			PolicyVersion: prepared.policy.PolicyVersion,
			Signature:     signature,
		}},
	})
	if err != nil {
		return fmt.Errorf("encode PQC extension: %w", err)
	}
	extendedBuilder, ok := builder.(sdkclient.ExtendedTxBuilder)
	if !ok {
		return fmt.Errorf("transaction builder does not support extension options")
	}
	provider, ok := builder.GetTx().(protoTxProvider)
	if !ok || provider.GetProtoTx() == nil || provider.GetProtoTx().Body == nil {
		return fmt.Errorf("protobuf transaction builder is required")
	}
	existing := provider.GetProtoTx().Body.ExtensionOptions
	for _, option := range existing {
		if option != nil && option.TypeUrl == types.ExtensionPQCAuthTypeURL {
			return fmt.Errorf("transaction already contains PQC authorization")
		}
	}
	extensions := make([]*codectypes.Any, 0, len(existing)+1)
	extensions = append(extensions, existing...)
	extensions = append(extensions, extensionAny)
	extendedBuilder.SetExtensionOptions(extensions...)
	return nil
}
