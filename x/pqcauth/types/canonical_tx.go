package types

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
)

const (
	ExtensionPQCAuthTypeURL = "/doravota.pqcauth.v1.ExtensionPQCAuth"
	msgRecoverKeyTypeURL    = "/doravota.pqcauth.v1.MsgRecoverKey"
)

// CanonicalPQCTransaction is the shared, immutable transaction representation
// used to build signer-specific PQC documents without re-marshaling the full
// transaction for every signer.
type CanonicalPQCTransaction struct {
	BodyBytesWithoutPQCAuth []byte
	AuthInfoBytes           []byte
}

// CanonicalBodyBytesWithoutPQCAuth deterministically marshals a TxBody after
// removing its unique critical pqcauth extension. The input is never mutated.
func CanonicalBodyBytesWithoutPQCAuth(tx *txtypes.Tx) ([]byte, int, error) {
	if tx == nil || tx.Body == nil {
		return nil, 0, fmt.Errorf("%w: transaction body is missing", ErrInvalidExtension)
	}

	body := *tx.Body
	body.Messages = append([]*codectypes.Any(nil), tx.Body.Messages...)
	body.ExtensionOptions = make([]*codectypes.Any, 0, len(tx.Body.ExtensionOptions))
	removed := 0
	for _, option := range tx.Body.ExtensionOptions {
		if option != nil && option.TypeUrl == ExtensionPQCAuthTypeURL {
			removed++
			continue
		}
		body.ExtensionOptions = append(body.ExtensionOptions, option)
	}
	body.NonCriticalExtensionOptions = append(
		[]*codectypes.Any(nil),
		tx.Body.NonCriticalExtensionOptions...,
	)
	bz, err := body.Marshal()
	if err != nil {
		return nil, 0, fmt.Errorf("marshal canonical transaction body: %w", err)
	}
	return bz, removed, nil
}

func CanonicalAuthInfoBytes(tx *txtypes.Tx) ([]byte, error) {
	if tx == nil || tx.AuthInfo == nil {
		return nil, fmt.Errorf("%w: transaction auth info is missing", ErrInvalidExtension)
	}
	bz, err := tx.AuthInfo.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal canonical auth info: %w", err)
	}
	return bz, nil
}

func NewCanonicalPQCTransaction(tx *txtypes.Tx) (CanonicalPQCTransaction, error) {
	bodyBytes, removed, err := CanonicalBodyBytesWithoutPQCAuth(tx)
	if err != nil {
		return CanonicalPQCTransaction{}, err
	}
	if removed > 1 {
		return CanonicalPQCTransaction{}, fmt.Errorf(
			"%w: multiple pqcauth extensions",
			ErrInvalidExtension,
		)
	}
	authInfoBytes, err := CanonicalAuthInfoBytes(tx)
	if err != nil {
		return CanonicalPQCTransaction{}, err
	}
	return CanonicalPQCTransaction{
		BodyBytesWithoutPQCAuth: bodyBytes,
		AuthInfoBytes:           authInfoBytes,
	}, nil
}

// CanonicalRecoveryBodyBytes deterministically marshals the sole MsgRecoverKey
// transaction after removing the PQC extension and clearing the embedded
// recovery signature. All other message and TxBody fields remain bound.
func CanonicalRecoveryBodyBytes(tx *txtypes.Tx) ([]byte, error) {
	if tx == nil || tx.Body == nil {
		return nil, fmt.Errorf("%w: transaction body is missing", ErrInvalidExtension)
	}
	if len(tx.Body.Messages) != 1 || tx.Body.Messages[0] == nil ||
		tx.Body.Messages[0].TypeUrl != msgRecoverKeyTypeURL {
		return nil, fmt.Errorf(
			"%w: recovery authorization requires one top-level MsgRecoverKey",
			ErrInvalidKeyProof,
		)
	}

	var recovery MsgRecoverKey
	if err := recovery.Unmarshal(tx.Body.Messages[0].Value); err != nil {
		return nil, fmt.Errorf("%w: decode recovery message: %v", ErrInvalidKeyProof, err)
	}
	recovery.RecoverySignature = nil
	recoveryBytes, err := recovery.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: marshal recovery message: %v", ErrInvalidKeyProof, err)
	}

	body := *tx.Body
	body.Messages = append([]*codectypes.Any(nil), tx.Body.Messages...)
	body.Messages[0] = &codectypes.Any{
		TypeUrl: msgRecoverKeyTypeURL,
		Value:   recoveryBytes,
	}
	body.ExtensionOptions = make([]*codectypes.Any, 0, len(tx.Body.ExtensionOptions))
	removed := 0
	for _, option := range tx.Body.ExtensionOptions {
		if option != nil && option.TypeUrl == ExtensionPQCAuthTypeURL {
			removed++
			continue
		}
		body.ExtensionOptions = append(body.ExtensionOptions, option)
	}
	if removed > 1 {
		return nil, fmt.Errorf("%w: multiple pqcauth extensions", ErrInvalidExtension)
	}
	body.NonCriticalExtensionOptions = append(
		[]*codectypes.Any(nil),
		tx.Body.NonCriticalExtensionOptions...,
	)
	bz, err := body.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal canonical recovery transaction body: %w", err)
	}
	return bz, nil
}

// NewRecoverySignDocV1 constructs a signer- and transaction-specific recovery
// authorization document. The complete AuthInfo is included verbatim after
// deterministic protobuf marshaling.
func NewRecoverySignDocV1(
	tx *txtypes.Tx,
	networkID []byte,
	chainID string,
	accountNumber uint64,
	sequence uint64,
	signerIndex uint32,
	signer string,
	owner string,
	recoveryKeyID uint64,
	proposedSigningKeyID uint64,
	proposedAlgorithm Algorithm,
	proposedPublicKey []byte,
	currentPolicyVersion uint64,
) (RecoverySignDocV1, error) {
	bodyBytes, err := CanonicalRecoveryBodyBytes(tx)
	if err != nil {
		return RecoverySignDocV1{}, err
	}
	authInfoBytes, err := CanonicalAuthInfoBytes(tx)
	if err != nil {
		return RecoverySignDocV1{}, err
	}
	return RecoverySignDocV1{
		FormatVersion:        FormatVersionV1,
		NetworkId:            append([]byte(nil), networkID...),
		ChainId:              chainID,
		Owner:                owner,
		RecoveryKeyId:        recoveryKeyID,
		ProposedSigningKeyId: proposedSigningKeyID,
		ProposedAlgorithm:    proposedAlgorithm,
		ProposedPublicKey:    append([]byte(nil), proposedPublicKey...),
		CurrentPolicyVersion: currentPolicyVersion,
		AccountNumber:        accountNumber,
		Sequence:             sequence,
		SignerIndex:          signerIndex,
		Signer:               signer,
		BodyBytesWithoutPqcAuthAndRecoverySignature: bodyBytes,
		AuthInfoBytes: authInfoBytes,
	}, nil
}

// NewPQCSignDocV1 constructs one signer-specific sign document from the shared
// canonical transaction representation.
func NewPQCSignDocV1(
	tx *txtypes.Tx,
	networkID []byte,
	chainID string,
	accountNumber uint64,
	sequence uint64,
	signerIndex uint32,
	signer string,
	keyID uint64,
	algorithm Algorithm,
	policyVersion uint64,
) (PQCSignDocV1, error) {
	canonical, err := NewCanonicalPQCTransaction(tx)
	if err != nil {
		return PQCSignDocV1{}, err
	}
	return NewPQCSignDocV1FromCanonical(
		canonical,
		networkID,
		chainID,
		accountNumber,
		sequence,
		signerIndex,
		signer,
		keyID,
		algorithm,
		policyVersion,
	), nil
}

func NewPQCSignDocV1FromCanonical(
	canonical CanonicalPQCTransaction,
	networkID []byte,
	chainID string,
	accountNumber uint64,
	sequence uint64,
	signerIndex uint32,
	signer string,
	keyID uint64,
	algorithm Algorithm,
	policyVersion uint64,
) PQCSignDocV1 {
	return PQCSignDocV1{
		FormatVersion: FormatVersionV1,
		NetworkId:     append([]byte(nil), networkID...),
		ChainId:       chainID,
		AccountNumber: accountNumber,
		Sequence:      sequence,
		SignerIndex:   signerIndex,
		Signer:        signer,
		KeyId:         keyID,
		Algorithm:     algorithm,
		PolicyVersion: policyVersion,
		BodyBytesWithoutPqcAuth: append(
			[]byte(nil),
			canonical.BodyBytesWithoutPQCAuth...,
		),
		AuthInfoBytes: append([]byte(nil), canonical.AuthInfoBytes...),
	}
}
