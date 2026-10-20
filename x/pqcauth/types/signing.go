package types

import (
	"fmt"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
)

const (
	FormatVersionV1 uint32 = 1

	PurposeRegisterSigning  = "register-signing"
	PurposeRegisterRecovery = "register-recovery"
	PurposeRotateSigning    = "rotate-signing"
	PurposeRotateRecovery   = "rotate-recovery"
	PurposeRecoverSigning   = "recover-signing"

	TxSignatureContext       = "doravota/pqcauth/tx/v1"
	RegisterProofContext     = "doravota/pqcauth/register/v1"
	RotateProofContext       = "doravota/pqcauth/rotate/v1"
	RotateRecoveryContext    = "doravota/pqcauth/rotate-recovery/v1"
	RecoveryKeyProofContext  = "doravota/pqcauth/recover-key-proof/v1"
	RecoverySignatureContext = "doravota/pqcauth/recovery/v1"
)

func MarshalPQCSignDocV1(doc PQCSignDocV1) ([]byte, error) {
	if doc.FormatVersion != FormatVersionV1 {
		return nil, fmt.Errorf("%w: sign doc format version %d", ErrInvalidExtension, doc.FormatVersion)
	}
	if len(doc.NetworkId) == 0 || doc.ChainId == "" || doc.Signer == "" || doc.KeyId == 0 {
		return nil, fmt.Errorf("%w: incomplete PQC sign doc", ErrInvalidExtension)
	}
	if !SupportedAlgorithm(doc.Algorithm) {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, doc.Algorithm)
	}
	return doc.Marshal()
}

func MarshalKeyProofDocV1(doc KeyProofDocV1) ([]byte, error) {
	if doc.FormatVersion != FormatVersionV1 {
		return nil, fmt.Errorf("%w: proof doc format version %d", ErrInvalidKeyProof, doc.FormatVersion)
	}
	if len(doc.NetworkId) == 0 || doc.ChainId == "" || doc.Owner == "" ||
		doc.ProposedKeyId == 0 || len(doc.PublicKey) == 0 || doc.Purpose == "" {
		return nil, fmt.Errorf("%w: incomplete key proof doc", ErrInvalidKeyProof)
	}
	if !SupportedAlgorithm(doc.Algorithm) {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, doc.Algorithm)
	}
	if doc.Role != KeyRole_KEY_ROLE_SIGNING && doc.Role != KeyRole_KEY_ROLE_RECOVERY {
		return nil, fmt.Errorf("%w: invalid key role %d", ErrInvalidKeyProof, doc.Role)
	}
	return doc.Marshal()
}

func MarshalRecoverySignDocV1(doc RecoverySignDocV1) ([]byte, error) {
	if doc.FormatVersion != FormatVersionV1 {
		return nil, fmt.Errorf("%w: recovery doc format version %d", ErrInvalidKeyProof, doc.FormatVersion)
	}
	if len(doc.NetworkId) == 0 || doc.ChainId == "" || doc.Owner == "" ||
		doc.RecoveryKeyId == 0 || doc.ProposedSigningKeyId == 0 ||
		len(doc.ProposedPublicKey) == 0 || doc.Signer == "" ||
		len(doc.BodyBytesWithoutPqcAuthAndRecoverySignature) == 0 ||
		len(doc.AuthInfoBytes) == 0 {
		return nil, fmt.Errorf("%w: incomplete recovery sign doc", ErrInvalidKeyProof)
	}
	if !SupportedAlgorithm(doc.ProposedAlgorithm) {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, doc.ProposedAlgorithm)
	}
	return doc.Marshal()
}

func ValidatePublicKeyAndProofLengths(algorithm Algorithm, publicKey, proof []byte) error {
	cryptoAlgorithm, err := CryptoAlgorithm(algorithm)
	if err != nil {
		return err
	}
	publicKeySize, signatureSize, err := pqccrypto.Sizes(cryptoAlgorithm)
	if err != nil {
		return err
	}
	if len(publicKey) != publicKeySize {
		return fmt.Errorf("%w: public key length %d, want %d", ErrInvalidKey, len(publicKey), publicKeySize)
	}
	if len(proof) != signatureSize {
		return fmt.Errorf("%w: proof length %d, want %d", ErrInvalidKeyProof, len(proof), signatureSize)
	}
	return nil
}
