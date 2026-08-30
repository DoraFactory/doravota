// Package pqcibc contains the compatibility boundary required by an IBC
// relayer when a CometBFT validator set contains ML-DSA-65 public keys.
//
// The package deliberately does not trust data merely because it came from an
// RPC endpoint. Callers must obtain LightBlocks through a verified CometBFT
// light provider. The returned 07-tendermint header is then checked again by
// the counterparty chain when MsgUpdateClient is executed.
package pqcibc

import (
	"fmt"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/gogoproto/proto"

	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"
	ibctm "github.com/cosmos/ibc-go/v11/modules/light-clients/07-tendermint"
)

const (
	// DefaultMaxValidators bounds validator-set decoding and signature checks in
	// relayer processes. A production deployment should lower this to the
	// governance-enforced validator-set maximum where possible.
	DefaultMaxValidators = 200
	// DefaultMaxHeaderBytes rejects unexpectedly large update messages before
	// transaction construction. It is intentionally below common gRPC message
	// defaults while leaving room for 200 ML-DSA-65 validators.
	DefaultMaxHeaderBytes = 4 * 1024 * 1024
)

// HeaderLimits are local relayer safety limits. They do not replace the
// consensus rules enforced by the destination chain.
type HeaderLimits struct {
	MaxValidators       int
	MaxCommitSignatures int
	MaxHeaderBytes      int
}

// DefaultHeaderLimits returns conservative limits suitable for preflight and
// relayer admission checks.
func DefaultHeaderLimits() HeaderLimits {
	return HeaderLimits{
		MaxValidators:       DefaultMaxValidators,
		MaxCommitSignatures: DefaultMaxValidators,
		MaxHeaderBytes:      DefaultMaxHeaderBytes,
	}
}

// HeaderStats records the wire and cryptographic shape of an update. Relayers
// can export these values as telemetry to observe growth during a staged
// validator-key rotation.
type HeaderStats struct {
	Height                   int64  `json:"height"`
	TrustedHeight            uint64 `json:"trusted_height"`
	HeaderBytes              int    `json:"header_bytes"`
	Validators               int    `json:"validators"`
	TrustedValidators        int    `json:"trusted_validators"`
	CommitSignatures         int    `json:"commit_signatures"`
	MLDSA65Validators        int    `json:"mldsa65_validators"`
	Ed25519Validators        int    `json:"ed25519_validators"`
	TrustedMLDSA65Validators int    `json:"trusted_mldsa65_validators"`
	TrustedEd25519Validators int    `json:"trusted_ed25519_validators"`
}

// BuildUpdateHeader converts verified CometBFT light-client material into the
// IBC 07-tendermint wire type. trustedValidators must be the validator set
// committed by the trusted consensus state (normally the source set at
// trustedHeight+1).
func BuildUpdateHeader(
	latest *cmttypes.LightBlock,
	trustedHeight clienttypes.Height,
	trustedValidators *cmttypes.ValidatorSet,
	limits HeaderLimits,
) (*ibctm.Header, HeaderStats, error) {
	if latest == nil || latest.SignedHeader == nil || latest.Header == nil {
		return nil, HeaderStats{}, fmt.Errorf("latest light block is incomplete")
	}
	if latest.ValidatorSet == nil {
		return nil, HeaderStats{}, fmt.Errorf("latest validator set is nil")
	}
	if trustedHeight.IsZero() {
		return nil, HeaderStats{}, fmt.Errorf("trusted height must be non-zero")
	}
	if trustedValidators == nil {
		return nil, HeaderStats{}, fmt.Errorf("trusted validator set is nil")
	}
	if err := latest.ValidateBasic(latest.ChainID); err != nil {
		return nil, HeaderStats{}, fmt.Errorf("invalid latest light block: %w", err)
	}
	if err := latest.ValidatorSet.VerifyCommitLight(
		latest.ChainID,
		latest.Commit.BlockID,
		latest.Height,
		latest.Commit,
	); err != nil {
		return nil, HeaderStats{}, fmt.Errorf("latest commit is not signed by two-thirds of the validator set: %w", err)
	}
	if err := trustedValidators.ValidateBasic(); err != nil {
		return nil, HeaderStats{}, fmt.Errorf("invalid trusted validator set: %w", err)
	}

	validatorSet, err := latest.ValidatorSet.ToProto()
	if err != nil {
		return nil, HeaderStats{}, fmt.Errorf("encode latest validator set: %w", err)
	}
	trustedSet, err := trustedValidators.ToProto()
	if err != nil {
		return nil, HeaderStats{}, fmt.Errorf("encode trusted validator set: %w", err)
	}

	header := &ibctm.Header{
		SignedHeader:      latest.SignedHeader.ToProto(),
		ValidatorSet:      validatorSet,
		TrustedHeight:     trustedHeight,
		TrustedValidators: trustedSet,
	}
	stats, err := ValidateUpdateHeader(header, limits)
	if err != nil {
		return nil, HeaderStats{}, err
	}
	return header, stats, nil
}

// ValidateUpdateHeader performs fail-closed structural, algorithm, size and
// commit checks before a relayer places the header in MsgUpdateClient.
func ValidateUpdateHeader(header *ibctm.Header, limits HeaderLimits) (HeaderStats, error) {
	limits = normalizeLimits(limits)
	if header == nil {
		return HeaderStats{}, fmt.Errorf("update header is nil")
	}
	if header.TrustedHeight.IsZero() {
		return HeaderStats{}, fmt.Errorf("trusted height must be non-zero")
	}
	if header.TrustedValidators == nil {
		return HeaderStats{}, fmt.Errorf("trusted validator set is nil")
	}
	if err := header.ValidateBasic(); err != nil {
		return HeaderStats{}, fmt.Errorf("invalid 07-tendermint header: %w", err)
	}

	validatorSet, err := cmttypes.ValidatorSetFromProto(header.ValidatorSet)
	if err != nil {
		return HeaderStats{}, fmt.Errorf("decode latest validator set: %w", err)
	}
	trustedSet, err := cmttypes.ValidatorSetFromProto(header.TrustedValidators)
	if err != nil {
		return HeaderStats{}, fmt.Errorf("decode trusted validator set: %w", err)
	}
	signedHeader, err := cmttypes.SignedHeaderFromProto(header.SignedHeader)
	if err != nil {
		return HeaderStats{}, fmt.Errorf("decode signed header: %w", err)
	}

	if len(validatorSet.Validators) > limits.MaxValidators {
		return HeaderStats{}, fmt.Errorf("validator count %d exceeds relayer limit %d", len(validatorSet.Validators), limits.MaxValidators)
	}
	if len(trustedSet.Validators) > limits.MaxValidators {
		return HeaderStats{}, fmt.Errorf("trusted validator count %d exceeds relayer limit %d", len(trustedSet.Validators), limits.MaxValidators)
	}
	if len(signedHeader.Commit.Signatures) > limits.MaxCommitSignatures {
		return HeaderStats{}, fmt.Errorf("commit signature count %d exceeds relayer limit %d", len(signedHeader.Commit.Signatures), limits.MaxCommitSignatures)
	}

	latestMLDSA, latestEd, err := countSupportedAlgorithms(validatorSet)
	if err != nil {
		return HeaderStats{}, err
	}
	trustedMLDSA, trustedEd, err := countSupportedAlgorithms(trustedSet)
	if err != nil {
		return HeaderStats{}, fmt.Errorf("trusted validator set: %w", err)
	}
	if err := validatorSet.VerifyCommitLight(
		signedHeader.ChainID,
		signedHeader.Commit.BlockID,
		signedHeader.Height,
		signedHeader.Commit,
	); err != nil {
		return HeaderStats{}, fmt.Errorf("invalid latest commit signatures: %w", err)
	}

	wireBytes := proto.Size(header)
	if wireBytes > limits.MaxHeaderBytes {
		return HeaderStats{}, fmt.Errorf("update header size %d exceeds relayer limit %d", wireBytes, limits.MaxHeaderBytes)
	}

	return HeaderStats{
		Height:                   signedHeader.Height,
		TrustedHeight:            header.TrustedHeight.RevisionHeight,
		HeaderBytes:              wireBytes,
		Validators:               len(validatorSet.Validators),
		TrustedValidators:        len(trustedSet.Validators),
		CommitSignatures:         len(signedHeader.Commit.Signatures),
		MLDSA65Validators:        latestMLDSA,
		Ed25519Validators:        latestEd,
		TrustedMLDSA65Validators: trustedMLDSA,
		TrustedEd25519Validators: trustedEd,
	}, nil
}

// InspectLightBlock validates a CometBFT light block and reports its ML-DSA
// composition. It is useful for RPC preflight before an IBC update is built.
// It verifies the block's own commit but does not establish trust in the RPC
// endpoint; production relaying must still use a verified light provider.
func InspectLightBlock(lightBlock *cmttypes.LightBlock, limits HeaderLimits) (HeaderStats, error) {
	limits = normalizeLimits(limits)
	if lightBlock == nil || lightBlock.SignedHeader == nil || lightBlock.Header == nil || lightBlock.ValidatorSet == nil {
		return HeaderStats{}, fmt.Errorf("light block is incomplete")
	}
	if err := lightBlock.ValidateBasic(lightBlock.ChainID); err != nil {
		return HeaderStats{}, fmt.Errorf("invalid light block: %w", err)
	}
	if len(lightBlock.ValidatorSet.Validators) > limits.MaxValidators {
		return HeaderStats{}, fmt.Errorf("validator count %d exceeds relayer limit %d", len(lightBlock.ValidatorSet.Validators), limits.MaxValidators)
	}
	if len(lightBlock.Commit.Signatures) > limits.MaxCommitSignatures {
		return HeaderStats{}, fmt.Errorf("commit signature count %d exceeds relayer limit %d", len(lightBlock.Commit.Signatures), limits.MaxCommitSignatures)
	}
	mldsa, ed, err := countSupportedAlgorithms(lightBlock.ValidatorSet)
	if err != nil {
		return HeaderStats{}, err
	}
	if err := lightBlock.ValidatorSet.VerifyCommitLight(
		lightBlock.ChainID,
		lightBlock.Commit.BlockID,
		lightBlock.Height,
		lightBlock.Commit,
	); err != nil {
		return HeaderStats{}, fmt.Errorf("invalid light block commit signatures: %w", err)
	}
	protoBlock, err := lightBlock.ToProto()
	if err != nil {
		return HeaderStats{}, fmt.Errorf("encode light block: %w", err)
	}
	wireBytes := proto.Size(protoBlock)
	if wireBytes > limits.MaxHeaderBytes {
		return HeaderStats{}, fmt.Errorf("light block size %d exceeds relayer limit %d", wireBytes, limits.MaxHeaderBytes)
	}
	return HeaderStats{
		Height:            lightBlock.Height,
		HeaderBytes:       wireBytes,
		Validators:        len(lightBlock.ValidatorSet.Validators),
		CommitSignatures:  len(lightBlock.Commit.Signatures),
		MLDSA65Validators: mldsa,
		Ed25519Validators: ed,
	}, nil
}

// MarshalUpdateHeader performs a protobuf round trip after validation. This is
// the exact boundary that older relayers fail at because their CometBFT proto
// does not contain the ML-DSA-65 public-key oneof.
func MarshalUpdateHeader(header *ibctm.Header, limits HeaderLimits) ([]byte, error) {
	if _, err := ValidateUpdateHeader(header, limits); err != nil {
		return nil, err
	}
	bz, err := proto.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshal update header: %w", err)
	}
	var roundTrip ibctm.Header
	if err := proto.Unmarshal(bz, &roundTrip); err != nil {
		return nil, fmt.Errorf("unmarshal update header: %w", err)
	}
	if _, err := ValidateUpdateHeader(&roundTrip, limits); err != nil {
		return nil, fmt.Errorf("validate round-tripped update header: %w", err)
	}
	return bz, nil
}

func countSupportedAlgorithms(set *cmttypes.ValidatorSet) (mldsa, ed25519 int, err error) {
	for _, validator := range set.Validators {
		if validator == nil || validator.PubKey == nil {
			return 0, 0, fmt.Errorf("validator has no public key")
		}
		switch validator.PubKey.Type() {
		case cmtmldsa65.KeyType:
			mldsa++
		case cmted25519.KeyType:
			ed25519++
		default:
			return 0, 0, fmt.Errorf("unsupported validator public key type %q", validator.PubKey.Type())
		}
	}
	return mldsa, ed25519, nil
}

func normalizeLimits(limits HeaderLimits) HeaderLimits {
	defaults := DefaultHeaderLimits()
	if limits.MaxValidators <= 0 {
		limits.MaxValidators = defaults.MaxValidators
	}
	if limits.MaxCommitSignatures <= 0 {
		limits.MaxCommitSignatures = defaults.MaxCommitSignatures
	}
	if limits.MaxHeaderBytes <= 0 {
		limits.MaxHeaderBytes = defaults.MaxHeaderBytes
	}
	return limits
}
