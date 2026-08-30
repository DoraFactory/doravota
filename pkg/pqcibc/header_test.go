package pqcibc_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtprotoversion "github.com/cometbft/cometbft/proto/tendermint/version"
	cmttypes "github.com/cometbft/cometbft/types"
	cmtversion "github.com/cometbft/cometbft/version"
	"github.com/stretchr/testify/require"

	clienttypes "github.com/cosmos/ibc-go/v11/modules/core/02-client/types"

	"github.com/DoraFactory/doravota/pkg/pqcibc"
)

func TestMLDSA65UpdateHeaderRoundTrip(t *testing.T) {
	trusted := newLightBlock(t, "pqc-ibc-1", 10, false)
	latest := newLightBlock(t, "pqc-ibc-1", 12, true)

	header, stats, err := pqcibc.BuildUpdateHeader(
		latest,
		clienttypes.NewHeight(1, 10),
		trusted.ValidatorSet,
		pqcibc.DefaultHeaderLimits(),
	)
	require.NoError(t, err)
	require.Equal(t, 4, stats.MLDSA65Validators)
	require.Equal(t, 4, stats.TrustedEd25519Validators)
	require.Zero(t, stats.Ed25519Validators)
	require.Greater(t, stats.HeaderBytes, 10_000)

	wire, err := pqcibc.MarshalUpdateHeader(header, pqcibc.DefaultHeaderLimits())
	require.NoError(t, err)
	require.Len(t, wire, stats.HeaderBytes)
}

func TestUpdateHeaderLimitsFailClosed(t *testing.T) {
	trusted := newLightBlock(t, "pqc-ibc-1", 10, false)
	latest := newLightBlock(t, "pqc-ibc-1", 11, true)

	_, _, err := pqcibc.BuildUpdateHeader(
		latest,
		clienttypes.NewHeight(1, 10),
		trusted.ValidatorSet,
		pqcibc.HeaderLimits{MaxValidators: 3, MaxCommitSignatures: 4, MaxHeaderBytes: 1 << 20},
	)
	require.ErrorContains(t, err, "validator count")

	_, _, err = pqcibc.BuildUpdateHeader(
		latest,
		clienttypes.NewHeight(1, 10),
		trusted.ValidatorSet,
		pqcibc.HeaderLimits{MaxValidators: 4, MaxCommitSignatures: 4, MaxHeaderBytes: 1024},
	)
	require.ErrorContains(t, err, "header size")
}

func TestBuildUpdateHeaderRejectsTamperedMLDSA65Commit(t *testing.T) {
	trusted := newLightBlock(t, "pqc-ibc-1", 10, false)
	latest := newLightBlock(t, "pqc-ibc-1", 11, true)
	require.NotEmpty(t, latest.Commit.Signatures)
	require.NotEmpty(t, latest.Commit.Signatures[0].Signature)
	latest.Commit.Signatures[0].Signature[0] ^= 0xff

	_, _, err := pqcibc.BuildUpdateHeader(
		latest,
		clienttypes.NewHeight(1, 10),
		trusted.ValidatorSet,
		pqcibc.DefaultHeaderLimits(),
	)
	require.ErrorContains(t, err, "latest commit is not signed by two-thirds")
}

func TestBuildUpdateHeaderFromVerifiedSourceUsesTrustedHeightPlusOne(t *testing.T) {
	source := &recordingLightSource{blocks: map[int64]*cmttypes.LightBlock{
		11: newLightBlock(t, "pqc-ibc-1", 11, false),
		20: newLightBlock(t, "pqc-ibc-1", 20, true),
	}}
	header, stats, err := pqcibc.BuildUpdateHeaderFromSource(
		context.Background(),
		source,
		20,
		clienttypes.NewHeight(1, 10),
		pqcibc.DefaultHeaderLimits(),
	)
	require.NoError(t, err)
	require.Equal(t, []int64{20, 11}, source.calls)
	require.Equal(t, int64(20), header.Header.Height)
	require.Equal(t, 4, stats.MLDSA65Validators)
}

func TestBuildUpdateHeaderFromSourceRejectsWrongHeight(t *testing.T) {
	source := &recordingLightSource{blocks: map[int64]*cmttypes.LightBlock{
		20: newLightBlock(t, "pqc-ibc-1", 19, true),
	}}
	_, _, err := pqcibc.BuildUpdateHeaderFromSource(
		context.Background(),
		source,
		20,
		clienttypes.NewHeight(1, 10),
		pqcibc.DefaultHeaderLimits(),
	)
	require.ErrorContains(t, err, "unexpected target height")
}

type recordingLightSource struct {
	blocks map[int64]*cmttypes.LightBlock
	calls  []int64
}

func (source *recordingLightSource) LightBlock(_ context.Context, height int64) (*cmttypes.LightBlock, error) {
	source.calls = append(source.calls, height)
	block, found := source.blocks[height]
	if !found {
		return nil, fmt.Errorf("missing height %d", height)
	}
	return block, nil
}

func newLightBlock(t *testing.T, chainID string, height int64, postQuantum bool) *cmttypes.LightBlock {
	t.Helper()
	validators := make([]*cmttypes.Validator, 0, 4)
	signers := make(map[string]cmttypes.PrivValidator, 4)
	for range 4 {
		var mock cmttypes.MockPV
		if postQuantum {
			key, err := cmtmldsa65.GenPrivKey()
			require.NoError(t, err)
			mock = cmttypes.NewMockPVWithParams(key, false, false)
		} else {
			mock = cmttypes.NewMockPVWithParams(cmted25519.GenPrivKey(), false, false)
		}
		publicKey, err := mock.GetPubKey()
		require.NoError(t, err)
		validators = append(validators, cmttypes.NewValidator(publicKey, 1))
		signers[publicKey.Address().String()] = mock
	}
	validatorSet := cmttypes.NewValidatorSet(validators)
	hash := tmhash.Sum([]byte("pqc-ibc-test"))
	header := cmttypes.Header{
		Version:            cmtprotoversion.Consensus{Block: cmtversion.BlockProtocol, App: 2},
		ChainID:            chainID,
		Height:             height,
		Time:               time.Unix(1_800_000_000+height, 0).UTC(),
		LastBlockID:        makeBlockID(hash, 1, hash),
		LastCommitHash:     hash,
		DataHash:           hash,
		ValidatorsHash:     validatorSet.Hash(),
		NextValidatorsHash: validatorSet.Hash(),
		ConsensusHash:      hash,
		AppHash:            hash,
		LastResultsHash:    hash,
		EvidenceHash:       hash,
		ProposerAddress:    validatorSet.Proposer.Address,
	}
	signedProto, err := commitHeader(header, validatorSet, signers)
	require.NoError(t, err)
	signedHeader, err := cmttypes.SignedHeaderFromProto(signedProto)
	require.NoError(t, err)
	require.Equal(t, cmtproto.BlockIDFlagCommit, signedProto.Commit.Signatures[0].BlockIdFlag)
	return &cmttypes.LightBlock{SignedHeader: signedHeader, ValidatorSet: validatorSet}
}

func commitHeader(
	header cmttypes.Header,
	validatorSet *cmttypes.ValidatorSet,
	signers map[string]cmttypes.PrivValidator,
) (*cmtproto.SignedHeader, error) {
	blockID := makeBlockID(header.Hash(), 3, tmhash.Sum([]byte("parts")))
	voteSet := cmttypes.NewVoteSet(header.ChainID, header.Height, 1, cmtproto.PrecommitType, validatorSet)
	signerArray := make([]cmttypes.PrivValidator, len(validatorSet.Validators))
	for index, validator := range validatorSet.Validators {
		signerArray[index] = signers[validator.Address.String()]
	}
	extendedCommit, err := cmttypes.MakeExtCommit(
		blockID,
		header.Height,
		1,
		voteSet,
		signerArray,
		header.Time,
		false,
	)
	if err != nil {
		return nil, err
	}
	return &cmtproto.SignedHeader{
		Header: header.ToProto(),
		Commit: extendedCommit.ToCommit().ToProto(),
	}, nil
}

func makeBlockID(hash []byte, partSetSize uint32, partSetHash []byte) cmttypes.BlockID {
	return cmttypes.BlockID{
		Hash: hash,
		PartSetHeader: cmttypes.PartSetHeader{
			Total: partSetSize,
			Hash:  partSetHash,
		},
	}
}
