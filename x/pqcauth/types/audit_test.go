package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditGenesisStateAcceptsConsistentLiveState(t *testing.T) {
	report := AuditGenesisState(validGenesisForTest(t), 10, true, 100)
	require.True(t, report.Consistent)
	require.Zero(t, report.TotalIssues)
	require.Equal(t, uint64(2), report.Keys)
	require.Equal(t, uint64(1), report.Policies)
	require.Equal(t, uint64(1), report.KeySequences)
	require.NoError(t, report.Error())
}

func TestAuditGenesisStateRequiresSequenceOnlyForLiveState(t *testing.T) {
	genesis := validGenesisForTest(t)
	genesis.KeySequences = nil

	importReport := AuditGenesisState(genesis, 10, false, 100)
	require.True(t, importReport.Consistent)

	liveReport := AuditGenesisState(genesis, 10, true, 100)
	require.False(t, liveReport.Consistent)
	require.Equal(t, "missing_key_sequence", liveReport.Issues[0].Code)
	require.ErrorIs(t, liveReport.Error(), ErrInconsistentState)
}

func TestAuditGenesisStateFindsUnreferencedEffectiveAndInvalidHeightKeys(t *testing.T) {
	genesis := validGenesisForTest(t)
	extra := genesis.Keys[0]
	extra.KeyId = 3
	extra.CreatedHeight = 5
	extra.EffectiveHeight = 4
	extra.PublicKey = bytes.Repeat([]byte{0x33}, len(extra.PublicKey))
	genesis.Keys = append(genesis.Keys, extra)
	genesis.KeySequences[0].NextKeyId = 4

	report := AuditGenesisState(genesis, 10, true, 100)
	require.False(t, report.Consistent)
	codes := make(map[string]bool)
	for _, issue := range report.Issues {
		codes[issue.Code] = true
	}
	require.True(t, codes["invalid_key_height_order"])
	require.True(t, codes["unreferenced_active_signing_key"])
}

func TestStateAuditReportTruncatesDetailsButRetainsTotal(t *testing.T) {
	report := NewStateAuditReport(1)
	for i := 0; i < 5; i++ {
		report.AddIssue(2, "broken", "", "detail")
	}
	require.False(t, report.Consistent)
	require.Equal(t, uint64(5), report.TotalIssues)
	require.Len(t, report.Issues, 2)
	require.True(t, report.IssuesTruncated)
}
