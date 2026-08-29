package types

import (
	"fmt"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	DefaultStateAuditMaxIssues  = 100
	AbsoluteStateAuditMaxIssues = 1_000
)

// StateAuditIssue is one deterministic state-consistency finding. Code is
// stable enough for operator automation; Detail is intended for humans.
type StateAuditIssue struct {
	Code   string `json:"code"`
	Owner  string `json:"owner,omitempty"`
	Detail string `json:"detail"`
}

// StateAuditReport is shared by the live-store invariant and the offline
// exported-state auditor. Counts always describe every record inspected, even
// when the issue list is truncated.
type StateAuditReport struct {
	Consistent      bool              `json:"consistent"`
	Height          int64             `json:"height"`
	Keys            uint64            `json:"keys"`
	Policies        uint64            `json:"policies"`
	KeySequences    uint64            `json:"key_sequences"`
	KeyHistories    uint64            `json:"key_histories"`
	TotalIssues     uint64            `json:"total_issues"`
	IssuesTruncated bool              `json:"issues_truncated"`
	Issues          []StateAuditIssue `json:"issues"`
}

func NewStateAuditReport(height int64) StateAuditReport {
	return StateAuditReport{
		Consistent: true,
		Height:     height,
		Issues:     make([]StateAuditIssue, 0),
	}
}

func NormalizeStateAuditMaxIssues(maxIssues uint32) uint32 {
	if maxIssues == 0 {
		return DefaultStateAuditMaxIssues
	}
	if maxIssues > AbsoluteStateAuditMaxIssues {
		return AbsoluteStateAuditMaxIssues
	}
	return maxIssues
}

func (r *StateAuditReport) AddIssue(maxIssues uint32, code, owner, detail string) {
	r.Consistent = false
	r.TotalIssues++
	if uint32(len(r.Issues)) >= NormalizeStateAuditMaxIssues(maxIssues) {
		r.IssuesTruncated = true
		return
	}
	r.Issues = append(r.Issues, StateAuditIssue{
		Code:   code,
		Owner:  owner,
		Detail: detail,
	})
}

func (r *StateAuditReport) MergeIssues(maxIssues uint32, other StateAuditReport) {
	if other.Consistent {
		return
	}
	for _, issue := range other.Issues {
		r.AddIssue(maxIssues, issue.Code, issue.Owner, issue.Detail)
	}
	missing := other.TotalIssues - uint64(len(other.Issues))
	if missing != 0 {
		r.Consistent = false
		r.TotalIssues += missing
		r.IssuesTruncated = true
	}
}

func (r StateAuditReport) Error() error {
	if r.Consistent {
		return nil
	}
	if len(r.Issues) == 0 {
		return fmt.Errorf("%w: %d state audit issues", ErrInconsistentState, r.TotalIssues)
	}
	first := r.Issues[0]
	if first.Owner == "" {
		return fmt.Errorf("%w: %s: %s", ErrInconsistentState, first.Code, first.Detail)
	}
	return fmt.Errorf(
		"%w: %s for %s: %s",
		ErrInconsistentState,
		first.Code,
		first.Owner,
		first.Detail,
	)
}

// AuditGenesisState validates an in-memory module snapshot without mutating
// it. requireLiveSequences is false for importable genesis (InitGenesis can
// derive a missing sequence) and true for committed live state.
func AuditGenesisState(
	genesis GenesisState,
	height int64,
	requireLiveSequences bool,
	maxIssues uint32,
) StateAuditReport {
	report := NewStateAuditReport(height)
	report.Keys = uint64(len(genesis.Keys))
	report.Policies = uint64(len(genesis.Policies))
	report.KeySequences = uint64(len(genesis.KeySequences))
	report.KeyHistories = uint64(len(genesis.KeyHistories))

	validationParams := genesis.Params
	if err := validationParams.Validate(); err != nil {
		report.AddIssue(maxIssues, "invalid_params", "", err.Error())
		validationParams = DefaultParams()
	}

	type ownerState struct {
		keys      []PQCKeyRecord
		policies  []AccountPolicy
		sequences []AccountKeySequence
		histories []AccountKeyHistory
	}
	owners := make(map[string]*ownerState)
	stateFor := func(owner string) *ownerState {
		state := owners[owner]
		if state == nil {
			state = &ownerState{}
			owners[owner] = state
		}
		return state
	}
	for _, key := range genesis.Keys {
		stateFor(key.Owner).keys = append(stateFor(key.Owner).keys, key)
	}
	for _, policy := range genesis.Policies {
		stateFor(policy.Owner).policies = append(stateFor(policy.Owner).policies, policy)
	}
	for _, sequence := range genesis.KeySequences {
		stateFor(sequence.Owner).sequences = append(stateFor(sequence.Owner).sequences, sequence)
	}
	for _, history := range genesis.KeyHistories {
		stateFor(history.Owner).histories = append(stateFor(history.Owner).histories, history)
	}

	orderedOwners := make([]string, 0, len(owners))
	for owner := range owners {
		orderedOwners = append(orderedOwners, owner)
	}
	sort.Strings(orderedOwners)
	for _, owner := range orderedOwners {
		state := owners[owner]
		snapshot := GenesisState{
			Params:       validationParams,
			Keys:         state.keys,
			Policies:     state.policies,
			KeySequences: state.sequences,
			KeyHistories: state.histories,
		}
		if err := ValidateGenesis(snapshot); err != nil {
			report.AddIssue(maxIssues, "invalid_owner_state", owner, err.Error())
			continue
		}
		if !requireLiveSequences {
			continue
		}
		if len(state.policies) != 1 {
			if len(state.policies) == 0 {
				report.AddIssue(maxIssues, "missing_policy", owner, "state records exist without an account policy")
			}
			continue
		}
		if len(state.sequences) != 1 {
			if len(state.sequences) == 0 {
				report.AddIssue(maxIssues, "missing_key_sequence", owner, "live account state has no key sequence")
			}
			continue
		}
		auditEffectiveOwnerState(&report, maxIssues, owner, height, state.keys, state.policies[0])
	}
	return report
}

func auditEffectiveOwnerState(
	report *StateAuditReport,
	maxIssues uint32,
	owner string,
	height int64,
	keys []PQCKeyRecord,
	policy AccountPolicy,
) {
	address, err := sdk.AccAddressFromBech32(owner)
	if err != nil || address.String() != owner {
		return // ValidateGenesis already emitted the canonical-address issue.
	}
	effective := policy.Effective(height)
	for _, key := range keys {
		if key.CreatedHeight > key.EffectiveHeight {
			report.AddIssue(
				maxIssues,
				"invalid_key_height_order",
				owner,
				fmt.Sprintf("key %d is effective before it was created", key.KeyId),
			)
		}
		if !key.IsEffective(height) {
			continue
		}
		switch key.Role {
		case KeyRole_KEY_ROLE_SIGNING:
			if key.KeyId != effective.CurrentSigningKeyId {
				report.AddIssue(
					maxIssues,
					"unreferenced_active_signing_key",
					owner,
					fmt.Sprintf("effective signing key %d is not the current policy key", key.KeyId),
				)
			}
		case KeyRole_KEY_ROLE_RECOVERY:
			if key.KeyId != effective.RecoveryKeyId {
				report.AddIssue(
					maxIssues,
					"unreferenced_active_recovery_key",
					owner,
					fmt.Sprintf("effective recovery key %d is not the current policy key", key.KeyId),
				)
			}
		}
	}
}
