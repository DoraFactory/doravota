package types

import (
	"time"

	"github.com/cosmos/cosmos-sdk/telemetry"
)

const (
	VerificationKindTransaction = "transaction_signature"
	VerificationKindKeyProof    = "key_proof"
	VerificationKindRecovery    = "recovery_signature"
)

// RecordVerification records only fixed-cardinality metadata. Addresses, key
// identifiers, and signature material must never become metric labels.
func RecordVerification(start time.Time, kind string, err error) {
	telemetry.ModuleMeasureSince(ModuleName, start, "pqc_verify", kind)
	result := "success"
	if err != nil {
		result = "failure"
	}
	telemetry.IncrCounter(1, ModuleName, "pqc_verify", kind, result)
}
