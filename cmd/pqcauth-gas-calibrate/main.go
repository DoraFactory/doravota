// pqcauth-gas-calibrate measures ML-DSA-65 verification latency on validator
// target hardware and derives a conservative pqcauth gas recommendation. It is
// an operator calibration aid, not consensus code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type latencyReport struct {
	P50NS uint64 `json:"p50_ns"`
	P95NS uint64 `json:"p95_ns"`
	P99NS uint64 `json:"p99_ns"`
	MaxNS uint64 `json:"max_ns"`
}

type calibrationReport struct {
	GeneratedAt               string        `json:"generated_at"`
	GoVersion                 string        `json:"go_version"`
	GOOS                      string        `json:"goos"`
	GOARCH                    string        `json:"goarch"`
	GOMAXPROCS                int           `json:"gomaxprocs"`
	Samples                   int           `json:"samples"`
	MessageBytes              int           `json:"message_bytes"`
	Valid                     latencyReport `json:"valid_signature"`
	Invalid                   latencyReport `json:"invalid_signature"`
	WorstP99NS                uint64        `json:"worst_p99_ns"`
	BlockMaxGas               uint64        `json:"block_max_gas"`
	BlockTime                 string        `json:"block_time"`
	PQCCPUBudgetFraction      float64       `json:"pqc_cpu_budget_fraction"`
	SafetyFactor              float64       `json:"safety_factor"`
	SafeVerificationsPerBlock uint64        `json:"safe_verifications_per_block"`
	RawRecommendedGas         uint64        `json:"raw_recommended_gas_per_verification"`
	ProtocolMinimumGas        uint64        `json:"protocol_minimum_gas_per_verification"`
	RecommendedGas            uint64        `json:"recommended_gas_per_verification"`
	ExceedsProtocolMaximum    bool          `json:"exceeds_protocol_maximum"`
	ProtocolMaximumGas        uint64        `json:"protocol_maximum_gas_per_verification"`
}

func main() {
	samples := flag.Int("samples", 20_000, "number of valid and invalid verification samples")
	messageBytes := flag.Int("message-bytes", 4*1024, "representative PQC sign-document size")
	blockMaxGas := flag.Uint64("block-max-gas", 100_000_000, "consensus maximum gas per block")
	blockTime := flag.Duration("block-time", 5*time.Second, "target block interval")
	cpuBudget := flag.Float64("pqc-cpu-budget", 0.25, "fraction of one block interval available to PQC verification")
	safetyFactor := flag.Float64("safety-factor", 2.0, "multiplier applied to p99 verification latency")
	flag.Parse()

	if *samples < 100 || *messageBytes <= 0 || *blockMaxGas == 0 || *blockTime <= 0 ||
		*cpuBudget <= 0 || *cpuBudget > 1 || *safetyFactor < 1 {
		fatalf("invalid calibration arguments")
	}

	publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
	if err != nil {
		fatalf("generate ML-DSA-65 key: %v", err)
	}
	message := make([]byte, *messageBytes)
	for index := range message {
		message[index] = byte(index)
	}
	contextBytes := []byte(types.TxSignatureContext)
	signature, err := pqccrypto.SignMLDSA65(privateKey, message, contextBytes, false)
	if err != nil {
		fatalf("sign calibration message: %v", err)
	}
	invalidSignature := append([]byte(nil), signature...)
	invalidSignature[len(invalidSignature)/2] ^= 0x80

	for range 1_000 {
		if err := pqccrypto.Verify(
			pqccrypto.AlgorithmMLDSA65,
			publicKey,
			message,
			contextBytes,
			signature,
		); err != nil {
			fatalf("warmup verification: %v", err)
		}
	}

	valid := measure(*samples, func() error {
		return pqccrypto.Verify(
			pqccrypto.AlgorithmMLDSA65,
			publicKey,
			message,
			contextBytes,
			signature,
		)
	}, false)
	invalid := measure(*samples, func() error {
		return pqccrypto.Verify(
			pqccrypto.AlgorithmMLDSA65,
			publicKey,
			message,
			contextBytes,
			invalidSignature,
		)
	}, true)

	worstP99 := max(valid.P99NS, invalid.P99NS)
	budgetNS := uint64(float64(blockTime.Nanoseconds()) * *cpuBudget)
	adjustedP99 := uint64(float64(worstP99) * *safetyFactor)
	if adjustedP99 == 0 {
		adjustedP99 = 1
	}
	safeVerifications := budgetNS / adjustedP99
	if safeVerifications == 0 {
		safeVerifications = 1
	}
	rawGas := ceilDiv(*blockMaxGas, safeVerifications)
	recommended := max(rawGas, types.MinimumSignatureVerificationGas)

	report := calibrationReport{
		GeneratedAt:               time.Now().UTC().Format(time.RFC3339),
		GoVersion:                 runtime.Version(),
		GOOS:                      runtime.GOOS,
		GOARCH:                    runtime.GOARCH,
		GOMAXPROCS:                runtime.GOMAXPROCS(0),
		Samples:                   *samples,
		MessageBytes:              *messageBytes,
		Valid:                     valid,
		Invalid:                   invalid,
		WorstP99NS:                worstP99,
		BlockMaxGas:               *blockMaxGas,
		BlockTime:                 blockTime.String(),
		PQCCPUBudgetFraction:      *cpuBudget,
		SafetyFactor:              *safetyFactor,
		SafeVerificationsPerBlock: safeVerifications,
		RawRecommendedGas:         rawGas,
		ProtocolMinimumGas:        types.MinimumSignatureVerificationGas,
		RecommendedGas:            recommended,
		ExceedsProtocolMaximum:    recommended > types.AbsoluteMaxVerificationGas,
		ProtocolMaximumGas:        types.AbsoluteMaxVerificationGas,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fatalf("encode calibration report: %v", err)
	}
}

func measure(samples int, verify func() error, expectError bool) latencyReport {
	latencies := make([]uint64, samples)
	for index := range samples {
		started := time.Now()
		err := verify()
		latencies[index] = uint64(time.Since(started).Nanoseconds())
		if (err != nil) != expectError {
			fatalf("unexpected verification result at sample %d: %v", index, err)
		}
	}
	sort.Slice(latencies, func(left, right int) bool {
		return latencies[left] < latencies[right]
	})
	return latencyReport{
		P50NS: percentile(latencies, 50),
		P95NS: percentile(latencies, 95),
		P99NS: percentile(latencies, 99),
		MaxNS: latencies[len(latencies)-1],
	}
}

func percentile(sorted []uint64, percentile uint64) uint64 {
	index := ceilDiv(uint64(len(sorted))*percentile, 100)
	if index == 0 {
		return sorted[0]
	}
	return sorted[index-1]
}

func ceilDiv(numerator, denominator uint64) uint64 {
	return numerator/denominator + boolToUint64(numerator%denominator != 0)
}

func boolToUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
