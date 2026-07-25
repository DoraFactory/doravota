package app

import (
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
)

func TestWasmSizeLimitsInitialized(t *testing.T) {
	const expectedMaxWasmSize = 3 * 1024 * 1024

	if wasmtypes.MaxWasmSize != expectedMaxWasmSize {
		t.Fatalf("MaxWasmSize = %d, want %d", wasmtypes.MaxWasmSize, expectedMaxWasmSize)
	}
	if wasmtypes.MaxProposalWasmSize != expectedMaxWasmSize {
		t.Fatalf("MaxProposalWasmSize = %d, want %d", wasmtypes.MaxProposalWasmSize, expectedMaxWasmSize)
	}
}
