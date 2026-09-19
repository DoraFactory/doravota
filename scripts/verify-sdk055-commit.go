//go:build ignore

// Verify the public RPC artifacts produced by smoke-sdk055-native.py.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
)

func main() {
	for _, path := range os.Args[1:] {
		if err := verify(path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
func verify(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var artifact struct {
		ChainID    string          `json:"chain_id"`
		Commit     json.RawMessage `json:"commit"`
		Validators json.RawMessage `json:"validators"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return err
	}
	var signed coretypes.ResultCommit
	var validators coretypes.ResultValidators
	if err := cmtjson.Unmarshal(artifact.Commit, &signed); err != nil {
		return err
	}
	if err := cmtjson.Unmarshal(artifact.Validators, &validators); err != nil {
		return err
	}
	set := cmttypes.NewValidatorSet(validators.Validators)
	commit := signed.SignedHeader.Commit
	if err := signed.SignedHeader.ValidateBasic(artifact.ChainID); err != nil {
		return err
	}
	if err := set.VerifyCommitLight(artifact.ChainID, commit.BlockID, commit.Height, commit); err != nil {
		return err
	}
	// Negative control: reject a corrupted real commit, not only synthetic bytes.
	for i := range commit.Signatures {
		if len(commit.Signatures[i].Signature) > 0 {
			commit.Signatures[i].Signature[0] ^= 1
			break
		}
	}
	if err := set.VerifyCommitLight(artifact.ChainID, commit.BlockID, commit.Height, commit); err == nil {
		return fmt.Errorf("%s: corrupted commit was accepted", path)
	}
	fmt.Printf("%s: real commit verified; corrupted signature rejected\n", artifact.ChainID)
	return nil
}
