package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/DoraFactory/doravota/pkg/pqcibc"
)

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:26657", "CometBFT 0.40 RPC endpoint")
	height := flag.Int64("height", 0, "height to inspect; zero selects the latest committed height")
	maxValidators := flag.Int("max-validators", pqcibc.DefaultMaxValidators, "maximum accepted validator count")
	maxHeaderBytes := flag.Int("max-header-bytes", pqcibc.DefaultMaxHeaderBytes, "maximum accepted encoded light-block bytes")
	requireMLDSA := flag.Bool("require-mldsa", false, "fail unless at least one validator uses ML-DSA-65")
	timeout := flag.Duration("timeout", 15*time.Second, "RPC request timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client, err := rpchttp.New(*rpcURL, "/websocket")
	failIf(err)
	if *height == 0 {
		status, statusErr := client.Status(ctx)
		failIf(statusErr)
		*height = status.SyncInfo.LatestBlockHeight
	}
	if *height <= 0 {
		failIf(fmt.Errorf("height must be positive"))
	}

	commit, err := client.Commit(ctx, height)
	failIf(err)
	validators, err := fetchValidators(ctx, client, *height, *maxValidators)
	failIf(err)

	lightBlock := &cmttypes.LightBlock{
		SignedHeader: &commit.SignedHeader,
		ValidatorSet: cmttypes.NewValidatorSet(validators),
	}
	stats, err := pqcibc.InspectLightBlock(lightBlock, pqcibc.HeaderLimits{
		MaxValidators:       *maxValidators,
		MaxCommitSignatures: *maxValidators,
		MaxHeaderBytes:      *maxHeaderBytes,
	})
	failIf(err)
	if *requireMLDSA && stats.MLDSA65Validators == 0 {
		failIf(fmt.Errorf("height %d contains no ML-DSA-65 validator", *height))
	}

	result := struct {
		RPC     string             `json:"rpc"`
		ChainID string             `json:"chain_id"`
		Trusted bool               `json:"trusted"`
		Warning string             `json:"warning"`
		Stats   pqcibc.HeaderStats `json:"stats"`
	}{
		RPC:     *rpcURL,
		ChainID: lightBlock.ChainID,
		Trusted: false,
		Warning: "RPC preflight verifies the block's own commit but is not a trust anchor; production relaying must use a verified CometBFT light provider",
		Stats:   stats,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	failIf(encoder.Encode(result))
}

// Keeping pagination explicit is important: a single default RPC page would
// silently construct an invalid IBC header on a larger validator set.
func fetchValidators(ctx context.Context, client *rpchttp.HTTP, height int64, maximum int) ([]*cmttypes.Validator, error) {
	validators := make([]*cmttypes.Validator, 0)
	for page := 1; ; page++ {
		perPage := 100
		result, err := client.Validators(ctx, &height, &page, &perPage)
		if err != nil {
			return nil, err
		}
		validators = append(validators, result.Validators...)
		if len(validators) > maximum {
			return nil, fmt.Errorf("validator count exceeds configured maximum %d", maximum)
		}
		if len(validators) >= result.Total {
			break
		}
		if len(result.Validators) == 0 {
			return nil, fmt.Errorf("validator RPC pagination made no progress at page %d", page)
		}
	}
	return validators, nil
}

func failIf(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "pqcibc-preflight:", err)
	os.Exit(1)
}
