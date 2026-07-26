package app

import (
	"math"

	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// These consensus fallbacks keep proposal validation bounded even on legacy
	// networks whose on-chain block limits are still configured as unlimited.
	fallbackProposalGasLimit uint64 = 100_000_000
	fallbackProposalMaxBytes int64  = 21 * 1024 * 1024
)

type proposalGasTx interface {
	GetGas() uint64
}

func (app *App) setProposalHandlers(txConfig client.TxConfig) {
	app.SetPrepareProposal(app.prepareProposalHandler(txConfig))
	app.SetProcessProposal(app.processProposalHandler())
}

func (app *App) prepareProposalHandler(txConfig client.TxConfig) sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, request abci.RequestPrepareProposal) abci.ResponsePrepareProposal {
		maxBytes := effectiveProposalMaxBytes(ctx, request.MaxTxBytes)
		maxGas := effectiveProposalGasLimit(ctx)
		selected := make([][]byte, 0, len(request.Txs))
		var totalBytes int64
		var totalGas uint64

		for _, rawTx := range request.Txs {
			if int64(len(rawTx)) > maxBytes-totalBytes {
				break
			}
			tx, err := txConfig.TxDecoder()(rawTx)
			if err != nil {
				continue
			}
			txGas, ok := declaredGas(tx)
			if !ok || exceedsUint64(totalGas, txGas) || totalGas+txGas > maxGas {
				continue
			}
			verifiedBytes, err := app.PrepareProposalVerifyTx(tx)
			if err != nil {
				continue
			}
			if int64(len(verifiedBytes)) > maxBytes-totalBytes {
				break
			}
			selected = append(selected, verifiedBytes)
			totalBytes += int64(len(verifiedBytes))
			totalGas += txGas
		}
		return abci.ResponsePrepareProposal{Txs: selected}
	}
}

func (app *App) processProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, request abci.RequestProcessProposal) abci.ResponseProcessProposal {
		maxBytes := effectiveProposalMaxBytes(ctx, 0)
		maxGas := effectiveProposalGasLimit(ctx)
		var totalBytes int64
		var totalGas uint64

		for _, rawTx := range request.Txs {
			if int64(len(rawTx)) > maxBytes-totalBytes {
				return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
			}
			decodedTx, err := app.txConfig.TxDecoder()(rawTx)
			if err != nil {
				return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
			}
			txGas, ok := declaredGas(decodedTx)
			if !ok || exceedsUint64(totalGas, txGas) || totalGas+txGas > maxGas {
				return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
			}
			tx, err := app.ProcessProposalVerifyTx(rawTx)
			if err != nil {
				return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
			}
			verifiedGas, ok := declaredGas(tx)
			if !ok || verifiedGas != txGas {
				return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
			}
			totalBytes += int64(len(rawTx))
			totalGas += txGas
		}
		return abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}
	}
}

func effectiveProposalGasLimit(ctx sdk.Context) uint64 {
	if block := ctx.ConsensusParams().Block; block != nil && block.MaxGas > 0 {
		return uint64(block.MaxGas)
	}
	return fallbackProposalGasLimit
}

func effectiveProposalMaxBytes(ctx sdk.Context, requested int64) int64 {
	limit := fallbackProposalMaxBytes
	if block := ctx.ConsensusParams().Block; block != nil && block.MaxBytes > 0 {
		limit = block.MaxBytes
	}
	if requested > 0 && requested < limit {
		return requested
	}
	return limit
}

func declaredGas(tx sdk.Tx) (uint64, bool) {
	gasTx, ok := tx.(proposalGasTx)
	if !ok || gasTx.GetGas() == 0 {
		return 0, false
	}
	return gasTx.GetGas(), true
}

func exceedsUint64(current, addition uint64) bool {
	return addition > math.MaxUint64-current
}

// ensureFiniteBlockLimits mutates only legacy unlimited/missing values and
// preserves any explicit positive consensus limits.
func ensureFiniteBlockLimits(params *tmproto.ConsensusParams) bool {
	if params == nil {
		return false
	}
	changed := false
	if params.Block == nil {
		params.Block = &tmproto.BlockParams{}
		changed = true
	}
	if params.Block.MaxGas <= 0 {
		params.Block.MaxGas = int64(fallbackProposalGasLimit)
		changed = true
	}
	if params.Block.MaxBytes <= 0 {
		params.Block.MaxBytes = fallbackProposalMaxBytes
		changed = true
	}
	return changed
}
