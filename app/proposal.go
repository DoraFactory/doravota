package app

import (
	"math"

	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pqcauthante "github.com/DoraFactory/doravota/x/pqcauth/ante"
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
	txDecoder := pqcauthante.CanonicalPQCAuthTxDecoder(txConfig.TxDecoder())
	app.SetPrepareProposal(app.prepareProposalHandler(txDecoder))
	app.SetProcessProposal(app.processProposalHandler(txDecoder))
}

func (app *App) prepareProposalHandler(txDecoder sdk.TxDecoder) sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, request *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		maxBytes := effectiveProposalMaxBytes(ctx, request.MaxTxBytes)
		maxGas := effectiveProposalGasLimit(ctx)
		selected := make([][]byte, 0, len(request.Txs))
		var totalBytes int64
		var totalGas uint64

		for _, rawTx := range request.Txs {
			if int64(len(rawTx)) > maxBytes-totalBytes {
				break
			}
			tx, err := txDecoder(rawTx)
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
		return &abci.ResponsePrepareProposal{Txs: selected}, nil
	}
}

func (app *App) processProposalHandler(txDecoder sdk.TxDecoder) sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, request *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		maxBytes := effectiveProposalMaxBytes(ctx, 0)
		maxGas := effectiveProposalGasLimit(ctx)
		var totalBytes int64
		var totalGas uint64

		for _, rawTx := range request.Txs {
			if int64(len(rawTx)) > maxBytes-totalBytes {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
			decodedTx, err := txDecoder(rawTx)
			if err != nil {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
			txGas, ok := declaredGas(decodedTx)
			if !ok || exceedsUint64(totalGas, txGas) || totalGas+txGas > maxGas {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
			tx, gasWanted, err := app.ProcessProposalVerifyTx(rawTx)
			if err != nil {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
			verifiedGas, ok := declaredGas(tx)
			if !ok || verifiedGas != txGas || gasWanted == 0 {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
			totalBytes += int64(len(rawTx))
			totalGas += txGas
		}
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
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

// completeConsensusParams fills fields that may be absent from the persisted
// x/consensus record with the parameters observed by CometBFT for the current
// block. Doravota v0.4.x stored these parameters in x/upgrade; SDK v0.53+
// stores them in the dedicated consensus store, so the bridge upgrade must
// explicitly seed the new location.
func completeConsensusParams(
	stored tmproto.ConsensusParams,
	observed tmproto.ConsensusParams,
) (tmproto.ConsensusParams, bool) {
	changed := false
	if stored.Block == nil && observed.Block != nil {
		stored.Block = observed.Block
		changed = true
	}
	if stored.Evidence == nil && observed.Evidence != nil {
		stored.Evidence = observed.Evidence
		changed = true
	}
	if stored.Validator == nil && observed.Validator != nil {
		stored.Validator = observed.Validator
		changed = true
	}
	if stored.Version == nil && observed.Version != nil {
		stored.Version = observed.Version
		changed = true
	}
	if stored.Abci == nil && observed.Abci != nil {
		stored.Abci = observed.Abci
		changed = true
	}
	if stored.Authority == nil && observed.Authority != nil {
		stored.Authority = observed.Authority
		changed = true
	}

	return stored, changed
}
