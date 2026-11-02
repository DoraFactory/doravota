package app

import (
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
)

// PQC uses the SDK's gas/byte selection policy, not a parallel verification
// quota. BaseApp retains CanonicalPQCAuthTxDecoder and the block gas meter;
// Ante still authenticates every transaction at execution.
func (app *App) setProposalHandlers(_ client.TxConfig) {
	defaults := baseapp.NewDefaultProposalHandler(app.Mempool(), app.BaseApp)
	app.SetPrepareProposal(defaults.PrepareProposalHandler())
	app.SetProcessProposal(defaults.ProcessProposalHandler())
}
