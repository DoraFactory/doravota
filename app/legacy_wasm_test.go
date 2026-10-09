package app_test

import (
	"context"
	"cosmossdk.io/collections"
	"encoding/json"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	tmtypes "github.com/cometbft/cometbft/types"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govmodule "github.com/cosmos/cosmos-sdk/x/gov"
	"testing"
	"time"

	"github.com/DoraFactory/doravota/app"
	"github.com/DoraFactory/doravota/app/wasmarchive"
	legacy "github.com/DoraFactory/doravota/third_party/wasm-legacy-codec"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	ct "github.com/cosmos/cosmos-sdk/codec/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	gov "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	govlegacy "github.com/cosmos/cosmos-sdk/x/gov/types/v1beta1"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func TestLegacyWasmCodecRoundTripsAndHasNoHandlers(t *testing.T) {
	a := policyTestApp(t)
	cdc := a.AppCodec()
	msg := &legacy.MsgExecuteContract{Sender: sdk.AccAddress([]byte("sender-address-123456")).String(), Contract: sdk.AccAddress([]byte("target-address-123456")).String(), Msg: legacy.RawContractMessage(`{"claim":{}}`)}
	packed, err := ct.NewAnyWithValue(msg)
	require.NoError(t, err)
	expired := time.Unix(1700000010, 0)
	limit, err := ct.NewAnyWithValue(&legacy.MaxCallsLimit{Remaining: 2})
	require.NoError(t, err)
	filter, err := ct.NewAnyWithValue(&legacy.AcceptedMessageKeysFilter{Keys: []string{"claim"}})
	require.NoError(t, err)
	grant := legacy.ContractGrant{Contract: msg.Contract, Limit: limit, Filter: filter}
	cases := []proto.Message{
		msg,
		&authz.MsgExec{Grantee: msg.Sender, Msgs: []*ct.Any{packed}},
		&gov.Proposal{Id: 3, Messages: []*ct.Any{packed}, Title: "archived", Summary: "archived"},
	}
	for _, authorization := range []authz.Authorization{authz.NewGenericAuthorization("/cosmwasm.wasm.v1.MsgExecuteContract"), &legacy.StoreCodeAuthorization{}, &legacy.ContractExecutionAuthorization{Grants: []legacy.ContractGrant{grant}}, &legacy.ContractMigrationAuthorization{Grants: []legacy.ContractGrant{grant}}} {
		any, err := ct.NewAnyWithValue(authorization)
		require.NoError(t, err)
		cases = append(cases, &authz.Grant{Authorization: any, Expiration: &expired})
	}
	content, err := ct.NewAnyWithValue(&legacy.ExecuteContractProposal{Title: "history", Description: "history", Contract: msg.Contract, RunAs: msg.Sender, Msg: legacy.RawContractMessage(`{}`)})
	require.NoError(t, err)
	cases = append(cases, &govlegacy.Proposal{ProposalId: 9, Content: content})
	for _, original := range cases {
		t.Run(proto.MessageName(original), func(t *testing.T) {
			encoded, err := cdc.Marshal(original)
			require.NoError(t, err)
			decoded := proto.Clone(original)
			decoded.Reset()
			require.NoError(t, cdc.Unmarshal(encoded, decoded))
			text, err := cdc.MarshalJSON(decoded)
			require.NoError(t, err)
			require.True(t, json.Valid(text))
			roundtrip := proto.Clone(original)
			roundtrip.Reset()
			require.NoError(t, cdc.UnmarshalJSON(text, roundtrip))
			again, err := cdc.Marshal(roundtrip)
			require.NoError(t, err)
			require.Equal(t, encoded, again)
		})
	}
	require.Nil(t, a.MsgServiceRouter().Handler(msg))
	auth := &legacy.ContractExecutionAuthorization{Grants: []legacy.ContractGrant{grant}}
	response, err := auth.Accept(context.Background(), msg)
	require.ErrorIs(t, err, legacy.ErrRetired)
	require.False(t, response.Accept)
	require.ErrorIs(t, auth.ValidateBasic(), legacy.ErrRetired)
}

func TestUserTextAndGrantsCannotVetoRetirement(t *testing.T) {
	a := policyTestApp(t)
	ctx := a.NewContextLegacy(true, tmproto.Header{Height: 12, Time: time.Unix(1700000000, 0)})
	proposal := &gov.Proposal{Id: 42, Status: gov.StatusDepositPeriod, Title: "cosmwasm.wasm. text", Summary: "cosmwasm.wasm.", Metadata: "cosmwasm.wasm."}
	require.NoError(t, a.GovKeeper.Proposals.Set(ctx, 42, *proposal))
	granter := sdk.AccAddress([]byte("granter-address-12345"))
	grantee := sdk.AccAddress([]byte("grantee-address-12345"))
	expiry := ctx.BlockTime().Add(time.Hour)
	require.NoError(t, a.AuthzKeeper.SaveGrant(ctx, grantee, granter, authz.NewGenericAuthorization("/cosmwasm.wasm.v1.MsgExecuteContract"), &expiry))
	require.NoError(t, a.AuthzKeeper.SaveGrant(ctx, grantee, granter, &legacy.ContractMigrationAuthorization{}, &expiry))
	keys := map[string]*storetypes.KVStoreKey{"ibc": a.GetKey("ibc"), "gov": a.GetKey("gov"), "authz": a.GetKey("authz")}
	require.NoError(t, wasmarchive.ValidateContext(ctx, keys))
	// Genesis export traverses all grants, including concrete Wasm authorizations.
	state := a.AuthzKeeper.ExportGenesis(ctx)
	encoded, err := a.AppCodec().MarshalJSON(state)
	require.NoError(t, err)
	var decoded authz.GenesisState
	require.NoError(t, a.AppCodec().UnmarshalJSON(encoded, &decoded))
	require.Len(t, decoded.Authorization, 2)
	require.NoError(t, a.AuthzKeeper.DequeueAndDeleteExpiredGrants(ctx.WithBlockTime(expiry.Add(time.Second)), 100))
	require.Empty(t, a.AuthzKeeper.ExportGenesis(ctx).Authorization)
}

// Exercise the interface registry independently of application construction.
func TestLegacyWasmStoredProposalDecode(t *testing.T) {
	e := app.MakeEncodingConfig()
	raw := []byte(`{"id":"7","messages":[{"@type":"/cosmwasm.wasm.v1.MsgExecuteContract","sender":"","contract":"","msg":{},"funds":[]}],"status":"PROPOSAL_STATUS_DEPOSIT_PERIOD","title":"legacy","summary":"legacy"}`)
	var p gov.Proposal
	require.NoError(t, e.Marshaler.UnmarshalJSON(raw, &p))
	msgs, err := p.GetMsgs()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.IsType(t, &legacy.MsgExecuteContract{}, msgs[0])
}

// A passing proposal queued before retirement must fail as a proposal, not halt EndBlock.
func TestLegacyWasmVotingProposalEndsWithoutHalting(t *testing.T) {
	a := policyTestApp(t)
	pub := ed25519.GenPrivKey().PubKey()
	addr := sdk.AccAddress(pub.Address())
	genesis, err := simtestutil.GenesisStateWithValSet(a.AppCodec(), app.NewDefaultGenesisState(a.AppCodec()), tmtypes.NewValidatorSet([]*tmtypes.Validator{tmtypes.NewValidator(pub, 1)}), []authtypes.GenesisAccount{authtypes.NewBaseAccountWithAddress(addr)})
	require.NoError(t, err)
	raw, err := json.Marshal(genesis)
	require.NoError(t, err)
	stamp := time.Unix(1700000000, 0)
	cp := tmtypes.DefaultConsensusParams().ToProto()
	_, err = a.InitChain(&abci.RequestInitChain{ChainId: "policy-test", InitialHeight: 1, Time: stamp, ConsensusParams: &cp, AppStateBytes: raw})
	require.NoError(t, err)
	_, err = a.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Time: stamp.Add(time.Second)})
	require.NoError(t, err)
	_, err = a.Commit()
	require.NoError(t, err)
	ctx := a.NewContextLegacy(true, tmproto.Header{Height: 2, Time: stamp.Add(3 * time.Second)})
	expiry := stamp.Add(2 * time.Second)
	packed, err := ct.NewAnyWithValue(&legacy.MsgExecuteContract{Sender: addr.String(), Contract: addr.String(), Msg: legacy.RawContractMessage(`{}`)})
	require.NoError(t, err)
	p := gov.Proposal{Id: 99, Messages: []*ct.Any{packed}, Status: gov.StatusVotingPeriod, Title: "legacy", Summary: "legacy", VotingEndTime: &expiry}
	require.NoError(t, a.GovKeeper.Proposals.Set(ctx, 99, p))
	require.NoError(t, a.GovKeeper.ActiveProposalsQueue.Set(ctx, collections.Join(expiry, uint64(99)), 99))
	require.NoError(t, a.GovKeeper.AddVote(ctx, 99, addr, gov.NewNonSplitVoteOption(gov.OptionYes), ""))
	require.NoError(t, govmodule.EndBlocker(ctx, a.GovKeeper))
	result, err := a.GovKeeper.Proposals.Get(ctx, 99)
	require.NoError(t, err)
	require.Equal(t, gov.StatusFailed, result.Status)
	encoded, err := a.AppCodec().MarshalJSON(&result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "MsgExecuteContract")
	require.NoError(t, govmodule.EndBlocker(ctx, a.GovKeeper))
}
