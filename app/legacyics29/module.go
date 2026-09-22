package legacyics29

import (
	"encoding/json"
	"fmt"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
)

// The small compatibility store is exported with genesis so an export/import
// does not silently break old channels or lose pending async acknowledgements.
// It never owns an account, holds funds, or exposes a fee-payment service.
type Entry struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}
type Basic struct{}

func (Basic) Name() string                                                { return StoreKey }
func (Basic) RegisterLegacyAminoCodec(*codec.LegacyAmino)                 {}
func (Basic) RegisterInterfaces(codectypes.InterfaceRegistry)             {}
func (Basic) RegisterGRPCGatewayRoutes(client.Context, *runtime.ServeMux) {}
func (Basic) DefaultGenesis(codec.JSONCodec) json.RawMessage              { return json.RawMessage(`[]`) }
func (Basic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, raw json.RawMessage) error {
	_, err := parseGenesis(raw)
	return err
}
func parseGenesis(raw json.RawMessage) ([]Entry, error) {
	var entries []Entry
	if len(raw) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[string(e.Key)] {
			return nil, fmt.Errorf("duplicate legacy ICS-29 genesis key")
		}
		seen[string(e.Key)] = true
		if err := validateKey(e.Key, e.Value, false); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

type Module struct {
	Basic
	Key *storetypes.KVStoreKey
}

var _ module.AppModule = Module{}
var _ module.HasGenesis = Module{}

func (Module) IsAppModule()             {}
func (Module) IsOnePerModuleType()      {}
func (Module) ConsensusVersion() uint64 { return 1 }
func (m Module) InitGenesis(ctx sdk.Context, _ codec.JSONCodec, raw json.RawMessage) {
	entries, err := parseGenesis(raw)
	if err != nil {
		panic(err)
	}
	// During migration the store was renamed by StoreLoader. Empty genesis MUST
	// leave that state intact until RefundAndRetire validates and cleans it.
	for _, e := range entries {
		ctx.KVStore(m.Key).Set(e.Key, e.Value)
	}
}
func (m Module) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	entries := []Entry{}
	it := ctx.KVStore(m.Key).Iterator(nil, nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		if err := validateKey(it.Key(), it.Value(), false); err != nil {
			panic(err)
		}
		entries = append(entries, Entry{append([]byte(nil), it.Key()...), append([]byte(nil), it.Value()...)})
	}
	if err := it.Error(); err != nil {
		panic(err)
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}
	return raw
}
