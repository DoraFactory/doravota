// Package wasmarchive retains Wasmd's original store without its runtime.
// Query responses are exact bytes, not VM-evaluated contract queries.
package wasmarchive

import (
	"bytes"
	"context"
	"fmt"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const StoreKey = "wasm"
const GenesisKey = "wasm_archive"
const maxPageSize = 1000
const maxPageBytes = 4 << 20
const maxKeyBytes = 64 << 10

type Server struct {
	UnimplementedQueryServer
	key *storetypes.KVStoreKey
}

func NewServer(key *storetypes.KVStoreKey) *Server { return &Server{key: key} }

func (s *Server) Get(goCtx context.Context, req *GetRequest) (*GetResponse, error) {
	if req == nil || len(req.Key) == 0 || len(req.Key) > maxKeyBytes {
		return nil, status.Error(codes.InvalidArgument, "a non-empty key of at most 64 KiB is required")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	value := ctx.KVStore(s.key).Get(req.Key)
	return &GetResponse{Value: value, Found: value != nil, Height: ctx.BlockHeight()}, nil
}

func (s *Server) Scan(goCtx context.Context, req *ScanRequest) (*ScanResponse, error) {
	if req == nil || len(req.Prefix) > maxKeyBytes || len(req.StartKey) > maxKeyBytes || req.Limit > maxPageSize {
		return nil, status.Error(codes.InvalidArgument, "invalid scan: maximum limit 1000; key/prefix at most 64 KiB")
	}
	if len(req.StartKey) > 0 && !bytes.HasPrefix(req.StartKey, req.Prefix) {
		return nil, status.Error(codes.InvalidArgument, "start_key must be within prefix")
	}
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	start := req.Prefix
	if len(req.StartKey) > 0 {
		start = req.StartKey
	}
	it := ctx.KVStore(s.key).Iterator(start, storetypes.PrefixEndBytes(req.Prefix))
	defer it.Close()
	res := &ScanResponse{Height: ctx.BlockHeight()}
	size := 0
	for ; it.Valid(); it.Next() {
		n := len(it.Key()) + len(it.Value())
		if len(res.Entries) >= int(limit) || (len(res.Entries) > 0 && size+n > maxPageBytes) {
			res.NextKey = bytes.Clone(it.Key())
			break
		}
		if n > maxPageBytes {
			return nil, status.Error(codes.ResourceExhausted, "single entry exceeds scan byte limit; fetch it with Get")
		}
		res.Entries = append(res.Entries, &Entry{Key: bytes.Clone(it.Key()), Value: bytes.Clone(it.Value())})
		size += n
	}
	return res, nil
}

// ContractPrefix uses Wasmd 0.61.x's unmodified storage layout.
func ContractPrefix(address string) ([]byte, error) {
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return nil, err
	}
	if len(addr) != 20 && len(addr) != 32 {
		return nil, fmt.Errorf("invalid contract address length %d", len(addr))
	}
	return append([]byte{3}, addr...), nil
}
