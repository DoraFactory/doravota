package wasmarchive

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fetch uses the SDK ABCI query path so --height / historical gRPC semantics
// come from BaseApp's versioned query context, not IAVL's current-state subspace.
func Fetch(ctx client.Context, method string, req, res proto.Message) error {
	raw, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	value, _, err := ctx.QueryWithData("/doravota.wasmarchive.v1.Query/"+method, raw)
	if err != nil {
		return err
	}
	return proto.Unmarshal(value, res)
}

func QueryCommand() *cobra.Command {
	root := &cobra.Command{Use: "wasm-archive", Short: "Read preserved Wasm bytes without executing contracts"}
	get := &cobra.Command{Use: "get KEY_HEX", Short: "Read an exact full Wasm store key", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx, err := client.GetClientQueryContext(cmd)
		if err != nil {
			return err
		}
		key, err := hex.DecodeString(args[0])
		if err != nil {
			return err
		}
		res := &GetResponse{}
		if err = Fetch(ctx, "Get", &GetRequest{Key: key}, res); err != nil {
			return err
		}
		out, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(res)
		if err != nil {
			return err
		}
		return ctx.PrintString(string(out) + "\n")
	}}
	root.AddCommand(get)
	root.AddCommand(metadataCommands()...)
	flags.AddQueryFlagsToCmd(get)
	for _, contract := range []bool{false, true} {
		use, short := "scan PREFIX_HEX", "Page through raw store keys (empty prefix scans all entries)"
		if contract {
			use, short = "contract-state ADDRESS", "Page through a contract's raw storage (full keys, base64 values)"
		}
		cmd := &cobra.Command{Use: use, Short: short, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			var prefix []byte
			if contract {
				prefix, err = ContractPrefix(args[0])
			} else {
				prefix, err = hex.DecodeString(args[0])
			}
			if err != nil {
				return err
			}
			cursor, _ := cmd.Flags().GetString("start-key")
			key, err := hex.DecodeString(cursor)
			if err != nil {
				return err
			}
			limit, _ := cmd.Flags().GetUint32("limit")
			res := &ScanResponse{}
			if err = Fetch(ctx, "Scan", &ScanRequest{Prefix: prefix, StartKey: key, Limit: limit}, res); err != nil {
				return err
			}
			out, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(res)
			if err != nil {
				return err
			}
			return ctx.PrintString(string(out) + "\n")
		}}
		cmd.Flags().String("start-key", "", "Inclusive full key in hex (decode response next_key from base64)")
		cmd.Flags().Uint32("limit", 100, "Page size, maximum 1000")
		flags.AddQueryFlagsToCmd(cmd)
		root.AddCommand(cmd)
	}
	return root
}

// REST is deliberately a new namespace; it does not claim compatibility with
// Wasmd's smart-query endpoint. gRPC clients can use generated QueryClient.
func RegisterREST(ctx client.Context, router *mux.Router) {
	for _, method := range []string{"get", "scan"} {
		router.HandleFunc("/doravota/wasmarchive/v1/"+method, func(w http.ResponseWriter, r *http.Request) {
			qctx := ctx.WithCmdContext(r.Context())
			if h := r.Header.Get("x-cosmos-block-height"); h != "" {
				height, err := strconv.ParseInt(h, 10, 64)
				if err != nil || height < 0 {
					http.Error(w, "invalid block height", 400)
					return
				}
				qctx = qctx.WithHeight(height)
			}
			decode := func(name string) ([]byte, error) { return hex.DecodeString(r.URL.Query().Get(name)) }
			var response proto.Message
			var err error
			if method == "get" {
				var key []byte
				key, err = decode("key")
				res := &GetResponse{}
				response = res
				if err == nil {
					err = Fetch(qctx, "Get", &GetRequest{Key: key}, res)
				}
			} else {
				var prefix, key []byte
				prefix, err = decode("prefix")
				if err == nil {
					key, err = decode("start_key")
				}
				limit := uint64(100)
				if v := r.URL.Query().Get("limit"); v != "" && err == nil {
					limit, err = strconv.ParseUint(v, 10, 32)
				}
				res := &ScanResponse{}
				response = res
				if err == nil {
					err = Fetch(qctx, "Scan", &ScanRequest{Prefix: prefix, StartKey: key, Limit: uint32(limit)}, res)
				}
			}
			if err != nil {
				http.Error(w, fmt.Sprintf("archive query failed: %v", err), 400)
				return
			}
			raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(response)
			if err != nil {
				http.Error(w, "marshal failed", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(raw)
		}).Methods("GET")
	}
}
