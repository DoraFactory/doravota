package wasmarchive

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protowire"
)

// DecodeMetadata describes the stable stored protobuf fields without linking a
// Wasm runtime. Unknown/extension fields remain available through the raw API.
func DecodeMetadata(raw []byte, kind string) (map[string]any, error) {
	out := map[string]any{}
	for len(raw) > 0 {
		n, t, l := protowire.ConsumeTag(raw)
		if l < 0 {
			return nil, protowire.ParseError(l)
		}
		raw = raw[l:]
		size := protowire.ConsumeFieldValue(n, t, raw)
		if size < 0 {
			return nil, protowire.ParseError(size)
		}
		if kind == "contract" {
			if n == 1 && t == protowire.VarintType {
				v, _ := protowire.ConsumeVarint(raw)
				out["code_id"] = strconv.FormatUint(v, 10)
			}
			names := map[protowire.Number]string{2: "creator", 3: "admin", 4: "label", 6: "ibc_port_id", 8: "ibc2_port_id"}
			if name, ok := names[n]; ok && t == protowire.BytesType {
				v, _ := protowire.ConsumeBytes(raw)
				out[name] = string(v)
			}
		} else if kind == "code" {
			if t == protowire.BytesType {
				v, _ := protowire.ConsumeBytes(raw)
				switch n {
				case 1:
					out["code_hash"] = hex.EncodeToString(v)
				case 2:
					out["creator"] = string(v)
				case 5:
					out["instantiate_config_raw"] = v
				}
			}
		}
		raw = raw[size:]
	}
	return out, nil
}

func metadataCommands() []*cobra.Command {
	var result []*cobra.Command
	for _, kind := range []string{"contract", "code"} {
		cmd := &cobra.Command{Use: kind + "-info ID_OR_ADDRESS", Short: "Read archived " + kind + " metadata (raw protobuf also included)", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			var key []byte
			if kind == "code" {
				id, e := strconv.ParseUint(args[0], 10, 64)
				if e != nil || id == 0 {
					return fmt.Errorf("positive code ID required")
				}
				key = make([]byte, 9)
				key[0] = 1
				binary.BigEndian.PutUint64(key[1:], id)
			} else {
				addr, e := sdk.AccAddressFromBech32(args[0])
				if e != nil {
					return e
				}
				if len(addr) != 20 && len(addr) != 32 {
					return fmt.Errorf("invalid contract address length")
				}
				key = append([]byte{2}, addr...)
			}
			res := &GetResponse{}
			if err = Fetch(ctx, "Get", &GetRequest{Key: key}, res); err != nil {
				return err
			}
			decoded := map[string]any{}
			if res.Found {
				decoded, err = DecodeMetadata(res.Value, kind)
				if err != nil {
					return err
				}
			}
			out, err := json.Marshal(map[string]any{"found": res.Found, "height": res.Height, "metadata": decoded, "raw": res.Value})
			if err != nil {
				return err
			}
			return ctx.PrintString(string(out) + "\n")
		}}
		flags.AddQueryFlagsToCmd(cmd)
		result = append(result, cmd)
	}
	return result
}
