// Package legacyics29 retires the IBC-Go v7 fee ledger while preserving the
// wire protocol of channels which already negotiated ICS-29. It has no fee
// payment, reward distribution, or new fee-channel registration messages.
package legacyics29

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	channeltypes "github.com/cosmos/ibc-go/v10/modules/core/04-channel/types"
	host "github.com/cosmos/ibc-go/v10/modules/core/24-host"
	"google.golang.org/protobuf/encoding/protowire"
)

const StoreKey = "legacyics29"

type Bank interface {
	GetAllBalances(context.Context, sdk.AccAddress) sdk.Coins
	SendCoins(context.Context, sdk.AccAddress, sdk.AccAddress, sdk.Coins) error
	BlockedAddr(sdk.AccAddress) bool
}
type Channels interface {
	GetChannel(sdk.Context, string, string) (channeltypes.Channel, bool)
}
type refund struct {
	address sdk.AccAddress
	coins   sdk.Coins
}

// bytesFields decodes only the length-delimited fields used by the pinned
// ibc-go/v7 v7.3.0 fee.proto. Reject unknown fields instead of losing liabilities.
func bytesFields(raw []byte, visit func(protowire.Number, []byte) error) error {
	for len(raw) > 0 {
		n, t, k := protowire.ConsumeTag(raw)
		if k < 0 || t != protowire.BytesType {
			return fmt.Errorf("invalid legacy fee protobuf tag")
		}
		raw = raw[k:]
		value, k := protowire.ConsumeBytes(raw)
		if k < 0 {
			return fmt.Errorf("truncated legacy fee protobuf")
		}
		if err := visit(n, value); err != nil {
			return err
		}
		raw = raw[k:]
	}
	return nil
}
func decodeRefunds(raw []byte) ([]refund, error) {
	var result []refund
	err := bytesFields(raw, func(n protowire.Number, packet []byte) error {
		if n != 1 {
			return fmt.Errorf("unknown PacketFees field %d", n)
		}
		var r refund
		seenFee, seenAddress := false, false
		err := bytesFields(packet, func(n protowire.Number, value []byte) error {
			switch n {
			case 1:
				if seenFee {
					return fmt.Errorf("duplicate fee field")
				}
				seenFee = true
				parts := [3]sdk.Coins{}
				if err := bytesFields(value, func(n protowire.Number, b []byte) error {
					if n < 1 || n > 3 {
						return fmt.Errorf("unknown Fee field %d", n)
					}
					var coin sdk.Coin
					if err := coin.Unmarshal(b); err != nil {
						return err
					}
					if err := coin.Validate(); err != nil {
						return err
					}
					if !coin.IsPositive() {
						return fmt.Errorf("nonpositive fee coin")
					}
					parts[n-1] = append(parts[n-1], coin)
					return nil
				}); err != nil {
					return err
				}
				// v7 escrows the SUM of receive + acknowledgement + timeout fees.
				// Do not substitute the different v8.1 max(success, timeout) rule.
				for _, part := range parts {
					if !part.IsValid() {
						return fmt.Errorf("invalid fee coin list")
					}
					r.coins = r.coins.Add(part...)
				}
			case 2:
				if seenAddress {
					return fmt.Errorf("duplicate refund address")
				}
				seenAddress = true
				var err error
				r.address, err = sdk.AccAddressFromBech32(string(value))
				if err != nil {
					return err
				}
			case 3:
				return fmt.Errorf("v7 fee records must not specify a relayer allowlist")
			default:
				return fmt.Errorf("unknown PacketFee field %d", n)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !seenFee || !seenAddress || r.coins.IsZero() {
			return fmt.Errorf("incomplete packet fee")
		}
		result = append(result, r)
		return nil
	})
	if err == nil && len(result) == 0 {
		err = fmt.Errorf("empty PacketFees record")
	}
	return result, err
}

// validateKey recognizes every key written by v7.3.0; it is also used to limit
// genesis exports to compatibility metadata after the financial migration.
func validateKey(key, value []byte, financial bool) error {
	p := strings.Split(string(key), "/")
	switch p[0] {
	case "locked":
		if !financial || len(p) != 1 || !bytes.Equal(value, []byte{1}) {
			return fmt.Errorf("invalid lock record")
		}
	case "feeEnabled", "forwardRelayer", "feesInEscrow":
		count := 3
		if p[0] != "feeEnabled" {
			count = 4
		}
		if len(p) != count {
			return fmt.Errorf("malformed key %q", key)
		}
		if err := host.PortIdentifierValidator(p[1]); err != nil {
			return err
		}
		if err := host.ChannelIdentifierValidator(p[2]); err != nil {
			return err
		}
		if count == 4 {
			seq, err := strconv.ParseUint(p[3], 10, 64)
			if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != p[3] {
				return fmt.Errorf("invalid packet sequence")
			}
		}
		switch p[0] {
		case "feeEnabled":
			if !bytes.Equal(value, []byte{1}) {
				return fmt.Errorf("invalid fee flag")
			}
		case "forwardRelayer":
			if _, err := sdk.AccAddressFromBech32(string(value)); err != nil {
				return err
			}
		case "feesInEscrow":
			if !financial {
				return fmt.Errorf("fee liabilities cannot be imported into retired module")
			}
		}
	case "payee", "counterpartyPayee":
		if len(p) != 3 || (p[0] == "payee" && !financial) {
			return fmt.Errorf("invalid payee key")
		}
		if _, err := sdk.AccAddressFromBech32(p[1]); err != nil {
			return err
		}
		if err := host.ChannelIdentifierValidator(p[2]); err != nil {
			return err
		}
		if len(value) == 0 {
			return fmt.Errorf("invalid payee value")
		}
		// v7.3.0 accepted non-UTF-8 counterparty payees through signed
		// transactions. Preserve those opaque historical bytes for the legacy
		// acknowledgement path and genesis export/import. Refund destinations
		// come from PacketFee.RefundAddress, not this mapping. Local payees
		// must still be valid account addresses.
		if p[0] == "payee" {
			if _, err := sdk.AccAddressFromBech32(string(value)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown legacy fee key %q", key)
	}
	return nil
}

// RefundAndRetire operates on the renamed legacy store. All validation precedes
// writes; the cache commits refunds and ledger cleanup together. StoreLoader's
// rename is persisted with these writes only when the upgrade block commits.
func RefundAndRetire(ctx sdk.Context, key *storetypes.KVStoreKey, bank Bank, channels Channels) error {
	cache, write := ctx.CacheContext()
	store := cache.KVStore(key)
	it := store.Iterator(nil, nil)
	var refunds []refund
	var remove [][]byte
	total := sdk.NewCoins()
	for ; it.Valid(); it.Next() {
		k, v := bytes.Clone(it.Key()), bytes.Clone(it.Value())
		if err := validateKey(k, v, true); err != nil {
			it.Close()
			return err
		}
		p := strings.Split(string(k), "/")
		if p[0] == "locked" {
			it.Close()
			return fmt.Errorf("legacy fee module is locked; reconcile escrow before upgrade")
		}
		if p[0] == "feeEnabled" {
			channel, found := channels.GetChannel(cache, p[1], p[2])
			if !found {
				it.Close()
				return fmt.Errorf("fee channel %s/%s is missing", p[1], p[2])
			}
			if _, err := appVersion(channel.Version); err != nil {
				it.Close()
				return fmt.Errorf("legacy channel %s/%s: %w", p[1], p[2], err)
			}
		}
		if p[0] == "feesInEscrow" || p[0] == "forwardRelayer" {
			if !store.Has(feeKey(p[1], p[2])) {
				it.Close()
				return fmt.Errorf("orphan packet record %q", k)
			}
		}
		if p[0] == "feesInEscrow" {
			rs, err := decodeRefunds(v)
			if err != nil {
				it.Close()
				return fmt.Errorf("decode %q: %w", k, err)
			}
			for _, r := range rs {
				if bank.BlockedAddr(r.address) || r.address.Equals(authtypes.NewModuleAddress("feeibc")) {
					it.Close()
					return fmt.Errorf("unsupported refund recipient %s", r.address)
				}
				total = total.Add(r.coins...)
			}
			refunds = append(refunds, rs...)
			remove = append(remove, k)
		} else if p[0] == "payee" {
			remove = append(remove, k)
		}
	}
	// SDK cache iterators report Error on normal exhaustion as well.
	// Close releases the iterator; do not mistake end-of-store for a read failure.
	if err := it.Close(); err != nil {
		return err
	}
	source := authtypes.NewModuleAddress("feeibc")
	if !bank.GetAllBalances(cache, source).Equal(total) {
		return fmt.Errorf("fee escrow balance does not equal recorded refunds: balance=%s refunds=%s", bank.GetAllBalances(cache, source), total)
	}
	for _, r := range refunds {
		if err := bank.SendCoins(cache, source, r.address, r.coins); err != nil {
			return fmt.Errorf("refund %s: %w", r.address, err)
		}
	}
	if !bank.GetAllBalances(cache, source).IsZero() {
		return fmt.Errorf("fee escrow not empty after refunds")
	}
	for _, k := range remove {
		store.Delete(k)
	}
	cache.EventManager().EmitEvent(sdk.NewEvent("legacy_ics29_refunded", sdk.NewAttribute("refund_entries", strconv.Itoa(len(refunds))), sdk.NewAttribute("amount", total.String())))
	write()
	return nil
}
