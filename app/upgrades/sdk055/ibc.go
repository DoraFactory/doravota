package sdk055

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ibc "github.com/cosmos/ibc-go/v11/modules/core"
	channelv11 "github.com/cosmos/ibc-go/v11/modules/core/04-channel/migrations/v11"
	channeltypes "github.com/cosmos/ibc-go/v11/modules/core/04-channel/types"
	ibckeeper "github.com/cosmos/ibc-go/v11/modules/core/keeper"
)

// ValidateIBCChannelMigration must also run BEFORE RunMigrations. A dependency
// update can register the previously manual migration and must be reviewed.
func ValidateIBCChannelMigration(ctx sdk.Context, key *storetypes.KVStoreKey, k *ibckeeper.Keeper) error {
	if version := (ibc.AppModule{}).ConsensusVersion(); version != 8 {
		return fmt.Errorf("IBC core version changed to %d: review automatic migrations before the manual v11 channel migration", version)
	}
	store := ctx.KVStore(key)
	var failure error
	k.ChannelKeeper.IterateChannels(ctx, func(ch channeltypes.IdentifiedChannel) bool {
		old := store.Get(channelv11.NextSequenceSendV1Key(ch.PortId, ch.ChannelId))
		if len(old) != 8 || sdk.BigEndianToUint64(old) == 0 {
			failure = fmt.Errorf("IBC channel %s/%s missing or invalid legacy send sequence; migration may already have run", ch.PortId, ch.ChannelId)
			return true
		}
		if _, found := k.ChannelKeeperV2.GetNextSequenceSend(ctx, ch.ChannelId); found {
			failure = fmt.Errorf("IBC channel %s already has a destination send sequence; refusing mixed or repeated migration", ch.ChannelId)
			return true
		}
		return false
	})
	return failure
}

// MigrateIBCChannels refuses repeated/partial migration rather than allowing
// upstream's nil legacy value to overwrite a live sequence with zero.
func MigrateIBCChannels(ctx sdk.Context, key *storetypes.KVStoreKey, cdc codec.BinaryCodec, k *ibckeeper.Keeper) error {
	if err := ValidateIBCChannelMigration(ctx, key, k); err != nil {
		return err
	}
	type sequence struct {
		port, channel string
		value         uint64
	}
	var before []sequence
	store := ctx.KVStore(key)
	k.ChannelKeeper.IterateChannels(ctx, func(ch channeltypes.IdentifiedChannel) bool {
		before = append(before, sequence{ch.PortId, ch.ChannelId, sdk.BigEndianToUint64(store.Get(channelv11.NextSequenceSendV1Key(ch.PortId, ch.ChannelId)))})
		return false
	})
	if err := channelv11.MigrateStore(ctx, runtime.NewKVStoreService(key), cdc, k); err != nil {
		return err
	}
	for _, old := range before {
		got, found := k.ChannelKeeperV2.GetNextSequenceSend(ctx, old.channel)
		if !found || got != old.value || store.Has(channelv11.NextSequenceSendV1Key(old.port, old.channel)) {
			return fmt.Errorf("IBC send sequence verification failed for %s/%s", old.port, old.channel)
		}
	}
	return nil
}
