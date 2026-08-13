package app

import (
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/codec/address"
	vesting "github.com/cosmos/cosmos-sdk/x/auth/vesting"
	vestingcli "github.com/cosmos/cosmos-sdk/x/auth/vesting/client/cli"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankcli "github.com/cosmos/cosmos-sdk/x/bank/client/cli"
	"github.com/cosmos/cosmos-sdk/x/distribution"
	distrcli "github.com/cosmos/cosmos-sdk/x/distribution/client/cli"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingcli "github.com/cosmos/cosmos-sdk/x/staking/client/cli"
	"github.com/cosmos/cosmos-sdk/x/upgrade"
	upgradecli "github.com/cosmos/cosmos-sdk/x/upgrade/client/cli"

	group "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat"
	groupcli "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat/client/cli"
	groupmodule "github.com/DoraFactory/doravota/third_party/cosmos-sdk-x-group-v055-compat/module"
)

// Cosmos SDK v0.55's keeper-backed AppModules populate private address-codec
// fields in their AppModuleBasic values. Doravota keeps a static BasicManager
// for genesis and codec registration, so these wrappers provide the same CLI
// codecs without requiring a temporary application instance.

func accountAddressCodec() address.Bech32Codec {
	return address.Bech32Codec{Bech32Prefix: Bech32PrefixAccAddr}
}

func validatorAddressCodec() address.Bech32Codec {
	return address.Bech32Codec{Bech32Prefix: Bech32PrefixValAddr}
}

type bankAppModuleBasic struct{ bank.AppModuleBasic }

func (bankAppModuleBasic) GetTxCmd() *cobra.Command {
	return bankcli.NewTxCmd(accountAddressCodec())
}

type stakingAppModuleBasic struct{ staking.AppModuleBasic }

func (stakingAppModuleBasic) GetTxCmd() *cobra.Command {
	return stakingcli.NewTxCmd(validatorAddressCodec(), accountAddressCodec())
}

type distributionAppModuleBasic struct{ distribution.AppModuleBasic }

func (distributionAppModuleBasic) GetTxCmd() *cobra.Command {
	return distrcli.NewTxCmd(validatorAddressCodec(), accountAddressCodec())
}

type upgradeAppModuleBasic struct{ upgrade.AppModuleBasic }

func (upgradeAppModuleBasic) GetTxCmd() *cobra.Command {
	return upgradecli.GetTxCmd(accountAddressCodec())
}

type vestingAppModuleBasic struct{ vesting.AppModuleBasic }

func (vestingAppModuleBasic) GetTxCmd() *cobra.Command {
	return vestingcli.GetTxCmd(accountAddressCodec())
}

type groupAppModuleBasic struct{ groupmodule.AppModuleBasic }

func (groupAppModuleBasic) GetTxCmd() *cobra.Command {
	return groupcli.TxCmd(group.ModuleName, accountAddressCodec())
}
