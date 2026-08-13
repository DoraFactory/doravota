package cmd

import (
	sdkmath "cosmossdk.io/math"

	"github.com/DoraFactory/doravota/app"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/version"
)

const (
	// set token decimal
	HumanCoinUnit = "DORA"
	BaseCoinUnit  = "peaka"
	DoraExponent  = 18

	DefaultBondDenom = BaseCoinUnit
)

func initSDKConfig() {
	// Set prefixes
	accountPubKeyPrefix := app.AccountAddressPrefix + "pub"
	validatorAddressPrefix := app.AccountAddressPrefix + "valoper"
	validatorPubKeyPrefix := app.AccountAddressPrefix + "valoperpub"
	consNodeAddressPrefix := app.AccountAddressPrefix + "valcons"
	consNodePubKeyPrefix := app.AccountAddressPrefix + "valconspub"

	// Set and seal config
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(app.AccountAddressPrefix, accountPubKeyPrefix)
	config.SetBech32PrefixForValidator(validatorAddressPrefix, validatorPubKeyPrefix)
	config.SetBech32PrefixForConsensusNode(consNodeAddressPrefix, consNodePubKeyPrefix)

	err := sdk.RegisterDenom(HumanCoinUnit, sdkmath.LegacyOneDec())
	if err != nil {
		panic(err)
	}
	err = sdk.RegisterDenom(BaseCoinUnit, sdkmath.LegacyNewDecWithPrec(1, DoraExponent))
	if err != nil {
		panic(err)
	}

	// set the genesis default denom
	sdk.DefaultBondDenom = DefaultBondDenom

	config.Seal()
}

const (
	name     = "doravota"
	app_name = "dorad"
	Version  = "v1.0.0"
)

func setVersionInfo() {
	version.Name = name
	version.AppName = app_name
	version.Version = Version
}
