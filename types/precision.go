package types

import (
	"math/big"

	sdkmath "cosmossdk.io/math"
)

const (
	BaseDenomUnit = 18
)

var DefaultPowerReduction = sdkmath.NewIntFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(BaseDenomUnit), nil)) // 10^18
