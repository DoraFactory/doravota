# dora-vota
doravota node which supports cosmwasm in cosmos ecosystem

## Install and Using
> requirement: go version 1.20+

1. download
```shell
git clone https://github.com/DoraFactory/doravota.git
```

2. compile
```
cd doravota && make install
sudo cp ~/go/bin/dorad /usr/local/bin
```

3. create wallet
```
dorad keys add xxx
```

## Chain Info
- chain-id: doravota-devnet
- decimal: 6
- Name: DORA

## Some parameters
```
{
  "chainId": "doravota-devnet",
  "chainName": "dora",
  "rpc": "https://vota-rpc.dorafactory.org",
  "rest": "https://vota-rest.dorafactory.org",
  "bip44": {
    "coinType": 118
  },
  "bech32Config": {
    "bech32PrefixAccAddr": "dora",
    "bech32PrefixAccPub": "dorapub",
    "bech32PrefixValAddr": "doravaloper",
    "bech32PrefixValPub": "doravaloperpub",
    "bech32PrefixConsAddr": "doravalcons",
    "bech32PrefixConsPub": "doravalconspub"
  },
  "currencies": [
    {
      "coinDenom": "DORA",
      "coinMinimalDenom": "uDORA",
      "coinDecimals": 6,
      "coinGeckoId": "dora"
    }
  ],
  "feeCurrencies": [
    {
      "coinDenom": "DORA",
      "coinMinimalDenom": "uDORA",
      "coinDecimals": 6,
      "coinGeckoId": "dora",
      "gasPriceStep": {
        "low": 0.001,
        "average": 0.0025,
        "high": 0.003
      }
    }
  ],
  "stakeCurrency": {
    "coinDenom": "DORA",
    "coinMinimalDenom": "uDORA",
    "coinDecimals": 6,
    "coinGeckoId": "dora"
  },
  "features": [
    // "cosmwasm",
    // "dora-txfees"
  ]
}

/** Setting to speed up testing */
const defaultSigningClientOptions = {
  broadcastPollIntervalMs: 8_000,
  broadcastTimeoutMs: 16_000,
  gasPrice: GasPrice.fromString("0.025uDORA"),
};

```