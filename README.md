# Dora Vota
doravota node which supports cosmwasm in cosmos ecosystem

## Install and Using
> requirement: go version 1.20+

1. download
```shell
git clone https://github.com/DoraFactory/doravota.git
git checkout 0.1.0
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
- chain-id: vota-ash
- decimal: 18
- token name: DORA
- chain name: Dora Vota

## Some parameters
```
{
    "chainId": "vota-ash",
    "chainName": "Dora Vota",
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
        "coinMinimalDenom": "peaka",
        "coinDecimals": 18,
        "coinGeckoId": "dora"
      }
    ],
    "feeCurrencies": [
      {
        "coinDenom": "DORA",
        "coinMinimalDenom": "peaka",
        "coinDecimals": 18,
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
      "coinMinimalDenom": "peaka",
      "coinDecimals": 18,
      "coinGeckoId": "dora"
    },
    "features": [
      "cosmwasm"
    ]
  }
```
