#!/usr/bin/env python3
"""Recompute bank genesis supply with arbitrary-precision integer arithmetic."""

import json
import os
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: normalize_genesis_supply.py GENESIS_JSON")
    path = os.path.abspath(sys.argv[1])
    with open(path, encoding="utf-8") as source:
        genesis = json.load(source)
    totals = {}
    for balance in genesis["app_state"]["bank"].get("balances", []):
        for coin in balance.get("coins", []):
            amount = int(coin["amount"])
            if amount < 0:
                raise ValueError(f"negative genesis balance for {coin['denom']}")
            totals[coin["denom"]] = totals.get(coin["denom"], 0) + amount
    genesis["app_state"]["bank"]["supply"] = [
        {"denom": denom, "amount": str(amount)}
        for denom, amount in sorted(totals.items())
    ]

    original_mode = os.stat(path).st_mode & 0o777
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=os.path.dirname(path), delete=False
    ) as output:
        json.dump(genesis, output, separators=(",", ":"))
        output.write("\n")
        temporary = output.name
    os.chmod(temporary, original_mode)
    os.replace(temporary, path)


if __name__ == "__main__":
    main()
