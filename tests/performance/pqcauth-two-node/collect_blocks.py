#!/usr/bin/env python3
"""Collect committed block metrics for one preloaded pqcauth benchmark phase."""

import argparse
import base64
import datetime as dt
import json
import time
import urllib.parse
import urllib.error
import urllib.request


def rpc(base, path, params=None, retry_seconds=20):
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    deadline = time.time() + retry_seconds
    while True:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return json.load(response)["result"]
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            if time.time() >= deadline:
                raise
            # /status can expose a committed height just before its block
            # results become queryable. Treat that short indexing gap as a
            # transient RPC condition, not a failed benchmark.
            time.sleep(0.25)


def height(base):
    return int(rpc(base, "/status")["sync_info"]["latest_block_height"])


def unconfirmed(base):
    result = rpc(base, "/num_unconfirmed_txs")
    return int(result.get("n_txs", result.get("total", "0")))


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--start-height", type=int, required=True)
    parser.add_argument("--expected", type=int, required=True)
    parser.add_argument("--blocks-out", required=True)
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    deadline = time.time() + args.timeout
    next_height = args.start_height + 1
    committed = 0
    total_bytes = 0
    total_gas_wanted = 0
    total_gas_used = 0
    nonempty_blocks = 0
    first_tx_height = None
    last_tx_height = None
    first_time = None
    last_time = None
    records = []

    while time.time() < deadline:
        latest = height(args.rpc)
        while next_height <= latest:
            block_response = rpc(args.rpc, "/block", {"height": next_height})
            block = block_response["block"]
            results = rpc(args.rpc, "/block_results", {"height": next_height})
            txs = block.get("data", {}).get("txs") or []
            tx_results = results.get("txs_results") or []
            tx_bytes = sum(len(base64.b64decode(value)) for value in txs)
            gas_wanted = sum(int(item.get("gas_wanted", "0")) for item in tx_results)
            gas_used = sum(int(item.get("gas_used", "0")) for item in tx_results)
            failures = sum(1 for item in tx_results if int(item.get("code", 0)) != 0)
            timestamp = block["header"]["time"]
            record = {
                "mode": args.mode,
                "height": next_height,
                "time": timestamp,
                "tx_count": len(txs),
                "tx_bytes": tx_bytes,
                "gas_wanted": gas_wanted,
                "gas_used": gas_used,
                "failed_deliveries": failures,
                "block_hash": block_response.get("block_id", {}).get("hash", ""),
            }
            records.append(record)
            if txs:
                nonempty_blocks += 1
                committed += len(txs)
                total_bytes += tx_bytes
                total_gas_wanted += gas_wanted
                total_gas_used += gas_used
                if first_tx_height is None:
                    first_tx_height = next_height
                    first_time = parse_time(timestamp)
                last_tx_height = next_height
                last_time = parse_time(timestamp)
            next_height += 1

        if committed >= args.expected and unconfirmed(args.rpc) == 0:
            break
        time.sleep(0.5)
    else:
        raise SystemExit(
            f"timeout: committed={committed}, expected={args.expected}, "
            f"unconfirmed={unconfirmed(args.rpc)}"
        )

    with open(args.blocks_out, "x", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, separators=(",", ":")) + "\n")

    elapsed = 0.0
    if first_time is not None and last_time is not None:
        elapsed = max(0.0, (last_time - first_time).total_seconds())
    summary = {
        "mode": args.mode,
        "start_height": args.start_height,
        "first_transaction_height": first_tx_height,
        "last_transaction_height": last_tx_height,
        "expected_transactions": args.expected,
        "committed_transactions": committed,
        "nonempty_blocks": nonempty_blocks,
        "total_transaction_bytes": total_bytes,
        "total_gas_wanted": total_gas_wanted,
        "total_gas_used": total_gas_used,
        "observed_commit_span_seconds": elapsed,
        "mean_transactions_per_nonempty_block": (
            committed / nonempty_blocks if nonempty_blocks else 0
        ),
        "max_transactions_in_one_block": max(
            (item["tx_count"] for item in records), default=0
        ),
        "max_transaction_bytes_in_one_block": max(
            (item["tx_bytes"] for item in records), default=0
        ),
        "max_gas_used_in_one_block": max(
            (item["gas_used"] for item in records), default=0
        ),
        "failed_deliveries": sum(item["failed_deliveries"] for item in records),
    }
    with open(args.summary_out, "x", encoding="utf-8") as output:
        json.dump(summary, output, indent=2)
        output.write("\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
