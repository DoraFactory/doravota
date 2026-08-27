#!/usr/bin/env python3
"""Collect block, confirmation-latency, and consensus-round metrics for a load phase."""

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict


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
            time.sleep(0.25)


def parse_time(value):
    if value.endswith("Z") and "." in value:
        head, fraction = value[:-1].split(".", 1)
        value = f"{head}.{fraction[:6].ljust(6, '0')}+00:00"
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def percentile(values, quantile):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def load_expected(path):
    expected = {}
    with open(path, encoding="utf-8") as source:
        for line in source:
            item = json.loads(line)
            if not item.get("accepted"):
                continue
            tx_hash = item["expected_hash"].lower()
            if tx_hash in expected:
                raise SystemExit(f"duplicate accepted transaction hash {tx_hash}")
            expected[tx_hash] = {
                "mode": item["mode"],
                "submitted": parse_time(item["submitted_at_utc"]),
            }
    return expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--start-height", required=True, type=int)
    parser.add_argument("--broadcast-results", required=True)
    parser.add_argument("--blocks-out", required=True)
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()

    expected = load_expected(args.broadcast_results)
    if not expected:
        raise SystemExit("no accepted transaction hashes to collect")
    found = {}
    records = []
    next_height = args.start_height + 1
    deadline = time.time() + args.timeout
    previous_block_time = None

    while time.time() < deadline:
        status = rpc(args.rpc, "/status")
        latest = int(status["sync_info"]["latest_block_height"])
        while next_height <= latest:
            block_response = rpc(args.rpc, "/block", {"height": next_height})
            block = block_response["block"]
            results = rpc(args.rpc, "/block_results", {"height": next_height})
            commit = rpc(args.rpc, "/commit", {"height": next_height})
            txs = block.get("data", {}).get("txs") or []
            tx_results = results.get("txs_results") or []
            block_time = parse_time(block["header"]["time"])
            interval = 0.0 if previous_block_time is None else (block_time - previous_block_time).total_seconds()
            previous_block_time = block_time
            matched = 0
            matched_modes = Counter()
            latencies = []
            for encoded in txs:
                raw = base64.b64decode(encoded)
                tx_hash = hashlib.sha256(raw).hexdigest()
                metadata = expected.get(tx_hash)
                if metadata is None:
                    continue
                latency = (block_time - metadata["submitted"]).total_seconds()
                found[tx_hash] = {
                    "height": next_height,
                    "block_time": block["header"]["time"],
                    "latency_seconds": latency,
                    "mode": metadata["mode"],
                }
                matched += 1
                matched_modes[metadata["mode"]] += 1
                latencies.append(latency)
            record = {
                "phase": args.phase,
                "height": next_height,
                "time": block["header"]["time"],
                "interval_seconds": interval,
                "consensus_round": int(commit["signed_header"]["commit"].get("round", 0)),
                "tx_count": len(txs),
                "matched_transactions": matched,
                "matched_modes": dict(matched_modes),
                "tx_bytes": sum(len(base64.b64decode(value)) for value in txs),
                "gas_wanted": sum(int(item.get("gas_wanted", "0")) for item in tx_results),
                "gas_used": sum(int(item.get("gas_used", "0")) for item in tx_results),
                "failed_deliveries": sum(1 for item in tx_results if int(item.get("code", 0)) != 0),
                "matched_latency_p50_seconds": percentile(latencies, 0.50),
                "matched_latency_p99_seconds": percentile(latencies, 0.99),
                "block_hash": block_response.get("block_id", {}).get("hash", ""),
            }
            records.append(record)
            next_height += 1

        unconfirmed = rpc(args.rpc, "/num_unconfirmed_txs")
        pending = int(unconfirmed.get("n_txs", unconfirmed.get("total", "0")))
        if len(found) == len(expected) and pending == 0:
            break
        time.sleep(0.5)
    else:
        missing = list(set(expected) - set(found))[:5]
        raise SystemExit(
            f"timeout: found={len(found)}, expected={len(expected)}, sample_missing={missing}"
        )

    with open(args.blocks_out, "x", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, separators=(",", ":")) + "\n")

    all_latencies = [item["latency_seconds"] for item in found.values()]
    by_mode = defaultdict(list)
    for item in found.values():
        by_mode[item["mode"]].append(item["latency_seconds"])
    nonempty = [item for item in records if item["matched_transactions"]]
    intervals = [item["interval_seconds"] for item in records if item["interval_seconds"] > 0]
    first_submit = min(item["submitted"] for item in expected.values())
    last_commit = max(parse_time(item["block_time"]) for item in found.values())
    wall_seconds = max(0.0, (last_commit - first_submit).total_seconds())
    summary = {
        "phase": args.phase,
        "start_height": args.start_height,
        "last_observed_height": records[-1]["height"] if records else args.start_height,
        "expected_transactions": len(expected),
        "committed_transactions": len(found),
        "failed_deliveries": sum(item["failed_deliveries"] for item in records),
        "nonempty_blocks": len(nonempty),
        "wall_seconds": wall_seconds,
        "committed_transactions_per_second": len(found) / wall_seconds if wall_seconds else 0,
        "confirmation_latency_seconds": {
            "p50": percentile(all_latencies, 0.50),
            "p95": percentile(all_latencies, 0.95),
            "p99": percentile(all_latencies, 0.99),
            "max": max(all_latencies, default=0),
        },
        "confirmation_latency_by_mode_seconds": {
            mode: {
                "count": len(values),
                "p50": percentile(values, 0.50),
                "p95": percentile(values, 0.95),
                "p99": percentile(values, 0.99),
            }
            for mode, values in sorted(by_mode.items())
        },
        "block_interval_seconds": {
            "p50": percentile(intervals, 0.50),
            "p95": percentile(intervals, 0.95),
            "p99": percentile(intervals, 0.99),
            "max": max(intervals, default=0),
        },
        "consensus_rounds": dict(Counter(item["consensus_round"] for item in records)),
        "max_transactions_in_block": max((item["matched_transactions"] for item in records), default=0),
        "max_gas_wanted_in_block": max((item["gas_wanted"] for item in records), default=0),
        "max_gas_used_in_block": max((item["gas_used"] for item in records), default=0),
        "max_transaction_bytes_in_block": max((item["tx_bytes"] for item in records), default=0),
    }
    with open(args.summary_out, "x", encoding="utf-8") as output:
        json.dump(summary, output, indent=2)
        output.write("\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
