#!/usr/bin/env python3
"""Observe live blocks and analyze confirmation metrics for a load phase."""

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
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
                payload = json.load(response)
                if "result" not in payload:
                    raise urllib.error.URLError(payload.get("error", "missing RPC result"))
                return payload["result"]
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            if time.time() >= deadline:
                raise
            time.sleep(0.25)


def parse_time(value):
    if value.endswith("Z") and "." in value:
        head, fraction = value[:-1].split(".", 1)
        value = f"{head}.{fraction[:6].ljust(6, '0')}+00:00"
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def percentile(values, quantile):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def unconfirmed(base):
    result = rpc(base, "/num_unconfirmed_txs")
    return int(result.get("n_txs", result.get("total", "0")))


def observe(args):
    next_height = args.start_height + 1
    previous_block_time = None
    deadline = time.time() + args.timeout
    with open(args.blocks_out, "x", encoding="utf-8", buffering=1) as output:
        while time.time() < deadline:
            latest = int(rpc(args.rpc, "/status")["sync_info"]["latest_block_height"])
            while next_height <= latest:
                block_response = rpc(args.rpc, "/block", {"height": next_height})
                block = block_response["block"]
                results = rpc(args.rpc, "/block_results", {"height": next_height})
                commit = rpc(args.rpc, "/commit", {"height": next_height})
                observed_at = utc_now()
                txs = block.get("data", {}).get("txs") or []
                tx_results = results.get("txs_results") or []
                block_time = parse_time(block["header"]["time"])
                interval = 0.0 if previous_block_time is None else (block_time - previous_block_time).total_seconds()
                previous_block_time = block_time
                record = {
                    "height": next_height,
                    "header_time": block["header"]["time"],
                    "observed_at_utc": observed_at.isoformat().replace("+00:00", "Z"),
                    "interval_seconds": interval,
                    "consensus_round": int(commit["signed_header"]["commit"].get("round", 0)),
                    "tx_count": len(txs),
                    "tx_hashes": [hashlib.sha256(base64.b64decode(value)).hexdigest() for value in txs],
                    "tx_bytes": sum(len(base64.b64decode(value)) for value in txs),
                    "gas_wanted": sum(int(item.get("gas_wanted", "0")) for item in tx_results),
                    "gas_used": sum(int(item.get("gas_used", "0")) for item in tx_results),
                    "failed_deliveries": sum(1 for item in tx_results if int(item.get("code", 0)) != 0),
                    "block_hash": block_response.get("block_id", {}).get("hash", ""),
                }
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
                next_height += 1

            if os.path.exists(args.stop_file) and unconfirmed(args.rpc) == 0:
                # Re-read status once after the empty-mempool observation so a
                # just-committed height cannot be missed by the prior snapshot.
                final_latest = int(rpc(args.rpc, "/status")["sync_info"]["latest_block_height"])
                if next_height > final_latest:
                    return
            time.sleep(0.1)
    raise SystemExit(f"observer timeout at next height {next_height}")


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


def analyze(args):
    expected = load_expected(args.broadcast_results)
    if not expected:
        raise SystemExit("no accepted transaction hashes to analyze")
    found = {}
    records = []
    with open(args.observations, encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            observed_at = parse_time(record["observed_at_utc"])
            matched_modes = Counter()
            matched_latencies = []
            for tx_hash in record.pop("tx_hashes"):
                metadata = expected.get(tx_hash)
                if metadata is None:
                    continue
                latency = (observed_at - metadata["submitted"]).total_seconds()
                if latency < 0:
                    raise SystemExit(
                        f"negative observed confirmation latency {latency} for {tx_hash}"
                    )
                found[tx_hash] = {
                    "height": record["height"],
                    "observed_at": observed_at,
                    "latency_seconds": latency,
                    "mode": metadata["mode"],
                }
                matched_modes[metadata["mode"]] += 1
                matched_latencies.append(latency)
            record["phase"] = args.phase
            record["matched_transactions"] = len(matched_latencies)
            record["matched_modes"] = dict(matched_modes)
            record["matched_latency_p50_seconds"] = percentile(matched_latencies, 0.50)
            record["matched_latency_p99_seconds"] = percentile(matched_latencies, 0.99)
            records.append(record)

    missing = set(expected) - set(found)
    if missing:
        raise SystemExit(
            f"observations missing {len(missing)} accepted transactions; sample={list(missing)[:5]}"
        )
    all_latencies = [item["latency_seconds"] for item in found.values()]
    by_mode = defaultdict(list)
    for item in found.values():
        by_mode[item["mode"]].append(item["latency_seconds"])
    nonempty = [item for item in records if item["matched_transactions"]]
    intervals = [item["interval_seconds"] for item in records if item["interval_seconds"] > 0]
    first_submit = min(item["submitted"] for item in expected.values())
    last_observed = max(item["observed_at"] for item in found.values())
    wall_seconds = max(0.0, (last_observed - first_submit).total_seconds())
    summary = {
        "phase": args.phase,
        "first_observed_height": records[0]["height"] if records else None,
        "last_observed_height": records[-1]["height"] if records else None,
        "expected_transactions": len(expected),
        "committed_transactions": len(found),
        "failed_deliveries": sum(item["failed_deliveries"] for item in records),
        "nonempty_blocks": len(nonempty),
        "wall_seconds": wall_seconds,
        "committed_transactions_per_second": len(found) / wall_seconds if wall_seconds else 0,
        "confirmation_latency_seconds": {
            "basis": "observer_wall_clock_minus_submission_wall_clock",
            "observer_poll_interval_seconds": 0.1,
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
            "basis": "successive_block_header_times",
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


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    watch = subparsers.add_parser("watch")
    watch.add_argument("--rpc", required=True)
    watch.add_argument("--start-height", type=int, required=True)
    watch.add_argument("--stop-file", required=True)
    watch.add_argument("--blocks-out", required=True)
    watch.add_argument("--timeout", type=int, default=1800)

    report = subparsers.add_parser("analyze")
    report.add_argument("--phase", required=True)
    report.add_argument("--broadcast-results", required=True)
    report.add_argument("--observations", required=True)
    report.add_argument("--summary-out", required=True)

    args = parser.parse_args()
    if args.command == "watch":
        observe(args)
    else:
        analyze(args)


if __name__ == "__main__":
    main()
