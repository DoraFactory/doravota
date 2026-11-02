#!/usr/bin/env python3
"""Opt-in, localhost-only four-validator load experiment using PUBLIC test keys.

Requires a fresh directory, candidate dorad, and `go test -c ./app` fixture binary.
No external RPC, production wallet or mainnet snapshot is accepted. Preserves
evidence, stops only children it started. Throughput is NOT a hardware guarantee.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import time
import traceback
import urllib.request

spec = importlib.util.spec_from_file_location("lifecycle", Path(__file__).with_name("rehearse-pqcauth-lifecycle.py"))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


def percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else None


def account_number(value):
    if isinstance(value, dict):
        if "account_number" in value:
            return int(value["account_number"])
        for nested in value.values():
            result = account_number(nested)
            if result is not None:
                return result
    return None


def block_time(block):
    return datetime.datetime.fromisoformat(block["header"]["time"].replace("Z", "+00:00")).timestamp()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--fixture-binary", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--kind", choices=["hybrid", "classic", "native"], required=True)
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--rpc-port", type=int, default=28657)
    parser.add_argument("--baseline-blocks", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if not 1 <= args.count <= 5000 or args.baseline_blocks < 3:
        parser.error("count must be 1..5000; baseline-blocks >= 3")
    args.rounds = 1
    fixture = Path(args.fixture_binary).resolve(strict=True)
    r = lifecycle.Rehearsal(args)
    result = {"kind": args.kind, "requested_txs": args.count, "signers_per_tx": 7, "declared_gas_per_tx": 3000000,
              "limitations": ["single shared host, not minimum hardware certification",
                              "synthetic funded accounts, no fee economics conclusion",
                              "homogeneous valid load, not exhaustive malicious admission testing"],
              "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()}
    def generate(config):
        r.save("load-config", config)
        with (r.evidence / ("fixture-" + config["phase"] + ".log")).open("w") as log:
            subprocess.run([str(fixture), "-test.run=^TestPQCAuthGenerateNetworkLoad$", "-test.v", "-test.timeout=10m"],
                           env={**r.env, "PQC_NETWORK_LOAD_DIR": str(r.evidence)}, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=610)
    try:
        r.setup()
        gp = r.root / "node0/config/genesis.json"
        genesis = json.loads(gp.read_text())
        config = {"chain_id": r.chain, "kind": args.kind, "phase": "prepare", "count": args.count,
                  "params": genesis["app_state"]["pqcauth"]["params"]}
        generate(config)
        generated = json.loads((r.evidence / "load-genesis.json").read_text())
        for address in generated["addresses"]:
            r.cli("genesis", "add-genesis-account", address, "100000000000000000000000000peaka")
        genesis = json.loads(gp.read_text())
        genesis["app_state"]["pqcauth"] = generated["pqcauth"]
        genesis["consensus"]["params"]["block"].update(max_gas="600000000", max_bytes="22020096")
        # These are declared experiment settings, not a query of mainnet.
        result["block_settings"] = {"max_gas": 600000000, "max_bytes": 22020096, "timeout_commit_seconds": 5}
        for i in range(4):
            (r.root / f"node{i}/config/genesis.json").write_text(json.dumps(genesis))
            cp = r.root / f"node{i}/config/config.toml"
            cp.write_text(cp.read_text().replace('timeout_commit = "1s"', 'timeout_commit = "5s"'))
            r.start(i)
        r.ready()
        first = r.height()
        r.wait(lambda: r.height() >= first + args.baseline_blocks, seconds=180)
        baseline = [r.rpc(f"block?height={h}")["block"] for h in range(first, first + args.baseline_blocks + 1)]
        intervals = [block_time(b) - block_time(a) for a, b in zip(baseline, baseline[1:])]
        result["baseline_intervals_seconds"] = intervals
        config.update(phase="sign", params=r.query("pqcauth", "params")["params"], account_numbers={address: account_number(r.query("auth", "account", address))
                                                    for address in generated["addresses"]})
        assert all(v is not None for v in config["account_numbers"].values())
        generate(config)
        # Temporarily remove quorum so initial CheckTx genuinely fills the pool.
        # All validators and all funds are synthetic and owned by this process.
        for i in (1, 2, 3):
            r.stop(i)
        start_height = r.height()
        admissions = []
        begin = time.monotonic()
        url = f"http://127.0.0.1:{r.base}/"
        with (r.evidence / "load-txs.jsonl").open() as txs, (r.evidence / "admission.jsonl").open("w") as logs:
            for index, line in enumerate(txs):
                tx = json.loads(line)
                req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": index,
                    "method": "broadcast_tx_sync", "params": {"tx": tx["tx"]}}).encode(), {"Content-Type": "application/json"})
                before = time.monotonic()
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.load(response)
                elapsed = time.monotonic() - before
                record = {"index": index, "seconds": elapsed, "bytes": tx["bytes"], "response": data}
                logs.write(json.dumps(record) + "\n")
                assert "result" in data and int(data["result"]["code"]) == 0, record
                admissions.append(elapsed)
                if (index + 1) % 500 == 0:
                    print("admitted", index + 1, "seconds", round(time.monotonic() - begin, 2), flush=True)
        assert int(r.rpc("num_unconfirmed_txs")["n_txs"]) == args.count
        result["admission_seconds"] = time.monotonic() - begin
        result["admission_p95_seconds"] = percentile(admissions, .95)
        r.save("full-mempool", r.rpc("num_unconfirmed_txs"))
        for i in (1, 2, 3):
            r.start(i)
        drain_start = time.monotonic()
        blocks = []
        committed = 0
        scanned = start_height
        deadline = drain_start + args.timeout
        peak_rss = 0
        while committed < args.count:
            if time.monotonic() > deadline:
                raise TimeoutError(f"committed {committed}/{args.count}")
            current = r.height()
            while scanned < current:
                scanned += 1
                block = r.rpc(f"block?height={scanned}")["block"]
                receipt = r.rpc(f"block_results?height={scanned}")
                outcomes = receipt.get("txs_results") or []
                assert all(int(x["code"]) == 0 for x in outcomes), receipt
                committed += len(outcomes)
                blocks.append({"height": scanned, "time": block["header"]["time"], "timestamp": block_time(block),
                               "transactions": len(outcomes), "signature_verifications": len(outcomes) * 7,
                               "gas_used": sum(int(x["gas_used"]) for x in outcomes)})
                r.save("loaded-blocks", blocks)
                print("block", scanned, "committed", committed, "pool", r.rpc("num_unconfirmed_txs")["n_txs"], flush=True)
            total_rss = 0
            for process in r.processes.values():
                for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        total_rss += int(line.split()[1]) * 1024
            peak_rss = max(peak_rss, total_rss)
            time.sleep(.5)
        assert committed == args.count
        result["drain_seconds"] = time.monotonic() - drain_start
        r.agreement("final-four-validator-agreement")
        for address in generated["addresses"]:
            account = r.query("auth", "account", address)
            r.save("account-" + address, account)
        loaded = [b["timestamp"] - a["timestamp"] for a, b in zip(blocks, blocks[1:]) if a["transactions"] and b["transactions"]]
        result.update(committed=committed, peak_four_process_rss_bytes=peak_rss,
                      loaded_intervals_seconds=loaded, baseline_p95_seconds=percentile(intervals, .95),
                      loaded_p95_seconds=percentile(loaded, .95),
                      max_verifications_in_block=max(b["signature_verifications"] for b in blocks),
                      functional_pass=True)
        result["p95_within_15_percent_baseline"] = bool(loaded and result["loaded_p95_seconds"] <= 1.15 * result["baseline_p95_seconds"])
        # Initial resume interval excluded because quorum was intentionally stopped.
        # This does not measure recheck alone; do not infer it from block intervals.
        r.save("result", result)
        print(json.dumps(result, indent=2), flush=True)
    except BaseException:
        result.update(functional_pass=False, failure=traceback.format_exc())
        r.save("result", result)
        raise
    finally:
        for i in list(r.processes):
            r.stop(i)
        for log in r.logs:
            log.close()


if __name__ == "__main__":
    main()
