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
import urllib.error
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


def install_hybrid_public_keys(genesis, generated):
    """A pre-enrolled synthetic owner must already have its classic SDK key."""
    owners = set(generated["addresses"])
    keys = generated["account_public_keys"]
    if len(owners) != 7 or set(keys) != owners:
        raise ValueError("hybrid fixture must contain exactly seven owner public keys")
    matched = set()
    for account in genesis["app_state"]["auth"]["accounts"]:
        owner = account.get("address")
        if owner not in owners:
            continue
        key = keys[owner]
        if (owner in matched or account.get("@type") != "/cosmos.auth.v1beta1.BaseAccount"
                or account.get("pub_key") is not None
                or key.get("@type") != "/cosmos.crypto.secp256k1.PubKey" or not key.get("key")):
            raise ValueError(f"unexpected hybrid fixture account/key: {owner}")
        account["pub_key"] = dict(key)
        matched.add(owner)
    if matched != owners:
        raise ValueError("hybrid fixture owner missing from auth genesis")


def results_not_saved_yet(status, body, height):
    """Only retry CometBFT v0.40's exact missing-result response for THIS height.

    Do not retry arbitrary 500s, pruned/corrupt data or disabled result storage.
    Even a matching error is only presumed transient until the deadline.
    """
    if status != 500:
        return False
    try:
        error = json.loads(body)["error"]
        return (error["code"] == -32603 and
                error["data"] == f"could not find results for height #{height}")
    except (ValueError, KeyError, TypeError):
        return False


def record_results_error(r, height, error, body, truncated, retryable, deadline, now):
    record = {"height": height, "path": f"block_results?height={height}",
              "http_status": error.code, "body": body.decode("utf-8", errors="replace"),
              "body_truncated": truncated, "retryable": retryable,
              "remaining_seconds": max(0, deadline - now()),
              "process_exit_codes": {str(i): p.poll() for i, p in r.processes.items()}}
    # A diagnostic failure must not convert a permanent query error into a retry.
    remaining = deadline - now()
    if remaining > 0:
        try:
            record["node0_status"] = r.rpc("status", timeout=min(.5, remaining))
        except Exception as diagnostic_error:
            record["status_error"] = repr(diagnostic_error)
    with (r.evidence / "block-results-errors.jsonl").open("a") as log:
        log.write(json.dumps(record) + "\n")


def read_finalized_block(r, height, deadline, *, now=time.monotonic, sleep=time.sleep):
    """Read one complete height, or fail without advancing the caller's cursor."""
    remaining = deadline - now()
    if remaining <= 0:
        raise TimeoutError(f"deadline before block {height}")
    block = r.rpc(f"block?height={height}", timeout=min(5, remaining))["block"]
    if int(block["header"]["height"]) != height:
        raise ValueError(f"block height mismatch at {height}")
    transactions = block["data"]["txs"]
    if transactions is not None and not isinstance(transactions, list):
        raise ValueError(f"invalid block transaction list at {height}")
    expected = len(transactions or [])
    while True:
        remaining = deadline - now()
        if remaining <= 0:
            raise TimeoutError(f"deadline waiting for execution results at height {height}")
        try:
            receipt = r.rpc(f"block_results?height={height}", timeout=min(5, remaining))
        except urllib.error.HTTPError as error:
            body = error.read(65537)
            error.close()
            truncated = len(body) > 65536
            body = body[:65536]
            retryable = not truncated and results_not_saved_yet(error.code, body, height)
            record_results_error(r, height, error, body, truncated, retryable, deadline, now)
            if not retryable:
                raise
            remaining = deadline - now()
            if remaining <= 0:
                raise TimeoutError(f"deadline waiting for execution results at height {height}") from error
            sleep(min(.25, remaining))
            continue
        if now() >= deadline:
            raise TimeoutError(f"execution results arrived after deadline at height {height}")
        if int(receipt["height"]) != height:
            raise ValueError(f"execution result height mismatch at {height}")
        outcomes = receipt["txs_results"]
        if outcomes is None:
            outcomes = []
        if not isinstance(outcomes, list) or len(outcomes) != expected:
            r.save(f"invalid-results-{height}", {"block": block, "receipt": receipt})
            raise ValueError(f"execution result count mismatch at height {height}: expected {expected}")
        if any(int(x["code"]) != 0 for x in outcomes):
            r.save(f"failed-transactions-{height}", receipt)
            raise ValueError(f"failed transaction at height {height}")
        return block, receipt


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
    if not 1 <= args.count <= 5000 or args.baseline_blocks < 3 or args.timeout <= 0:
        parser.error("count must be 1..5000; baseline-blocks >= 3; timeout > 0")
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
        if args.kind == "hybrid":
            install_hybrid_public_keys(genesis, generated)
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
                next_height = scanned + 1
                block, receipt = read_finalized_block(r, next_height, deadline)
                outcomes = receipt.get("txs_results") or []
                committed += len(outcomes)
                blocks.append({"height": next_height, "time": block["header"]["time"], "timestamp": block_time(block),
                               "transactions": len(outcomes), "signature_verifications": len(outcomes) * 7,
                               "gas_used": sum(int(x["gas_used"]) for x in outcomes)})
                r.save("loaded-blocks", blocks)
                # Advance only after the matching complete results are validated.
                scanned = next_height
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
