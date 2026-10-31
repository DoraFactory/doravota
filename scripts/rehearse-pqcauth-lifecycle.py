#!/usr/bin/env python3
"""Four local validators with synthetic funds; never connects to a public chain.

Requires a NEW work directory and a locally executable candidate binary.
Preserves logs/receipts on failure and stops only processes this script started.
Shortened recovery delay and reduced PQC budgets are test-only genesis settings.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import traceback
import urllib.request


class Rehearsal:
    def __init__(self, args):
        self.binary = Path(args.binary).resolve(strict=True)
        self.root = Path(args.work_dir).resolve()
        self.base = args.rpc_port
        self.rounds = args.rounds
        self.chain = "pqc-isolated-" + self.root.name
        self.processes = {}
        self.logs = []
        self.addresses = {}
        self.records = []
        self.epoch = 0
        self.root.mkdir(mode=0o700)  # Deliberately refuse to overwrite a run.
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.env = {**os.environ, "GOMAXPROCS": "2"}

    def save(self, name, value):
        path = self.evidence / (name + ".json")
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    def run(self, *args, node=0):
        result = subprocess.run(
            [str(self.binary), *map(str, args), "--home", str(self.root / f"node{node}")],
            text=True, capture_output=True, timeout=90, env=self.env,
        )
        return result

    def cli(self, *args, node=0):
        result = self.run(*args, node=node)
        if result.returncode:
            raise RuntimeError(f"{args[:3]}: {result.stderr[:2000]}")
        return result.stdout

    def rpc(self, path, node=0):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.base + node * 100}/{path}", timeout=5) as r:
            return json.load(r)["result"]

    def query(self, *args):
        return json.loads(self.cli("query", *args, "--node", self.endpoint, "--output", "json"))

    @property
    def endpoint(self):
        return f"tcp://127.0.0.1:{self.base}"

    @property
    def tx_flags(self):
        return ["--chain-id", self.chain, "--node", self.endpoint,
                "--keyring-backend", "test", "--gas", "4000000",
                "--fees", "100000peaka", "-y", "--output", "json"]

    @property
    def bundle_flags(self):
        # Bundles already bind gas/fees; their commands reject mutation flags.
        return ["--chain-id", self.chain, "--node", self.endpoint,
                "--keyring-backend", "test", "--from", "owner", "-y", "--output", "json"]

    def wait(self, predicate, seconds=120):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, ValueError, KeyError, RuntimeError) as err:
                last = err
            time.sleep(0.3)
        raise RuntimeError(f"readiness timeout: {last}")

    def height(self):
        return int(self.rpc("status")["sync_info"]["latest_block_height"])

    def ready(self):
        self.wait(lambda: all(
            not self.rpc("status", i)["sync_info"]["catching_up"]
            for i in self.processes))
        old = self.height()
        self.wait(lambda: self.height() > old)

    def receipt(self, label, output):
        response = json.loads(output)
        assert int(response.get("code", 0)) == 0, response
        result = self.wait(lambda: self.query("tx", response["txhash"]))
        self.save(label, result)
        assert int(result["code"]) == 0, result
        self.records.append({"operation": label, "txhash": result["txhash"],
                             "height": result["height"], "code": result["code"]})
        print(label, result["txhash"], flush=True)
        return result

    def tx(self, label, *args, sender="owner"):
        return self.receipt(label, self.cli("tx", *args, "--from", sender, *self.tx_flags))

    def reject(self, label, args, reason):
        result = self.run(*args)
        try:
            response = json.loads(result.stdout)
        except ValueError:
            response = {}
        assert result.returncode != 0 or int(response.get("code", 0)) != 0, result.stdout
        assert reason.lower() in (result.stderr + result.stdout).lower(), (label, result.stderr, response)
        self.save(label, {"returncode": result.returncode, "response": response, "stderr": result.stderr})
        self.records.append({"operation": label, "expected_rejection": reason})

    def key(self, name, algorithm="secp256k1", node=0):
        result = json.loads(self.cli("keys", "add", name, "--key-type", algorithm,
                                     "--keyring-backend", "test", "--no-backup", "--output", "json", node=node))
        self.addresses[name] = result["address"]

    def setup(self):
        for i in range(4):
            for port in (self.base + 100 * i - 1, self.base + 100 * i):
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", port))
            self.cli("init", f"validator{i}", "--chain-id", self.chain, "--default-denom", "peaka", node=i)
            self.key(f"val{i}", node=i)
        self.key("owner")
        self.key("recipient")
        for name in ["factor0", "factor1", "factor2", "factor3", "recovery0", "recovery1"] + [f"native{i}" for i in range(8)]:
            self.key(name, "ml_dsa_65")
        genesis_path = self.root / "node0/config/genesis.json"
        genesis = json.loads(genesis_path.read_text())
        params = genesis["app_state"]["pqcauth"]["params"]
        params.update(recovery_delay_blocks="12", max_pqc_verifications_per_tx=4,
                      max_pqc_verifications_per_block=4)
        genesis_path.write_text(json.dumps(genesis))
        self.save("test-only-params", params)
        for address in self.addresses.values():
            self.cli("genesis", "add-genesis-account", address, "100000000000000000000000000peaka")
        for i in range(4):
            if i:
                (self.root / f"node{i}/config/genesis.json").write_bytes(genesis_path.read_bytes())
            self.cli("genesis", "gentx", f"val{i}", "1000000000000000000000000peaka",
                     "--chain-id", self.chain, "--keyring-backend", "test", node=i)
            if i:
                for path in (self.root / f"node{i}/config/gentx").glob("*.json"):
                    (self.root / "node0/config/gentx" / path.name).write_bytes(path.read_bytes())
        self.cli("genesis", "collect-gentxs")
        for i in range(4):
            (self.root / f"node{i}/config/genesis.json").write_bytes(genesis_path.read_bytes())
            config = self.root / f"node{i}/config/config.toml"
            config.write_text(config.read_text().replace('timeout_commit = "5s"', 'timeout_commit = "1s"')
                              .replace("allow_duplicate_ip = false", "allow_duplicate_ip = true")
                              .replace("addr_book_strict = true", "addr_book_strict = false"))
        self.ids = [self.cli("comet", "show-node-id", node=i).strip() for i in range(4)]
        self.save("binary", {"sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                             "version": self.cli("version").strip(), "chain_id": self.chain})

    def start(self, i):
        peers = ",".join(f"{self.ids[j]}@127.0.0.1:{self.base + 100*j - 1}" for j in range(4) if j != i)
        log = (self.evidence / f"node{i}-{self.epoch}.log").open("w")
        self.logs.append(log)
        port = self.base + 100 * i
        self.processes[i] = subprocess.Popen(
            [str(self.binary), "start", "--home", str(self.root / f"node{i}"),
             "--minimum-gas-prices", "0peaka", "--rpc.laddr", f"tcp://127.0.0.1:{port}",
             "--p2p.laddr", f"tcp://127.0.0.1:{port-1}", "--p2p.persistent_peers", peers,
             "--grpc.enable=false", "--grpc-web.enable=false", "--api.enable=false", "--rpc.pprof_laddr", ""],
            env=self.env, stdout=log, stderr=subprocess.STDOUT)
        self.epoch += 1

    def stop(self, i):
        process = self.processes.pop(i)
        process.terminate()
        try:
            process.wait(20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def agreement(self, label):
        self.ready()
        height = self.height()
        self.wait(lambda: all(int(self.rpc("status", i)["sync_info"]["latest_block_height"]) > height for i in range(4)))
        hashes = [self.rpc(f"block?height={height+1}", i)["block"]["header"]["app_hash"] for i in range(4)]
        assert len(set(hashes)) == 1, hashes
        self.save(label, {"state_height": height, "hashes": hashes})

    def policy(self):
        return self.query("pqcauth", "account", self.addresses["owner"])["policy"]

    def activated(self, field, key_id):
        self.wait(lambda: int(self.policy()[field]) == key_id)

    def proof(self, name, key_id, role, purpose, policy_version):
        params = self.query("pqcauth", "params")["params"]
        return json.loads(self.cli("tx", "pqcauth", "create-key-proof", name,
                         self.addresses["owner"], key_id, role, purpose,
                         "--policy-version", policy_version, "--network-id-base64", params["network_id"],
                         "--chain-id", self.chain, "--keyring-backend", "test"))

    def bundle(self, label, factor, broadcast=True):
        unsigned = self.evidence / (label + "-unsigned.json")
        unsigned.write_text(self.cli("tx", "bank", "send", self.addresses["owner"],
                           self.addresses["recipient"], "7peaka", "--from", "owner", *self.tx_flags, "--generate-only"))
        prepared = self.evidence / (label + "-prepared.json")
        signed = self.evidence / (label + "-signed.json")
        self.cli("tx", "pqcauth", "prepare-bundle", unsigned, prepared, *self.bundle_flags)
        # No RPC is supplied to the offline signing step.
        self.cli("tx", "pqcauth", "sign-bundle", prepared, factor, signed, "--keyring-backend", "test", "-y")
        if broadcast:
            self.receipt(label, self.cli("tx", "pqcauth", "broadcast-bundle", signed, *self.bundle_flags))
        return signed

    def delegated_use(self, label):
        # Phase one deliberately preserves delegated ordinary operations, even
        # after enrollment/recovery. Only the grantee signs this execution.
        unsigned = self.evidence / (label + "-authz.json")
        unsigned.write_text(self.cli("tx", "bank", "send", self.addresses["owner"],
                           self.addresses["recipient"], "2peaka", "--from", "owner",
                           *self.tx_flags, "--generate-only"))
        self.tx(label + "-authz", "authz", "exec", unsigned, sender="recipient")
        before = self.balance(self.addresses["owner"])
        self.tx(label + "-feegrant", "bank", "send", self.addresses["recipient"],
                self.addresses["recipient"], "1peaka", "--fee-granter",
                self.addresses["owner"], sender="recipient")
        assert before - self.balance(self.addresses["owner"]) == 100000

    def lifecycle(self):
        self.tx("pre-enrollment-authz", "authz", "grant", self.addresses["recipient"],
                "generic", "--msg-type", "/cosmos.bank.v1beta1.MsgSend")
        self.tx("pre-enrollment-feegrant", "feegrant", "grant", self.addresses["owner"],
                self.addresses["recipient"], "--spend-limit", "1000000peaka")
        p = self.proof("factor0", 1, "signing", "register-signing", 0)
        r = self.proof("recovery0", 2, "recovery", "register-recovery", 0)
        self.tx("register", "pqcauth", "register-key", "1", p["public_key_base64"], p["proof_base64"],
                "--recovery-public-key-base64", r["public_key_base64"], "--recovery-proof-base64", r["proof_base64"])
        self.activated("current_signing_key_id", 1)
        self.delegated_use("after-enrollment")
        self.bundle("offline-transfer", "factor0")
        stale = self.bundle("pre-rotation", "factor0", broadcast=False)
        p = self.proof("factor1", 3, "signing", "rotate-signing", self.policy()["policy_version"])
        self.tx("rotate-signing", "pqcauth", "rotate-key", "3", p["public_key_base64"], p["proof_base64"], "--pqc-key", "factor0")
        self.activated("current_signing_key_id", 3)
        self.reject("stale-bundle-rejected", ["tx", "pqcauth", "broadcast-bundle", stale, *self.bundle_flags], "sequence")
        self.reject("old-factor-rejected", ["tx", "pqcauth", "set-protection", "true", "--pqc-key", "factor0", "--from", "owner", *self.tx_flags], "does not match")
        self.bundle("rotated-transfer", "factor1")
        p = self.proof("recovery1", 4, "recovery", "rotate-recovery", self.policy()["policy_version"])
        self.tx("rotate-recovery", "pqcauth", "rotate-recovery-key", "4", p["public_key_base64"], p["proof_base64"], "--pqc-key", "factor1")
        self.activated("recovery_key_id", 4)
        p = self.proof("factor2", 5, "signing", "recover-signing", self.policy()["policy_version"])
        args = ["pqcauth", "recover-key", "4", "5", p["public_key_base64"], p["proof_base64"]]
        self.reject("old-recovery-rejected", ["tx", *args, "--recovery-key", "recovery0", "--from", "owner", *self.tx_flags], "does not match")
        self.tx("request-recovery-cancel", *args, "--recovery-key", "recovery1")
        pending = self.policy()
        assert int(pending["current_signing_key_id"]) == 3
        self.tx("cancel-recovery", "pqcauth", "cancel-recovery", "5", pending["pending_policy_version"], "--pqc-key", "factor1")
        cancel_height = int(pending["pending_effective_height"])
        self.wait(lambda: self.height() > cancel_height)
        assert int(self.policy()["current_signing_key_id"]) == 3
        p = self.proof("factor3", 6, "signing", "recover-signing", self.policy()["policy_version"])
        self.tx("request-recovery-activate", "pqcauth", "recover-key", "4", "6", p["public_key_base64"], p["proof_base64"], "--recovery-key", "recovery1")
        pending = self.policy()
        assert int(pending["current_signing_key_id"]) == 3
        self.save("pending-recovery", pending)
        self.reject("early-factor-rejected", ["tx", "pqcauth", "set-protection", "true", "--pqc-key", "factor3", "--from", "owner", *self.tx_flags], "does not match")
        # Restart while the recovery is pending, then wait for the exact boundary.
        for i in list(self.processes):
            self.stop(i)
        for i in range(4):
            self.start(i)
        self.ready()
        self.activated("current_signing_key_id", 6)
        self.bundle("recovered-transfer", "factor3")
        self.delegated_use("after-recovery-and-restart")
        self.reject("pre-recovery-factor-rejected", ["tx", "pqcauth", "set-protection", "true", "--pqc-key", "factor1", "--from", "owner", *self.tx_flags], "does not match")
        self.reject("classic-only-rejected", ["tx", "bank", "send", self.addresses["owner"], self.addresses["recipient"], "1peaka", "--from", "owner", *self.tx_flags], "PQC")
        self.agreement("lifecycle-agreement")

    def load(self):
        started = time.monotonic()
        first_height = self.height()
        for round_id in range(self.rounds):
            if round_id == 1:
                self.stop(3)
            if round_id == 3:
                self.start(3)
                self.ready()
            def native(i):
                return self.tx(f"load-{round_id}-native-{i}", "bank", "send", self.addresses[f"native{i}"],
                               self.addresses["recipient"], "1peaka", sender=f"native{i}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(native, range(8)))
            self.tx(f"load-{round_id}-classic", "bank", "send", self.addresses["val0"], self.addresses["recipient"], "1peaka", sender="val0")
            self.bundle(f"load-{round_id}-hybrid", "factor3")
        self.agreement("load-agreement")
        last_height = self.height()
        blocks = []
        for height in range(first_height + 1, last_height + 1):
            block = self.rpc(f"block?height={height}")["block"]
            blocks.append({"height": height, "time": block["header"]["time"], "tx_count": len(block["data"].get("txs") or [])})
        self.save("load-metrics", {"rounds": self.rounds, "successful_transfers": self.rounds * 10,
                  "elapsed_seconds": time.monotonic() - started, "blocks": blocks,
                  "scope": "bounded mixed traffic with 1 of 4 validators offline during rounds 1 and 2; not a throughput benchmark or long soak"})
        native_per_height = {}
        for record in self.records:
            if record["operation"].startswith("load-") and "-native-" in record["operation"]:
                height = record["height"]
                native_per_height[height] = native_per_height.get(height, 0) + 1
        assert all(count <= 4 for count in native_per_height.values()), native_per_height
        self.save("native-budget-counts", native_per_height)

    def history_churn(self):
        # Keep key 6 active while newer cancelled recovery keys exceed the
        # default retention (16), then retire key 6 after those higher IDs.
        for key_id in range(7, 24):
            factor = f"cancelled-{key_id}"
            self.key(factor, "ml_dsa_65")
            p = self.proof(factor, key_id, "signing", "recover-signing", self.policy()["policy_version"])
            self.tx(f"history-request-{key_id}", "pqcauth", "recover-key", "4", str(key_id),
                    p["public_key_base64"], p["proof_base64"], "--recovery-key", "recovery1")
            pending = self.policy()
            self.tx(f"history-cancel-{key_id}", "pqcauth", "cancel-recovery", str(key_id),
                    pending["pending_policy_version"], "--pqc-key", "factor3")
        account = self.query("pqcauth", "account", self.addresses["owner"])
        self.save("history-before-rotation", account)
        assert int(account["policy"]["current_signing_key_id"]) == 6
        history = next(h for h in account["key_histories"] if h["role"] == "KEY_ROLE_SIGNING")
        assert int(history["last_compacted_key_id"]) > 6, history
        count_before = int(history["compacted_count"])
        old_factor = "factor3"
        for key_id in (24, 25):
            factor = f"history-final-{key_id}"
            self.key(factor, "ml_dsa_65")
            p = self.proof(factor, key_id, "signing", "rotate-signing", self.policy()["policy_version"])
            self.tx(f"history-rotate-{key_id}", "pqcauth", "rotate-key", str(key_id),
                    p["public_key_base64"], p["proof_base64"], "--pqc-key", old_factor)
            self.activated("current_signing_key_id", key_id)
            old_factor = factor
        self.bundle("history-post-rotation-transfer", old_factor)
        account = self.query("pqcauth", "account", self.addresses["owner"])
        keys = self.query("pqcauth", "keys", self.addresses["owner"])
        self.save("history-after-rotation", {"account": account, "keys": keys})
        history = next(h for h in account["key_histories"] if h["role"] == "KEY_ROLE_SIGNING")
        assert int(history["compacted_count"]) > count_before, history
        assert all(int(k["key_id"]) != 6 for k in keys["keys"]), keys
        assert not keys.get("pagination", {}).get("next_key"), keys
        self.agreement("history-agreement")
        for i in list(self.processes):
            self.stop(i)
        for i in range(4):
            self.start(i)
        self.ready()
        assert self.query("pqcauth", "account", self.addresses["owner"]) == account
        self.agreement("history-restart-agreement")

    def balance(self, address):
        balances = self.query("bank", "balances", address)["balances"]
        return sum(int(coin["amount"]) for coin in balances if coin["denom"] == "peaka")

    def recipient_balance(self):
        return self.balance(self.addresses["recipient"])

    def execute(self):
        try:
            self.setup()
            for i in range(4):
                self.start(i)
            self.ready()
            self.agreement("initial-agreement")
            balance_before = self.recipient_balance()
            self.lifecycle()
            self.load()
            self.history_churn()
            balance_after = self.recipient_balance()
            # Two delegated sends add 4; their grantee pays 2 * 100000 fees.
            expected = 4 * 7 + self.rounds * (8 + 1 + 7) + 4 - 2 * 100000
            assert balance_after - balance_before == expected
            self.save("recipient-balance", {"before": str(balance_before), "after": str(balance_after),
                      "expected_increase_peaka": expected})
            self.save("result", {"status": "PASS", "chain_id": self.chain, "records": self.records,
                      "scope": "isolated synthetic network only; no public testnet, IBC counterparties or physical Ledger"})
        except BaseException:
            self.save("failure", {"traceback": traceback.format_exc(), "records": self.records})
            raise
        finally:
            for i in list(self.processes):
                self.stop(i)
            for log in self.logs:
                log.close()


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise SystemExit(f"interrupted by signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--work-dir", required=True, help="new directory; existing runs are never overwritten")
    parser.add_argument("--rpc-port", type=int, default=47757)
    parser.add_argument("--rounds", type=int, default=8)
    args = parser.parse_args()
    if not 1025 <= args.rpc_port <= 65000 or not 4 <= args.rounds <= 100:
        parser.error("rpc-port must be 1025..65000; rounds must be 4..100")
    Rehearsal(args).execute()
