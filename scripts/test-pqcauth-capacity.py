#!/usr/bin/env python3
"""Offline regression tests for the capacity observer; no network/node claims."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

spec = importlib.util.spec_from_file_location("capacity", Path(__file__).with_name("rehearse-pqcauth-capacity.py"))
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def missing(height=18, status=500, data=None):
    if data is None:
        data = f"could not find results for height #{height}"
    body = json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error", "data": data}}).encode()
    return urllib.error.HTTPError("http://127.0.0.1/block_results", status, "error", {}, io.BytesIO(body))


class Node:
    def __init__(self, directory, replies, count=1):
        self.evidence = Path(directory)
        self.processes = {}
        self.replies = list(replies)
        self.calls = []
        self.block = {"header": {"height": "18"}, "data": {"txs": ["synthetic"] * count or None}}

    def rpc(self, path, node=0, timeout=5):
        self.calls.append((path, timeout))
        if path == "status":
            return {"sync_info": {"latest_block_height": "18"}}
        if path.startswith("block?"):
            return {"block": self.block}
        response = self.replies.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response()
        return response

    def save(self, name, value):
        (self.evidence / (name + ".json")).write_text(json.dumps(value))


class CapacityObserverTests(unittest.TestCase):
    def test_gate_pause_disconnects_flows_and_resume_reenables_acceptance(self):
        gate = object.__new__(capacity.LoopbackGate)
        gate.lock = capacity.threading.Lock()
        gate.enabled = True
        flow = (Mock(), Mock())
        gate.flows = {flow}
        gate.pause()
        self.assertFalse(gate.enabled)
        for sock in flow:
            sock.shutdown.assert_called_once_with(capacity.socket.SHUT_RDWR)
            sock.close.assert_called_once()
        gate.resume()
        self.assertTrue(gate.enabled)

    def test_isolated_prefill_checks_every_pool(self):
        r = Mock()
        def reply(path, node):
            return {"status": {"sync_info": {"latest_block_height": "50"}},
                    "net_info": {"n_peers": "0"}, "num_unconfirmed_txs": {"n_txs": "5000"}}[path]
        r.rpc.side_effect = reply
        self.assertEqual(len(capacity.verify_isolated_pools(r, 50, 5000)), 4)
        self.assertEqual(r.rpc.call_count, 12)
        for path, value in [("status", {"sync_info": {"latest_block_height": "51"}}),
                            ("net_info", {"n_peers": "1"}),
                            ("num_unconfirmed_txs", {"n_txs": "4999"})]:
            with self.subTest(path=path):
                r.rpc.side_effect = lambda p, n: value if p == path and n == 3 else reply(p, n)
                with self.assertRaises(ValueError):
                    capacity.verify_isolated_pools(r, 50, 5000)

    def test_forwarding_is_opt_in_loopback_only_and_no_unsafe_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            r = object.__new__(capacity.lifecycle.Rehearsal)
            r.ids = ["test" + str(i) for i in range(4)]
            r.evidence = r.root = Path(directory)
            r.binary = Path("/synthetic/dorad")
            r.base, r.epoch = 28657, 0
            r.logs, r.processes, r.env = [], {}, {}
            try:
                with patch.object(capacity.lifecycle.subprocess, "Popen") as popen:
                    r.start(0)
                    regular = popen.call_args.args[0]
                    self.assertNotIn("--rpc.unsafe=true", regular)
                    self.assertTrue(regular[regular.index("--p2p.persistent_peers") + 1])
                    r.start(0, peer_ports=[29656, 29756, 29856, 29956])
                    isolated = popen.call_args.args[0]
                    self.assertNotIn("--rpc.unsafe=true", isolated)
                    self.assertIn("--p2p.pex=false", isolated)
                    self.assertEqual(isolated[isolated.index("--p2p.persistent_peers") + 1],
                                     "test1@127.0.0.1:29756,test2@127.0.0.1:29856,test3@127.0.0.1:29956")
                    self.assertEqual(isolated[isolated.index("--rpc.laddr") + 1], "tcp://127.0.0.1:28657")
            finally:
                for log in r.logs:
                    log.close()

    def test_hybrid_genesis_installs_only_fixture_owner_keys(self):
        owners = [f"owner{i}" for i in range(7)]
        keys = {owner: {"@type": "/cosmos.crypto.secp256k1.PubKey", "key": owner} for owner in owners}
        generated = {"addresses": owners, "account_public_keys": keys}
        accounts = [{"@type": "/cosmos.auth.v1beta1.BaseAccount", "address": owner,
                     "pub_key": None, "sequence": "0"} for owner in owners + ["untouched"]]
        genesis = {"app_state": {"auth": {"accounts": accounts}}}
        capacity.install_hybrid_public_keys(genesis, generated)
        for account in accounts[:7]:
            self.assertEqual(account["pub_key"], keys[account["address"]])
            self.assertEqual(account["sequence"], "0")
        self.assertIsNone(accounts[-1]["pub_key"])
        with self.assertRaises(ValueError):
            capacity.install_hybrid_public_keys(genesis, generated)

    def test_hybrid_genesis_rejects_missing_or_wrong_fixture_keys(self):
        owners = [f"owner{i}" for i in range(7)]
        keys = {owner: {"@type": "/cosmos.crypto.secp256k1.PubKey", "key": owner} for owner in owners}
        generated = {"addresses": owners, "account_public_keys": keys}
        empty = {"app_state": {"auth": {"accounts": []}}}
        with self.assertRaises(ValueError):
            capacity.install_hybrid_public_keys(empty, generated)
        missing = copy.deepcopy(generated)
        missing["account_public_keys"].pop(owners[0])
        with self.assertRaises(ValueError):
            capacity.install_hybrid_public_keys(empty, missing)
        wrong = {"app_state": {"auth": {"accounts": [
            {"@type": "/unsupported.Account", "address": owners[0], "pub_key": None}]}}}
        with self.assertRaises(ValueError):
            capacity.install_hybrid_public_keys(wrong, generated)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.receipt = {"height": "18", "txs_results": [{"code": 0, "gas_used": "123"}]}

    def read(self, node, deadline=2):
        return capacity.read_finalized_block(node, 18, deadline, now=self.clock.now, sleep=self.clock.sleep)

    def test_missing_results_retry_same_height_then_advance_cursor(self):
        node = Node(self.tmp.name, [missing(), missing(), self.receipt])
        scanned = 17
        def sleep(seconds):
            self.assertEqual(scanned, 17)
            self.clock.sleep(seconds)
        block, receipt = capacity.read_finalized_block(node, scanned + 1, 2, now=self.clock.now, sleep=sleep)
        scanned += 1
        self.assertEqual(scanned, 18)
        self.assertEqual(receipt, self.receipt)
        self.assertEqual(block, node.block)
        self.assertEqual([p for p, _ in node.calls if p.startswith("block_results")], ["block_results?height=18"] * 3)
        records = [json.loads(line) for line in (node.evidence / "block-results-errors.jsonl").read_text().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(x["retryable"] and x["http_status"] == 500 for x in records))
        self.assertIn("could not find results for height #18", records[0]["body"])
        self.assertIn("node0_status", records[0])

    def test_permanently_missing_results_timeout_not_pass(self):
        node = Node(self.tmp.name, [missing() for _ in range(4)])
        scanned = 17
        with self.assertRaises(TimeoutError):
            self.read(node, .6)
            scanned += 1
        self.assertEqual(scanned, 17)
        self.assertAlmostEqual(self.clock.value, .6)
        self.assertFalse((node.evidence / "result.json").exists())
        self.assertEqual(len([p for p, _ in node.calls if p.startswith("block_results")]), 3)

    def test_only_exact_missing_result_is_retryable(self):
        cases = [missing(19), missing(status=404), missing(data="ABCI responses not persisted"),
                 missing(data="database corrupted"), missing(data="could not find results for height #18 extra")]
        for error in cases:
            with self.subTest(error=error), self.assertRaises(urllib.error.HTTPError):
                self.read(Node(self.tmp.name, [error, self.receipt]))
        self.assertEqual(self.clock.sleeps, [])

    def test_html_and_malformed_json_errors_are_not_retried(self):
        for body in [b"<html>server failed</html>", b"{", b"null", b'{"error":null}', b'{"error":{"code":0,"data":"could not find results for height #18"}}']:
            error = urllib.error.HTTPError("http://127.0.0.1", 500, "error", {}, io.BytesIO(body))
            with self.subTest(body=body), self.assertRaises(urllib.error.HTTPError):
                self.read(Node(self.tmp.name, [error]))
        self.assertEqual(self.clock.sleeps, [])

    def test_error_body_is_bounded_and_not_retried_when_truncated(self):
        body = b"x" * 100000
        error = urllib.error.HTTPError("http://127.0.0.1", 500, "error", {}, io.BytesIO(body))
        node = Node(self.tmp.name, [error])
        with self.assertRaises(urllib.error.HTTPError):
            self.read(node)
        record = json.loads((node.evidence / "block-results-errors.jsonl").read_text())
        self.assertEqual(len(record["body"]), 65536)
        self.assertTrue(record["body_truncated"])
        self.assertFalse(record["retryable"])

    def test_diagnostic_failure_does_not_hide_original_error(self):
        node = Node(self.tmp.name, [missing(data="corrupt")])
        rpc = node.rpc
        def fail_status(path, **kwargs):
            if path == "status":
                raise OSError("status unavailable")
            return rpc(path, **kwargs)
        node.rpc = fail_status
        with self.assertRaises(urllib.error.HTTPError):
            self.read(node)
        record = json.loads((node.evidence / "block-results-errors.jsonl").read_text())
        self.assertIn("status unavailable", record["status_error"])
        self.assertFalse(record["retryable"])

    def test_network_or_unexpected_rpc_error_fails_without_retry(self):
        for error in [urllib.error.URLError("connection refused"), TimeoutError("RPC timeout"), KeyError("result")]:
            with self.subTest(error=error), self.assertRaises(type(error)):
                self.read(Node(self.tmp.name, [error]))
        self.assertEqual(self.clock.sleeps, [])

    def test_wrong_result_height_is_not_accepted(self):
        receipt = {**self.receipt, "height": "17"}
        with self.assertRaisesRegex(ValueError, "height mismatch"):
            self.read(Node(self.tmp.name, [receipt]))

    def test_wrong_block_height_is_not_accepted(self):
        node = Node(self.tmp.name, [self.receipt])
        node.block["header"]["height"] = "19"
        with self.assertRaisesRegex(ValueError, "block height mismatch"):
            self.read(node)
        self.assertEqual(len(node.replies), 1)

    def test_missing_or_wrong_result_count_is_not_an_empty_block(self):
        for outcomes in [None, [], {}, [{"code": 0}, {"code": 0}]]:
            with self.subTest(outcomes=outcomes), self.assertRaisesRegex(ValueError, "count mismatch"):
                self.read(Node(self.tmp.name, [{**self.receipt, "txs_results": outcomes}]))
        self.assertTrue(Path(self.tmp.name, "invalid-results-18.json").exists())

    def test_missing_result_field_is_not_an_empty_block(self):
        with self.assertRaises(KeyError):
            self.read(Node(self.tmp.name, [{"height": "18"}], count=0))

    def test_real_empty_block_is_accepted(self):
        for outcomes in [None, []]:
            node = Node(self.tmp.name, [{**self.receipt, "txs_results": outcomes}], count=0)
            _, receipt = self.read(node)
            self.assertEqual(receipt["txs_results"], outcomes)

    def test_failed_transaction_fails_and_saves_receipt(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["txs_results"][0]["code"] = 11
        node = Node(self.tmp.name, [receipt])
        with self.assertRaisesRegex(ValueError, "failed transaction"):
            self.read(node)
        self.assertEqual(json.loads((node.evidence / "failed-transactions-18.json").read_text()), receipt)

    def test_deadline_before_query_does_not_query(self):
        node = Node(self.tmp.name, [self.receipt])
        with self.assertRaises(TimeoutError):
            self.read(node, 0)
        self.assertEqual(node.calls, [])

    def test_success_arriving_after_deadline_is_not_pass(self):
        def late():
            self.clock.value = 3
            return self.receipt
        with self.assertRaises(TimeoutError):
            self.read(Node(self.tmp.name, [late]), 2)

    def test_rpc_timeouts_respect_remaining_deadline(self):
        node = Node(self.tmp.name, [self.receipt])
        self.read(node, .1)
        self.assertTrue(all(0 < timeout <= .1 for _, timeout in node.calls))


if __name__ == "__main__":
    unittest.main()
