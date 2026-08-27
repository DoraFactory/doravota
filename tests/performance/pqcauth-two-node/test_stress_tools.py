#!/usr/bin/env python3

import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import build_stress_plan
import collect_stress


class StressToolTests(unittest.TestCase):
    def test_plan_allocation_preserves_total(self):
        counts = build_stress_plan.allocate(
            101, {"classic": 40, "hybrid": 30, "native": 30}
        )
        self.assertEqual(101, sum(counts.values()))
        self.assertEqual({"classic", "hybrid", "native"}, set(counts))

    def test_observed_wall_clock_produces_positive_confirmation_latency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "broadcast.jsonl"
            observations = root / "blocks.jsonl"
            summary = root / "summary.json"
            tx_hash = "ab" * 32
            results.write_text(
                json.dumps(
                    {
                        "accepted": True,
                        "expected_hash": tx_hash,
                        "mode": "hybrid",
                        "submitted_at_utc": "2026-08-27T00:00:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            observations.write_text(
                json.dumps(
                    {
                        "height": 10,
                        "header_time": "2026-08-26T23:59:59Z",
                        "observed_at_utc": "2026-08-27T00:00:01Z",
                        "interval_seconds": 2.0,
                        "consensus_round": 0,
                        "tx_count": 1,
                        "tx_hashes": [tx_hash],
                        "tx_bytes": 100,
                        "gas_wanted": 400000,
                        "gas_used": 300000,
                        "failed_deliveries": 0,
                        "block_hash": "CD",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            args = SimpleNamespace(
                phase="test",
                broadcast_results=str(results),
                observations=str(observations),
                summary_out=str(summary),
            )
            with contextlib.redirect_stdout(io.StringIO()):
                collect_stress.analyze(args)
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(1.0, payload["confirmation_latency_seconds"]["p50"])
            self.assertEqual(1, payload["committed_transactions"])
            self.assertEqual({"0": 1}, payload["consensus_rounds"])

    def test_parse_nanosecond_timestamp(self):
        parsed = collect_stress.parse_time("2026-08-27T00:00:00.123456789Z")
        self.assertEqual(dt.datetime(2026, 8, 27, 0, 0, 0, 123456, tzinfo=dt.timezone.utc), parsed)


if __name__ == "__main__":
    unittest.main()
