#!/usr/bin/env python3
"""Verify the review snapshot against the pinned upstream source and patch hashes."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
record = json.loads((root / "docs/ibc-amino-compat/upstream-manifest.json").read_text())
source = root / "third_party/ibc-go"
actual = {p.relative_to(source).as_posix(): p for p in source.rglob("*") if p.is_file()}
expected = record["sha256"] | record["patched_sha256"]
assert actual.keys() == expected.keys(), "snapshot file list differs from the recorded source"
for name, digest in expected.items():
    assert hashlib.sha256(actual[name].read_bytes()).hexdigest() == digest, name
assert set(record["patched_sha256"]) == {
    "proto/ibc/applications/transfer/v1/tx.proto",
    "modules/apps/transfer/types/tx.pb.go",
}
print(f"PASS: {len(actual)} source files; exactly two pinned patch files; no routing/store changes")
