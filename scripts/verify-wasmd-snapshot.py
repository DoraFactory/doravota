#!/usr/bin/env python3
"""Check the complete maintained Wasmd snapshot, not just go.sum modules."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1] / 'third_party/wasmd-v055-compat'
expected = json.loads((root / 'snapshot-sha256.json').read_text())
actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'snapshot-sha256.json'}
assert expected == actual, 'Wasmd snapshot changed: review diff and regenerate manifest'
print(f'Wasmd snapshot: {len(actual)} files verified')
