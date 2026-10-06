#!/usr/bin/env python3
"""Verify the selected Wasmd fork against its reviewed version and checksums."""
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
expected = json.loads((root / 'docs/v1.0.0-preserve/WASMD-FORK.json').read_text())

def go_json(*args):
    return json.loads(subprocess.check_output(['go', *args], cwd=root, text=True))

selected = go_json('list', '-mod=readonly', '-m', '-json', expected['module'])
replacement = selected.get('Replace', {})
if (replacement.get('Path'), replacement.get('Version')) != (expected['replacement'], expected['version']):
    raise SystemExit('Wasmd replacement differs from the reviewed fork pin')
module = go_json('mod', 'download', '-json', expected['replacement'] + '@' + expected['version'])
if (module.get('Sum'), module.get('GoModSum')) != (expected['sum'], expected['go_mod_sum']):
    raise SystemExit('Wasmd fork module checksums differ from the reviewed pin')
origin = module.get('Origin', {})
if origin.get('Hash') and origin['Hash'] != expected['commit']:
    raise SystemExit('Wasmd fork origin commit differs from the reviewed pin')
if not expected['version'].endswith('-' + expected['commit'][:12]):
    raise SystemExit('Wasmd pseudo-version does not identify the reviewed commit')
print('Wasmd fork verified:', expected['replacement'], expected['version'])
print('Source commit:', expected['commit'])
