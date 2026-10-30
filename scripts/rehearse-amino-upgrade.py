#!/usr/bin/env python3
"""Four-validator, network-isolated v1.0.0 -> v1.0.1 governance rehearsal.

Run ONLY in a remote container with --network none, bounded CPU/memory and fresh
work/evidence mounts. The generated public test keys never hold real funds.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import urllib.request

OLD = Path(os.environ['OLD_DORAD'])
NEW = Path(os.environ['NEW_DORAD'])
ROOT = Path(os.environ['REHEARSAL_DIR'])
ROOT.mkdir(parents=True, exist_ok=False)
CHAIN = 'isolated-amino-v101-rehearsal'
assert hashlib.sha256(OLD.read_bytes()).hexdigest() == '5c741ca406ee2ecb811dd62d83e9a446fee051e2947522525c2560a0a7ce968a'
homes = [ROOT / f'node{i}' for i in range(4)]
processes = []
logs = []
result = {'chain_id': CHAIN, 'validators': 4, 'old_sha256': hashlib.sha256(OLD.read_bytes()).hexdigest(),
          'new_sha256': hashlib.sha256(NEW.read_bytes()).hexdigest(), 'scope': 'isolated governance upgrade; no public IBC or hardware wallet'}

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

ports = []
while len(ports) < 12:
    p = port()
    if p not in ports:
        ports.append(p)
rpcs, peers, abcis = ports[:4], ports[4:8], ports[8:]

def cli(binary, i, *args):
    p = subprocess.run([str(binary), *map(str, args), '--home', str(homes[i])], text=True, capture_output=True, timeout=45)
    if p.returncode:
        raise RuntimeError(f'CLI {args[:2]}: {p.stderr[-2000:]}')
    return p.stdout

def query(i, path):
    with urllib.request.urlopen(f'http://127.0.0.1:{rpcs[i]}/{path}', timeout=3) as f:
        return json.load(f)['result']

def wait(fn, seconds=90):
    deadline = time.monotonic()+seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, KeyError) as e:
            last = e
        time.sleep(.3)
    raise TimeoutError(f'condition timed out: {last}')

def stop():
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
    processes.clear()
    for f in logs:
        f.close()
    logs.clear()

def command(binary, i):
    return [str(binary), 'start', '--home', str(homes[i]), '--minimum-gas-prices', '0peaka',
            '--rpc.laddr', f'tcp://127.0.0.1:{rpcs[i]}', '--p2p.laddr', f'tcp://127.0.0.1:{peers[i]}',
            '--address', f'tcp://127.0.0.1:{abcis[i]}', '--grpc.enable=false', '--grpc-web.enable=false',
            '--api.enable=false', '--rpc.pprof_laddr', '']

def start(binary, phase):
    for i in range(4):
        f = (ROOT/f'{phase}-{i}.log').open('w')
        logs.append(f)
        processes.append(subprocess.Popen(command(binary, i), stdout=f, stderr=subprocess.STDOUT))

def synced(height):
    states = [query(i, 'status')['sync_info'] for i in range(4)]
    return states if all(int(s['latest_block_height']) >= height and not s['catching_up'] for s in states) else None

def tx(binary, i, *args):
    raw = cli(binary, i, 'tx', *args, '--from', 'operator', '--keyring-backend', 'test', '--chain-id', CHAIN,
              '--fees', '100000peaka', '--gas', '600000', '--node', f'http://127.0.0.1:{rpcs[i]}',
              '--broadcast-mode', 'sync', '--output', 'json', '-y')
    response = json.loads(raw)
    assert response.get('code', 0) == 0, response
    h = response['txhash']
    confirmed = wait(lambda: query(i, f'tx?hash=0x{h}'))
    assert confirmed['tx_result']['code'] == 0, confirmed
    (ROOT/f'tx-{h}.json').write_text(json.dumps(confirmed, indent=2))
    return h

try:
    addresses, ids = [], []
    for i in range(4):
        cli(OLD, i, 'init', f'validator-{i}', '--chain-id', CHAIN, '--default-denom', 'peaka')
        key = json.loads(cli(OLD, i, 'keys', 'add', 'operator', '--keyring-backend', 'test', '--output', 'json', '--no-backup'))
        addresses.append(key['address'])
        ids.append(cli(OLD, i, 'comet', 'show-node-id').strip())
    for address in addresses:
        cli(OLD, 0, 'genesis', 'add-genesis-account', address, '1000000000000000000000000peaka')
    gp = homes[0]/'config/genesis.json'
    genesis = json.loads(gp.read_text())
    gov = genesis['app_state']['gov']['params']
    gov['min_deposit'] = [{'denom': 'peaka', 'amount': '1'}]
    gov['voting_period'] = '15s'
    gov['expedited_voting_period'] = '5s'
    gov['max_deposit_period'] = '600s'
    gp.write_text(json.dumps(genesis))
    for i in range(1, 4):
        shutil.copyfile(gp, homes[i]/'config/genesis.json')
    for i in range(4):
        cli(OLD, i, 'genesis', 'gentx', 'operator', '1000000000000000000000peaka', '--chain-id', CHAIN, '--keyring-backend', 'test')
        if i:
            for f in (homes[i]/'config/gentx').glob('*.json'):
                shutil.copyfile(f, homes[0]/'config/gentx'/f.name)
    cli(OLD, 0, 'genesis', 'collect-gentxs')
    for i in range(1, 4):
        shutil.copyfile(gp, homes[i]/'config/genesis.json')
    for i in range(4):
        config = homes[i]/'config/config.toml'
        content = config.read_text()
        settings = {'persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{peers[j]}' for j in range(4) if i != j),
                    'addr_book_strict': False, 'allow_duplicate_ip': True, 'timeout_commit': '500ms'}
        for name, value in settings.items():
            encoded = json.dumps(value)
            content, count = re.subn(rf'(?m)^{name} = .*$', f'{name} = {encoded}', content)
            assert count == 1, (name, count)
        config.write_text(content)
    start(OLD, 'old')
    wait(lambda: synced(4))
    result['before_transfer'] = tx(OLD, 0, 'bank', 'send', addresses[0], addresses[1], '7peaka')
    height = int(query(0, 'status')['sync_info']['latest_block_height']) + 80
    authority = cli(OLD, 0, 'query', 'auth', 'module-account', 'gov', '--node', f'http://127.0.0.1:{rpcs[0]}', '--output', 'json')
    (ROOT/'gov-module-account.json').write_text(authority)
    account = json.loads(authority)['account']
    if 'value' in account and isinstance(account['value'], dict):
        account = account['value']
    authority = account.get('base_account', account).get('address')
    assert authority, account
    proposal = {'messages': [{'@type': '/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade', 'authority': authority,
                             'plan': {'name': 'v1.0.1', 'height': str(height), 'info': 'isolated rehearsal'}}],
                'deposit': '1peaka', 'metadata': '', 'title': 'Isolated v1.0.1 upgrade',
                'summary': 'Temporary four-validator rehearsal only', 'expedited': False}
    proposal_path = ROOT/'proposal.json'; proposal_path.write_text(json.dumps(proposal))
    result['proposal_tx'] = tx(OLD, 0, 'gov', 'submit-proposal', proposal_path)
    result['vote_txs'] = [tx(OLD, i, 'gov', 'vote', '1', 'yes') for i in range(4)]
    def passed():
        p = json.loads(cli(OLD, 0, 'query', 'gov', 'proposal', '1', '--node', f'http://127.0.0.1:{rpcs[0]}', '--output', 'json'))
        return p if p['proposal']['status'] == 'PROPOSAL_STATUS_PASSED' else None
    result['proposal'] = wait(passed)
    stop()
    # Same existing database, before H-1, with a forged local hint: must reject.
    forged = homes[0]/'data/upgrade-info.json'
    forged.write_text(json.dumps({'name': 'v1.0.1', 'height': height}))
    early = subprocess.run(command(NEW, 0), text=True, capture_output=True, timeout=15)
    (ROOT/'early-start.log').write_text(early.stdout+early.stderr)
    assert early.returncode != 0 and 'IBC Amino upgrade boundary' in early.stdout+early.stderr
    result['premature_start_rejected'] = True
    forged.unlink()
    start(OLD, 'old-resumed')
    wait(lambda: all((h/'data/upgrade-info.json').exists() for h in homes), seconds=120)
    stop()
    for home in homes:
        info = json.loads((home/'data/upgrade-info.json').read_text())
        assert info['name'] == 'v1.0.1' and int(info['height']) == height, info
    start(NEW, 'new')
    result['after_upgrade'] = wait(lambda: synced(height+4))
    result['after_transfer'] = tx(NEW, 0, 'bank', 'send', addresses[0], addresses[1], '7peaka')
    compare_height = height+2
    commits = [query(i, f'commit?height={compare_height}') for i in range(4)]
    hashes = [c['signed_header']['header']['app_hash'] for c in commits]
    assert len(set(hashes)) == 1, hashes
    result['matching_app_hash'] = {'height': compare_height, 'hash': hashes[0], 'nodes': 4}
    assert len(query(0, 'validators')['validators']) == 4
    prior = max(int(s['latest_block_height']) for s in synced(height+4))
    stop()
    # Completion state, rather than the local upgrade-info file, must authorize restart.
    for home in homes:
        (home/'data/upgrade-info.json').rename(home/'data/rehearsal-completed-upgrade.json')
    start(NEW, 'restarted')
    result['after_restart'] = wait(lambda: synced(prior+4))
    compare_height = prior+2
    hashes = [query(i, f'commit?height={compare_height}')['signed_header']['header']['app_hash'] for i in range(4)]
    assert len(set(hashes)) == 1, hashes
    result['restart_matching_app_hash'] = {'height': compare_height, 'hash': hashes[0], 'nodes': 4}
    result['upgrade_height'] = height
    result['status'] = 'PASS'
    print(json.dumps(result, indent=2), flush=True)
finally:
    stop()
    (ROOT/'result.json').write_text(json.dumps(result, indent=2))
