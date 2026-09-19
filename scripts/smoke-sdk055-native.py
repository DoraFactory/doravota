#!/usr/bin/env python3
"""Local new-chain smoke only; all generated keys live in a temporary home."""
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / 'build/dorad'
OUT = ROOT / 'docs/sdk-055-evidence'

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def smoke(algo):
    with tempfile.TemporaryDirectory(prefix='doravota-sdk055-') as tmp:
        home = pathlib.Path(tmp)
        chain = 'sdk055-smoke-' + algo.replace('_', '-')
        def cli(*args):
            result = subprocess.run([str(BIN), *args, '--home', tmp], text=True, capture_output=True, timeout=60)
            if result.returncode:
                raise RuntimeError(f'{args[0:2]} failed: {result.stderr[-2500:]}')
            return result.stdout
        cli('init', 'isolated-smoke', '--chain-id', chain, '--default-denom', 'peaka', '--consensus-key-algo', algo)
        genesis_path = home / 'config/genesis.json'
        genesis = json.loads(genesis_path.read_text())
        # This allowlist belongs only to this throwaway network.
        genesis['consensus']['params']['validator']['pub_key_types'] = [algo]
        genesis_path.write_text(json.dumps(genesis))
        account = json.loads(cli('keys', 'add', 'operator', '--algo', 'ml_dsa_65', '--keyring-backend', 'test', '--output', 'json', '--no-backup'))
        address = account['address']
        cli('genesis', 'add-genesis-account', address, '1000000000000000000000000peaka')
        cli('genesis', 'gentx', 'operator', '1000000000000000000000peaka', '--chain-id', chain, '--keyring-backend', 'test')
        cli('genesis', 'collect-gentxs')
        cli('genesis', 'validate-genesis')
        rpc, p2p = port(), port()
        def query(route):
            with urllib.request.urlopen(f'http://127.0.0.1:{rpc}/{route}', timeout=3) as response:
                return json.load(response)['result']
        node_log = OUT / f'smoke-{algo}-node.log'
        with node_log.open('w') as log:
            process = subprocess.Popen([str(BIN), 'start', '--home', tmp, '--minimum-gas-prices', '0peaka',
                '--rpc.laddr', f'tcp://127.0.0.1:{rpc}', '--p2p.laddr', f'tcp://127.0.0.1:{p2p}',
                '--grpc.enable=false', '--grpc-web.enable=false', '--api.enable=false'], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic()+90
                status = None
                while time.monotonic()<deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f'{algo} node exited; see {node_log}')
                    try:
                        status = query('status')
                        if int(status['sync_info']['latest_block_height']) >= 3:
                            break
                    except (OSError, ValueError, KeyError):
                        pass
                    time.sleep(1)
                else:
                    raise RuntimeError(f'{algo}: failed to reach height 3')
                commit = query('commit')
                validators = query('validators')
                expected = 3309 if algo == 'ml_dsa_65' else 64
                sigs = commit['signed_header']['commit']['signatures']
                assert all(len(base64.b64decode(s['signature'])) == expected for s in sigs if s.get('signature'))
                result = {'algorithm': algo, 'chain_id': chain, 'operator_account_algorithm': 'ml_dsa_65',
                          'height': status['sync_info']['latest_block_height'], 'commit_signature_bytes': expected,
                          'validators': validators, 'commit': commit, 'status': 'passed',
                          'scope': 'single-node fresh genesis; not an upgrade or multinode acceptance'}
                (OUT/f'smoke-{algo}.json').write_text(json.dumps(result, indent=2)+'\n')
                print(f'{algo}: height {result["height"]}, commit signature {expected} bytes', flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        prior_height = int(result['height'])
        with node_log.open('a') as log:
            restarted = subprocess.Popen([str(BIN), 'start', '--home', tmp, '--minimum-gas-prices', '0peaka',
                '--rpc.laddr', f'tcp://127.0.0.1:{rpc}', '--p2p.laddr', f'tcp://127.0.0.1:{p2p}',
                '--grpc.enable=false', '--grpc-web.enable=false', '--api.enable=false'], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic()+60
                while time.monotonic()<deadline:
                    if restarted.poll() is not None:
                        raise RuntimeError(f'{algo}: restart failed; see {node_log}')
                    try:
                        status = query('status')
                        if int(status['sync_info']['latest_block_height']) >= prior_height+2:
                            break
                    except (OSError, ValueError, KeyError):
                        pass
                    time.sleep(1)
                else:
                    raise RuntimeError(f'{algo}: restart did not advance height')
                result['restart_height'] = status['sync_info']['latest_block_height']
            finally:
                restarted.terminate()
                try:
                    restarted.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    restarted.kill()
                    restarted.wait()
        exported = json.loads(cli('export'))
        result['export_passed'] = bool(exported.get('app_state'))
        assert result['export_passed']
        (OUT/f'smoke-{algo}.json').write_text(json.dumps(result, indent=2)+'\n')
        print(f'{algo}: restart height {result["restart_height"]}, export passed', flush=True)

if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    for algorithm in ['ed25519', 'ml_dsa_65']:
        smoke(algorithm)
