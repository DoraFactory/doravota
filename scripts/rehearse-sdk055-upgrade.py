#!/usr/bin/env python3
"""Isolated, single-validator real 0.5.0 -> SDK 0.55 rehearsal.
Run on the operator host only. Uses fresh keys and loopback ports.
Not a production-snapshot or cross-chain IBC acceptance test.
"""
import argparse, base64, hashlib, json, pathlib, shutil, socket, subprocess, time, urllib.request
p=argparse.ArgumentParser();p.add_argument('--old',required=True);p.add_argument('--new',required=True);p.add_argument('--work',required=True);a=p.parse_args()
work=pathlib.Path(a.work).resolve();work.mkdir(parents=True,exist_ok=False)
home=work/'node';chain='sdk055-isolated-rehearsal';binary=a.old

def save(name,obj): (work/(name+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def cli(*args):
 r=subprocess.run([binary,*map(str,args),'--home',str(home)],capture_output=True,text=True,timeout=90)
 if r.returncode: raise RuntimeError(f'{args[:3]}: {r.stderr[-3000:]}')
 return r.stdout

def query(*args): return json.loads(cli('query',*args,'--node',node,'--output','json'))
def port():
 with socket.socket() as s: s.bind(('127.0.0.1',0));return s.getsockname()[1]
rpc,p2p=port(),port();node=f'tcp://127.0.0.1:{rpc}'
def rpc_query(path):
 with urllib.request.urlopen(f'http://127.0.0.1:{rpc}/{path}',timeout=3) as r: return json.load(r)['result']
def height(): return int(rpc_query('status')['sync_info']['latest_block_height'])
def wait_height(n,process,seconds=150):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if process.poll() is not None: raise RuntimeError(f'node exited with {process.returncode}; see node logs')
  try:
   if height()>=n:return
  except (OSError,KeyError,ValueError):pass
  time.sleep(.5)
 raise TimeoutError(f'height {n}')
def start(label):
 log=(work/(label+'.log')).open('w')
 return subprocess.Popen([binary,'start','--home',str(home),'--minimum-gas-prices','0peaka','--rpc.laddr',node,'--p2p.laddr',f'tcp://127.0.0.1:{p2p}','--grpc.enable=false','--grpc-web.enable=false','--api.enable=false','--rpc.pprof_laddr',''],stdout=log,stderr=subprocess.STDOUT)
def stop(process):
 if process and process.poll() is None:
  process.terminate()
  try:process.wait(timeout=20)
  except subprocess.TimeoutExpired:process.kill();process.wait()
def tx(label,*args):
 r=json.loads(cli('tx',*args,'--from','operator','--keyring-backend','test','--chain-id',chain,'--node',node,'--gas','3000000','--fees','1000000peaka','--yes','--output','json'))
 assert r['code']==0,r
 end=time.monotonic()+50
 while time.monotonic()<end:
  try:
   committed=query('tx',r['txhash']);assert committed['code']==0,committed;save(label,committed);return committed
  except RuntimeError:time.sleep(.5)
 raise TimeoutError(label)

save('provenance',{'old_sha256':hashlib.sha256(pathlib.Path(a.old).read_bytes()).hexdigest(),'new_sha256':hashlib.sha256(pathlib.Path(a.new).read_bytes()).hexdigest(),'scope':'fresh 0.5.0 genesis; real binary governance halt/upgrade; single validator; no production keys/state','rpc':node})
cli('init','sdk055-rehearsal','--chain-id',chain,'--default-denom','peaka')
gp=home/'config/genesis.json';g=json.loads(gp.read_text());gov=g['app_state']['gov']['params'];gov.update(voting_period='12s',expedited_voting_period='6s',max_deposit_period='30s',min_deposit=[{'denom':'peaka','amount':'1'}],expedited_min_deposit=[{'denom':'peaka','amount':'2'}]);gp.write_text(json.dumps(g))
config=home/'config/config.toml';config.write_text(config.read_text().replace('timeout_commit = "5s"','timeout_commit = "1s"'))
account=json.loads(cli('keys','add','operator','--keyring-backend','test','--output','json','--no-backup'));address=account['address']
recipient=json.loads(cli('keys','add','recipient','--keyring-backend','test','--output','json','--no-backup'))['address']
cli('genesis','add-genesis-account',address,'1000000000000000000000000peaka');cli('genesis','gentx','operator','1000000000000000000000peaka','--chain-id',chain,'--keyring-backend','test');cli('genesis','collect-gentxs');cli('genesis','validate-genesis')
process=None
try:
 process=start('old');wait_height(3,process)
 tx('wasm-store','wasm','store',pathlib.Path(__file__).resolve().parents[1]/'third_party/wasmd-v055-compat/x/wasm/keeper/testdata/hackatom.wasm')
 tx('wasm-instantiate','wasm','instantiate','1',json.dumps({'verifier':address,'beneficiary':recipient}),'--label','upgrade-fixture','--no-admin','--amount','11peaka')
 contract=query('wasm','list-contract-by-code','1')['contracts'][0]
 contract_before=query('wasm','contract-state','smart',contract,json.dumps({'verifier':{}}));save('contract-before',contract_before)
 authority=query('auth','module-account','gov')['account']['value']['address']
 upgrade_height=height()+35
 proposal={'messages':[{'@type':'/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade','authority':authority,'plan':{'name':'sdk-055','height':str(upgrade_height),'info':'isolated rehearsal'}}],'metadata':'','deposit':'1peaka','title':'SDK 0.55 isolated rehearsal','summary':'Upgrade fresh test state from 0.5.0','expedited':False}
 save('proposal',proposal);tx('submit','gov','submit-proposal',work/'proposal.json');tx('vote','gov','vote','1','yes')
 wait_height(upgrade_height-2,process)
 before={name:query(*route) for name,route in {'wasm':['wasm','params'],'staking':['staking','params'],'auth':['auth','params'],'bank':['bank','params'],'ibc':['ibc','client','params'],'transfer':['ibc-transfer','params'],'versions':['upgrade','module-versions']}.items()};save('before',before)
 end=time.monotonic()+60
 while time.monotonic()<end:
  if (home/'data/upgrade-info.json').exists():break
  if process.poll() is not None:raise RuntimeError('old node exited without upgrade info')
  time.sleep(.5)
 else:raise TimeoutError('old binary did not halt for scheduled upgrade')
 stop(process);process=None
 assert json.loads((home/'data/upgrade-info.json').read_text())['name']=='sdk-055'
 shutil.copytree(home,work/'halted-backup');print('0.5.0 halted with committed upgrade plan',flush=True)
 binary=a.new;process=start('new');wait_height(upgrade_height+3,process)
 after={name:query(*route) for name,route in {'wasm':['wasm','params'],'staking':['staking','params'],'auth':['auth','params'],'bank':['bank','params'],'ibc':['ibc','client','params'],'transfer':['ibc-transfer','params'],'versions':['upgrade','module-versions']}.items()};save('after',after)
 assert before['wasm']==after['wasm'];assert before['bank']==after['bank'];assert before['transfer']==after['transfer'];assert before['ibc']==after['ibc']
 versions={v['name']:int(v.get('version',0)) for v in after['versions']['module_versions']};assert versions['auth']==7 and versions['staking']==6;assert 'params' not in versions and 'group' not in versions
 contract_after=query('wasm','contract-state','smart',contract,json.dumps({'verifier':{}}));save('contract-after',contract_after);assert contract_before==contract_after
 tx('wasm-release','wasm','execute',contract,json.dumps({'release':{}}));assert query('bank','balances',recipient)['balances']==[{'denom':'peaka','amount':'11'}]
 tx('bank-send','bank','send','operator',recipient,'7peaka');assert query('bank','balances',recipient)['balances']==[{'denom':'peaka','amount':'18'}]
 prior=height();save('status',rpc_query('status'));stop(process);process=None
 exported=json.loads(cli('export'));save('export',exported);assert 'group' not in exported['app_state'] and 'params' not in exported['app_state']
 process=start('restart');wait_height(prior+2,process);save('restart-status',rpc_query('status'))
 save('result',{'status':'passed','upgrade_height':upgrade_height,'restart_height':height(),'versions':versions,'scope':'single fresh old-binary chain; governance upgrade, parameter preservation, module removal, old Wasm contract query/execution, bank transaction, export and restart'});print('upgrade, transaction, export and restart passed',flush=True)
finally:stop(process)
