"""Disposable real-snapshot rehearsal; run in --network none container only.
No production keys, sockets, homes or network endpoints are mounted.
"""
import base64,hashlib,json,os,pathlib,re,shutil,signal,subprocess,threading,time,traceback,urllib.request
R=pathlib.Path('/work'); W=R/'snapshot-rehearsal'; E=R/'evidence'; E.mkdir(exist_ok=True)
CHAIN='pqc-phase1-snapshot-20261101'; SOURCE=18029707; BASE=28657
OLD='/binaries/v100'; BRIDGE='/binaries/v101'; NEW='/binaries/pqc'; B=OLD
P={}; THREADS=[]; EVENTS=[]; LOCK=threading.Lock(); STOP=threading.Event(); LABEL='prepare'
result={'status':'RUNNING','chain_id':CHAIN,'source_height':SOURCE,'candidate_commit':'91fc4592f8ff0038cc0af43969036ba96b78b4ca','limits':{'cpus':4,'memory_bytes':12*1024**3,'minimum_free_disk_bytes':40*1024**3},'transactions':[],'scope':'retained 2026-11-01 real snapshot, synthetic validator keys/faucet/governance checkpoint; offline container; no public IBC transactions'}
def save(n,v):
 p=E/(n+'.json');p.write_text(json.dumps(v,indent=2)+'\n');return p
def guard():
 if shutil.disk_usage(R).free < 40*1024**3:raise RuntimeError('40 GiB host disk reserve reached')
def run(argv,timeout=180,env=None):
 guard();p=subprocess.run(list(map(str,argv)),text=True,capture_output=True,timeout=timeout,env=env)
 if p.returncode:raise RuntimeError(f'{argv[:3]} failed: {p.stderr[-2500:]} {p.stdout[-500:]}')
 return p.stdout
def cli(*args,i=0,binary=None):return run([binary or B,*args,'--home',W/f'node{i}'])
def rpc(path,i=0):
 with urllib.request.urlopen(f'http://127.0.0.1:{BASE+100*i}/{path}',timeout=3) as f:
  d=json.load(f)
  if 'error' in d:raise ValueError(d['error'])
  return d['result']
def q(*args,i=0):return json.loads(cli('query',*args,'--node',f'http://127.0.0.1:{BASE+100*i}','--output','json',i=i))
def height(i=0):return int(rpc('status',i)['sync_info']['latest_block_height'])
def wait(fn,seconds=180):
 end=time.monotonic()+seconds;last=None
 while time.monotonic()<end:
  guard()
  try:
   v=fn()
   if v:return v
  except (OSError,ValueError,KeyError,RuntimeError) as e:last=str(e)
  time.sleep(.2)
 raise TimeoutError(str(last))
def synced(h):return all(height(i)>=h and not rpc('status',i)['sync_info']['catching_up'] for i in range(4))
def roots(label,i=0):
 d=json.loads(run(['/work/roots',W/f'node{i}']));save(label,d);return d
def event_reader(p,phase,i,started,kill_pattern):
 with (E/f'{phase}-node{i}.log').open('w') as f:
  for line in p.stdout:
   f.write(line);f.flush()
   now=time.monotonic()
   if any(x in line for x in ('applying upgrade','Starting upgrade','finalized block','committed state','executed block','ABCI Handshake App Info')):
    with LOCK:EVENTS.append({'phase':phase,'node':i,'elapsed':now-started,'monotonic':now,'line':line.strip()})
   if kill_pattern and kill_pattern in line and p.poll() is None:
    p.kill()
    with LOCK:EVENTS.append({'phase':phase,'node':i,'elapsed':now-started,'action':'SIGKILL','trigger':kill_pattern})
    kill_pattern=None
def start_node(i,phase,kill_pattern=None):
 ids=[cli('comet','show-node-id',i=j).strip() for j in range(4)]
 peers=','.join(f'{ids[j]}@127.0.0.1:{BASE+100*j-1}' for j in range(4) if j!=i)
 argv=[B,'start','--home',str(W/f'node{i}'),'--minimum-gas-prices','0peaka','--rpc.laddr',f'tcp://127.0.0.1:{BASE+100*i}','--p2p.laddr',f'tcp://127.0.0.1:{BASE+100*i-1}','--p2p.persistent_peers',peers,'--grpc.enable=false','--grpc-web.enable=false','--api.enable=false','--rpc.pprof_laddr','','--log_format','json']
 p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1);P[i]=p
 t=threading.Thread(target=event_reader,args=(p,phase,i,time.monotonic(),kill_pattern),daemon=True);t.start();THREADS.append(t)
 return p
def stop():
 for p in P.values():
  if p.poll() is None:p.terminate()
 for p in P.values():
  try:p.wait(30)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 P.clear()
 for t in THREADS:t.join(2)
 THREADS.clear()
def start(phase):
 global LABEL
 LABEL=phase
 for i in range(4):start_node(i,phase)
def agreement(label):
 h=min(height(i) for i in range(4));wait(lambda:synced(h+1))
 hashes=[rpc(f'block?height={h+1}',i)['block']['header']['app_hash'] for i in range(4)]
 assert len(set(hashes))==1,hashes
 d={'state_height':h,'hashes':hashes};save(label,d);return h
common=['--keyring-backend','test','--chain-id',CHAIN,'--node',f'http://127.0.0.1:{BASE}','--gas','4000000','--fees','100000peaka','-y','--output','json']
def tx(label,*args):
 d=json.loads(cli('tx',*args,'--from','faucet',*common));assert int(d.get('code',0))==0,d
 receipt=wait(lambda:rpc('tx?hash=0x'+d['txhash']));assert int(receipt['tx_result']['code'])==0,receipt
 save(label,receipt);result['transactions'].append({'operation':label,'hash':d['txhash'],'height':receipt['height'],'code':0});return receipt
def transfer(label):return tx(label,'bank','send',faucet,voters[0],'11peaka')
def proposal(name):
 target=height()+65
 p=save(name+'-proposal',{'messages':[{'@type':'/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade','authority':'dora10d07y265gmmuvt4z0w9aw880jnsr700jeckgp9','plan':{'name':name,'height':str(target),'info':'Isolated mainnet snapshot rehearsal, never public governance'}}],'deposit':'100peaka','metadata':'','title':'Isolated '+name,'summary':'Synthetic fork only','expedited':False})
 r=tx(name+'-submit','gov','submit-proposal',p)
 ids=[a['value'] for e in r['tx_result']['events'] if e['type']=='submit_proposal' for a in e['attributes'] if a['key']=='proposal_id'];assert len(ids)==1,r
 pid=ids[0]
 unsigned=json.loads(cli('tx','gov','vote',pid,'yes','--from','faucet',*common,'--generate-only'))
 unsigned['body']['messages']=[{'@type':'/cosmos.gov.v1.MsgVote','proposal_id':pid,'voter':a,'option':'VOTE_OPTION_YES','metadata':''} for a in voters]
 path=save(name+'-votes',unsigned);tx(name+'-vote','authz','exec',path)
 passed=wait(lambda:(p if (p:=q('gov','proposal',pid))['proposal']['status']=='PROPOSAL_STATUS_PASSED' else None));save(name+'-passed',passed)
 def halted():
  for i in range(4):
   f=W/f'node{i}/data/upgrade-info.json'
   if not f.exists():return False
   v=json.loads(f.read_text())
   if v['name']!=name or int(v['height'])!=target:return False
  return True
 wait(halted,240);stop();result[name+'_height']=target
 return target
def monitor():
 with (E/'resources.jsonl').open('w') as f:
  while not STOP.wait(.5):
   d={'time':time.time(),'phase':LABEL,'disk_free':shutil.disk_usage(R).free,'rss_bytes':{}}
   for i,p in list(P.items()):
    try:
     for ln in pathlib.Path(f'/proc/{p.pid}/status').read_text().splitlines():
      if ln.startswith('VmRSS:'):d['rss_bytes'][str(i)]=int(ln.split()[1])*1024
    except OSError:pass
   for name in ('memory.current','memory.peak','memory.events','cpu.stat'):
    try:d[name]=pathlib.Path('/sys/fs/cgroup/'+name).read_text().strip()
    except OSError:pass
   f.write(json.dumps(d)+'\n');f.flush()
   if d['disk_free']<40*1024**3:
    os.kill(os.getpid(),signal.SIGTERM);return
def terminated(sig,frame):raise RuntimeError('termination/resource guard')
signal.signal(signal.SIGTERM,terminated)
threading.Thread(target=monitor,daemon=True).start()
try:
 assert not W.exists(),'Never reuse or reset an existing node home'
 for path,want in [(OLD,'5c741ca406ee2ecb811dd62d83e9a446fee051e2947522525c2560a0a7ce968a'),(BRIDGE,'04bd2d0dced7ccf1f993a70fb2be6b1718e0f1852c27f1bdeef0fa49eaea1696'),(NEW,'b10e90aa1db0824a98ca3e59b3b09fad23b8a6ef3ec400fb0383fa334bec9878')]:
  assert hashlib.file_digest(open(path,'rb'),'sha256').hexdigest()==want
 W.mkdir();cli('init','snapshot-node0','--chain-id',CHAIN,'--default-denom','peaka')
 faucet=json.loads(cli('keys','add','faucet','--keyring-backend','test','--no-backup','--output','json'))['address']
 run(['cp','-a','--reflink=auto',str(R/'pristine/data')+'/.',W/'node0/data'],timeout=600)
 before=roots('source-roots');assert before['height']==SOURCE
 for proof in ['source-block-official.json','source-block-itrocket.json']:
  head=json.loads((R/proof).read_text())['result']['block']['header']
  assert head['chain_id']=='vota-ash' and int(head['height'])==SOURCE+1 and head['app_hash']==before['apphash']
 result['source_app_hash']=before['apphash'];print('SOURCE VERIFIED',SOURCE,before['apphash'],flush=True)
 f=run(['/work/snapshot-fork','fork',W/'node0'],env={**os.environ,'TEST_FAUCET_ADDR':faucet},timeout=300)
 (E/'fork.log').write_text(f);fork=json.loads((W/'node0/fork-report.json').read_text());save('fork-report',fork)
 voters=json.loads((W/'node0/voters.json').read_text())
 for i in range(1,4):
  run(['cp','-a','--reflink=auto',W/'node0',W/f'node{i}'],timeout=600)
  # Only replace freshly generated TEST node identity, not validator state.
  (W/f'node{i}/config/node_key.json').rename(W/f'node{i}/config/copied-test-node-key.json')
  cli('init',f'snapshot-node{i}','--chain-id',CHAIN,'--default-denom','peaka','--overwrite',i=i)
  shutil.copyfile(W/'node0/config/genesis.json',W/f'node{i}/config/genesis.json')
 for i in range(4):
  home=W/f'node{i}'
  shutil.copyfile(W/f'node0/test-keys/{i}/priv_validator_key.json',home/'config/priv_validator_key.json')
  shutil.copyfile(W/f'node0/test-keys/{i}/priv_validator_state.json',home/'data/priv_validator_state.json')
  cfg=home/'config/config.toml';s=cfg.read_text()
  for name,value in {'timeout_commit':'1s','allow_duplicate_ip':True,'addr_book_strict':False,'pex':False,'seeds':''}.items():
   s,n=re.subn(rf'(?m)^{name} = .*$',f'{name} = {json.dumps(value)}',s);assert n==1,(name,n)
  cfg.write_text(s)
 print('FOUR COPIES PREPARED',flush=True)
 start('v100-baseline');wait(lambda:synced(SOURCE+4),240);save('baseline-versions',q('upgrade','module-versions'));transfer('baseline-transfer');agreement('baseline-agreement')
 v101=proposal('v1.0.1');print('V101 HALTED',v101,flush=True)
 B=BRIDGE;t=time.monotonic();start('v101-upgrade');wait(lambda:synced(v101+3),240);result['v101_start_to_all_progress_seconds']=time.monotonic()-t
 transfer('v101-transfer');agreement('v101-agreement')
 pqc=proposal('v1.1.0');print('PQC HALTED',pqc,flush=True)
 halted=roots('pqc-pre-upgrade-roots');assert halted['height']==pqc-1
 assert 'pqcauth' not in halted['roots']
 # Independent replay: the halted block is already in Comet blockstore.
 B=NEW;LABEL='pqc-migration-interruption'
 for i,pattern in [(0,'applying upgrade'),(1,'finalized block')]:
  p=start_node(i,f'pqc-interrupt-{i}',pattern)
  p.wait(timeout=240)
  assert p.returncode==-signal.SIGKILL,('expected deliberate SIGKILL',i,p.returncode)
  for th in THREADS:th.join(2)
  d=roots(f'pqc-after-interruption-{i}',i)
  result[f'interruption_{i}']={'trigger':pattern,'last_committed_height':d['height'],'upgrade_height':pqc,'interrupted_before_upgrade_commit':d['height']==pqc-1}
  P.pop(i);print('INTERRUPTION',i,d['height'],flush=True)
 t=time.monotonic();start('pqc-upgrade-recovery');wait(lambda:synced(pqc+4),300);result['pqc_restart_to_all_progress_seconds']=time.monotonic()-t
 params=q('pqcauth','params');save('pqc-params',params);assert params['params']['enforcement_mode']=='ENFORCEMENT_MODE_OPTIONAL'
 for key,want in [('verification_gas',750),('recovery_delay_blocks',107520),('max_emergency_duration_blocks',46080),('governance_safety_delay_blocks',17280)]:
  assert int(params['params'][key])==want,(key,params)
 assert base64.b64decode(params['params']['network_id'])==hashlib.sha256(('doravota/pqcauth/upgrade/v1.1.0/'+CHAIN).encode()).digest()
 versions=q('upgrade','module-versions');save('pqc-versions',versions)
 assert any(v['name']=='pqcauth' and int(v['version'])==4 for v in versions['module_versions']),versions
 transfer('pqc-transfer');h=agreement('pqc-agreement');stop()
 after=roots('pqc-after-upgrade-roots')
 for key in ('wasm','ibc','feegrant','authz'):
  assert halted['roots'][key]==after['roots'][key],('unexpected store change',key)
 result['preserved_roots']=['wasm','ibc','feegrant','authz'];assert 'pqcauth' in after['roots']
 for i in range(4):(W/f'node{i}/data/upgrade-info.json').rename(W/f'node{i}/data/completed-pqc-upgrade.json')
 start('pqc-full-restart');wait(lambda:synced(h+4),240);transfer('restart-transfer');agreement('restart-agreement')
 # Drop the lowest-power validator, ensuring the remaining power exceeds 2/3.
 powers={int(v['node']):int(v['power']) for v in fork['validators']};off=min(powers,key=powers.get)
 assert 3*(sum(powers.values())-powers[off])>2*sum(powers.values())
 p=P.pop(off);p.terminate();p.wait(30);live=[i for i in range(4) if i!=off];h=min(height(i) for i in live)
 wait(lambda:all(height(i)>=h+5 for i in live),120)
 result['single_node_offline']={'node':off,'from_height':h,'to_height':min(height(i) for i in live)}
 start_node(off,'pqc-node-rejoin');wait(lambda:synced(h+7),180);result['final_height']=agreement('final-agreement');stop()
 result['status']='PASS';print('SNAPSHOT REHEARSAL PASS',result['final_height'],flush=True)
except BaseException:
 result['status']='FAIL';result['traceback']=traceback.format_exc();raise
finally:
 stop();STOP.set();save('events',EVENTS);save('result',result)
