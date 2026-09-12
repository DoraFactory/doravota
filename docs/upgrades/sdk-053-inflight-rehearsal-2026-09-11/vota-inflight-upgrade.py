import pathlib,json,urllib.request,base64,importlib.util,subprocess,time,shutil
R=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911');T=R/'inflight-snapshot-rehearsal';E=T/'upgrade-evidence';sp=importlib.util.spec_from_file_location('tx',T/'vota-upgrade-txs.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
B='http://127.0.0.1:43654';cid='vota-inflight-rehearsal-20260911';reg='dora1smg5qp5trjdkcekdjssqpjehdjf6n4cjss0clyvqcud3t3u3948s8rmgg4'
def get(p):return json.load(urllib.request.urlopen(B+p,timeout=30))
def capture(name):
 queries=json.loads((E/'registry-pre-queries.json').read_text());rs=json.loads((E/'round-pre-queries.json').read_text());todo={reg:list(queries)};todo.update({k:list(v) for k,v in rs.items()});r={}
 for a,keys in todo.items():
  r[a]={}
  for k in keys:
   try:r[a][k]=get('/cosmwasm/wasm/v1/contract/'+a+'/smart/'+base64.b64encode(json.dumps({k:{}}).encode()).decode())
   except urllib.error.HTTPError as e:r[a][k]={'error':e.read().decode()}
 (E/name).write_text(json.dumps(r,indent=2));return r
capture('wasm-immediately-pre-upgrade.json')
h=int(json.load(urllib.request.urlopen('http://127.0.0.1:43651/status'))['result']['sync_info']['latest_block_height'])+65
(E/'upgrade-height.txt').write_text(str(h))
m.tx('inflight-upgrade-proposal',['gov','submit-legacy-proposal','software-upgrade','sdk-v0.53-bridge','--upgrade-height',str(h),'--upgrade-info','{"binaries": {"linux/amd64": "http://77.42.3.141:18080/rehearsal-bridge.tar.gz?checksum=sha256:55dd4e9ce7ebcd733c126002c6f9e04dcdc4ad9f7428a92d0f3711f62541d8e4"}}','--deposit','1000000000000000000peaka','--title','Isolated in-flight IBC and Wasm upgrade rehearsal','--description','Test-only chain. No mainnet action.'])
ps=get('/cosmos/gov/v1/proposals?pagination.reverse=true')['proposals'];p=next(x for x in ps if 'sdk-v0.53-bridge' in json.dumps(x['messages']));m.tx('inflight-upgrade-vote',['gov','vote',p['id'],'yes']);print('WAIT HEIGHT',h,flush=True)
for _ in range(240):
 try:cur=int(json.load(urllib.request.urlopen('http://127.0.0.1:43651/status',timeout=5))['result']['sync_info']['latest_block_height'])
 except Exception:time.sleep(1);continue
 if cur>=h-1:break
 time.sleep(1)
else:raise Exception('upgrade did not reach boundary')
# Wait for old handler halt evidence before replacing binaries.
for _ in range(30):
 logs=subprocess.check_output(['docker','logs','vota-inflight-node0','--tail','30'],stderr=subprocess.STDOUT,text=True)
 if 'UPGRADE' in logs and 'NEEDED' in logs:break
 time.sleep(1)
else:raise Exception('no old halt evidence')
(E/'old-halt.log').write_text(logs)
for i in range(4):subprocess.run(['docker','stop','-t','15',f'vota-inflight-node{i}'],check=True,stdout=subprocess.DEVNULL)
backup=T/'before-upgrade';backup.mkdir();subprocess.run(['cp','-a','--reflink=auto',str(T/'node0'),str(backup/'node0')],check=True)
for i in range(4):
 subprocess.run(['docker','rm',f'vota-inflight-node{i}'],check=True,stdout=subprocess.DEVNULL);port=43650+i*10
 subprocess.run(['docker','run','-d','--name',f'vota-inflight-node{i}','--network','host','--memory','8g','--cpus','3','--log-opt','max-size=20m','--log-opt','max-file=3','-v',str(T/f'node{i}')+':/node','-v',str(R/'bin-bridge')+':/runtime:ro','golang:1.26.5-bookworm','/runtime/dorad','start','--home','/node','--minimum-gas-prices','10000000000peaka','--rpc.laddr',f'tcp://127.0.0.1:{port+1}','--p2p.laddr',f'tcp://127.0.0.1:{port}','--address',f'tcp://127.0.0.1:{port+2}','--grpc.address',f'127.0.0.1:{port+3}','--api.enable=true','--api.address',f'tcp://127.0.0.1:{port+4}','--p2p.pex=false','--pruning','nothing'],check=True,stdout=subprocess.DEVNULL)
for _ in range(180):
 try:
  cur=int(json.load(urllib.request.urlopen('http://127.0.0.1:43651/status',timeout=5))['result']['sync_info']['latest_block_height'])
  if cur>=h+3:break
 except Exception:pass
 time.sleep(1)
else:raise Exception('new version not producing')
a=capture('wasm-immediately-post-upgrade.json');b=json.loads((E/'wasm-immediately-pre-upgrade.json').read_text());assert a==b,'Wasm query output changed across upgrade'
pend=get('/ibc/core/channel/v1/channels/channel-18/ports/transfer/packet_commitments');assert len(pend['commitments'])==4;(E/'post-upgrade-pending-state.json').write_text(json.dumps(pend,indent=2));print('UPGRADE AND WASM QUERY EQUALITY PASSED',cur,flush=True)
