import pathlib,subprocess,urllib.request,json,time,base64,hashlib
R=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911');T=R/'inflight-snapshot-rehearsal';E=T/'upgrade-evidence';assert (E/'wasm-business-results.json').exists()
subprocess.run(['docker','stop','-t','30','vota-inflight-node3'],check=True)
p=T/'node3/wasm/wasm';dirs=[x for x in p.iterdir() if x.is_dir()];print('wasm directories',[x.name for x in dirs],flush=True)
# Move only the compiled cache; preserve contract bytecode and all state.
cache=p/'cache';moved=[]
if cache.exists():
 dest=T/'node3-compiled-cache-backup';assert not dest.exists();cache.rename(dest);moved.append(str(cache))
else:raise Exception('expected compiled cache missing; inspect before mutation')
subprocess.run(['docker','start','vota-inflight-node3'],check=True)
reg='dora1smg5qp5trjdkcekdjssqpjehdjf6n4cjss0clyvqcud3t3u3948s8rmgg4';a=json.loads((E/'wasm-test-round.json').read_text())['address']
def query(port,c,q):return json.load(urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/cosmwasm/wasm/v1/contract/'+c+'/smart/'+base64.b64encode(json.dumps(q).encode()).decode(),timeout=30))
for _ in range(90):
 try:
  out={}
  for c,q in [(reg,{'get_next_poll_id':{}}),(a,{'get_num_sign_up':{}}),(a,{'get_msg_chain_length':{}})]:
   x=query(43684,c,q);assert x==query(43654,c,q);out[c+':'+next(iter(q))]=x
  break
 except (urllib.error.URLError,ConnectionError):time.sleep(1)
else:raise Exception('cold cache query failed')
heights=[]
for i in range(4):heights.append(int(json.load(urllib.request.urlopen(f'http://127.0.0.1:{43651+i*10}/status'))['result']['sync_info']['latest_block_height']))
h=min(heights)-2;blocks=[json.load(urllib.request.urlopen(f'http://127.0.0.1:{43651+i*10}/block?height={h}'))['result'] for i in range(4)];assert len({x['block_id']['hash'] for x in blocks})==1;assert len({x['block']['header']['app_hash'] for x in blocks})==1
r={'height':h,'latest_heights':heights,'block_hash':blocks[0]['block_id']['hash'],'app_hash':blocks[0]['block']['header']['app_hash'],'cache_moved':moved,'cold_queries':out,'binary_sha256':hashlib.sha256((R/'bin-bridge/dorad').read_bytes()).hexdigest()};(E/'inflight-final-consistency.json').write_text(json.dumps(r,indent=2));print('COLD CACHE AND FOUR NODES PASS',h,flush=True)
