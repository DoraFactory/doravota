from pathlib import Path
import subprocess,shutil,json,re,os
r=Path('/root/vota-final-snapshot-rehearsal-d37fa73'); old=Path('/root/doravota-snapshot-rehearsal-20260911'); baseline=old/'baseline-v044'
for i in range(1,4):
 subprocess.run(['cp','-a','--reflink=auto',str(r/'node0'),str(r/f'node{i}')],check=True)
 for n in ['node_key.json','priv_validator_key.json']:
  shutil.copyfile(baseline/f'node{i}/config'/n,r/f'node{i}/config'/n)
ids=[]
for i in range(4):
 ids.append(subprocess.check_output([str(old/'bin/dorad'),'tendermint','show-node-id','--home',str(r/f'node{i}')],env={**os.environ,'LD_LIBRARY_PATH':str(old/'bin')},text=True).strip())
for i in range(4):
 h=r/f'node{i}';g=h/'config/genesis.json';o=json.loads(g.read_text());o['chain_id']='vota-final-d37fa73';g.write_text(json.dumps(o))
 shutil.copyfile(r/'signers'/str(i)/'priv_validator_state.json',h/'data/priv_validator_state.json')
 p=h/'data/upgrade-info.json'
 if p.exists():p.unlink()
 p=h/'config/config.toml';s=p.read_text()
 for k,v in {'persistent_peers':','.join(f'{ids[j]}@127.0.0.1:{44650+j*10}' for j in range(4) if j!=i),'seeds':'','pprof_laddr':''}.items():s=re.sub(r'^'+k+r' = .*',k+' = '+json.dumps(v),s,flags=re.M)
 s=re.sub(r'^pex = .*','pex = false',s,flags=re.M);s=re.sub(r'^enable = true','enable = false',s,flags=re.M)
 s=re.sub(r'^timeout_commit = .*','timeout_commit = "1s"',s,flags=re.M);p.write_text(s)
print('four isolated nodes prepared',flush=True)
