from pathlib import Path
import json,subprocess,re,sys,shutil
r=Path('/root/vota-final-snapshot-rehearsal-d37fa73');old=Path('/root/doravota-snapshot-rehearsal-20260911'); phase=sys.argv[1]
assert phase in ['old','new']
binpath=old/'bin' if phase=='old' else r/'bin'
if phase=='old':
 report=json.loads((r/'evidence/prepare.log').read_text());assert len(report['test_governance']['min_deposit'])==1
 for i in range(4):
  for name in ['config.toml','app.toml']:
   p=r/f'node{i}/config'/name;s=p.read_text();s=re.sub(r'426(\d\d)',lambda m:str(44600+int(m[1])+i*10),s);p.write_text(s)
for i in range(4):
 name=f'vota-final-node{i}'
 if phase=='new':
  subprocess.run(['docker','rm',name],check=True,stdout=subprocess.DEVNULL)
 p=44650+i*10
 cmd=['docker','run','-d','--name',name,'--network','host','--memory','5g','--cpus','2','--log-opt','max-size=20m','--log-opt','max-file=3','-v',str(r/f'node{i}')+':/node','-v',str(binpath)+':/runtime:ro','-e','LD_LIBRARY_PATH=/runtime','golang:1.24.7-bookworm','/runtime/dorad','start','--home','/node','--minimum-gas-prices','10000000000peaka','--rpc.laddr',f'tcp://127.0.0.1:{p+1}','--p2p.laddr',f'tcp://127.0.0.1:{p}','--address',f'tcp://127.0.0.1:{p+2}','--grpc.address',f'127.0.0.1:{p+3}','--api.enable=true','--api.address',f'tcp://127.0.0.1:{p+4}','--p2p.pex=false','--pruning','nothing']
 subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL)
print(phase,'nodes launched',flush=True)
