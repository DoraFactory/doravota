from pathlib import Path
import shutil,subprocess,os,json
r=Path('/root/vota-final-snapshot-rehearsal-d37fa73');old=Path('/root/doravota-snapshot-rehearsal-20260911');b=old/'baseline-v044'
subprocess.run(['docker','stop','-t','30',*[f'vota-final-node{i}' for i in range(4)]],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['docker','rm',*[f'vota-final-node{i}' for i in range(4)]],check=True,stdout=subprocess.DEVNULL)
(r/'dry-run-evidence').mkdir(exist_ok=False)
for p in list((r/'evidence').iterdir()):
 if p.name!='mainnet-gov-store.json':shutil.move(p,r/'dry-run-evidence'/p.name)
for i in range(4):
 shutil.rmtree(r/f'node{i}');shutil.copyfile(b/f'node{i}/data/priv_validator_state.json',r/'signers'/str(i)/'priv_validator_state.json')
subprocess.run(['cp','-a','--reflink=auto',str(b/'node0'),str(r/'node0')],check=True)
with open(r/'evidence/prepare.log','w') as f:subprocess.run([str(r/'prepare'),str(r/'node0'),str(r/'signers'),str(r/'evidence/mainnet-gov-store.json')],env={**os.environ,'LD_LIBRARY_PATH':str(old/'bin')},stdout=f,check=True)
x=json.loads((r/'evidence/prepare.log').read_text());assert x['test_minted_peaka']=='1000000000000000000000';assert len(x['test_governance']['min_deposit'])==1
subprocess.run(['python3',str(r/'setup.py')],check=True)
subprocess.run(['docker','run','--rm','--network','none','-v',str(old/'source-v044')+':/src','-v',str(r)+':/work','-v','doravota-pqc-ibc-go-mod:/go/pkg/mod','-v','doravota-pqc-ibc-go-build:/root/.cache/go-build','-w','/src','golang:1.26.5-bookworm','go','run','/work/fix-cache.go','/work'],check=True)
subprocess.run(['python3',str(r/'start.py'),'old'],check=True)
