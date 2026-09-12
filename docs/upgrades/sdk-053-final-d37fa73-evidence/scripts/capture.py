from pathlib import Path
import subprocess,json,hashlib,re,os,shutil
R=Path('/root/vota-final-snapshot-rehearsal-d37fa73');E=R/'evidence';os.environ['LD_LIBRARY_PATH']=str(R/'bin')
subprocess.run(['python3',str(R/'collect.py'),'final'],check=True)
checks=[]
for i in range(4):
 name=f'vota-final-node{i}';log=subprocess.check_output(['docker','logs',name],stderr=subprocess.STDOUT,text=True);(E/f'new-node{i}.log').write_text(log)
 bad=[line for line in log.splitlines() if re.search(r'panic:|CONSENSUS FAILURE|failed to run migrations|bridge preflight failed|failed to load latest',line,re.I)]
 x=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0];checks.append({'name':name,'oom_killed':x['State']['OOMKilled'],'state':x['State']['Status'],'memory_limit':x['HostConfig']['Memory'],'nanocpus':x['HostConfig']['NanoCpus'],'critical_log_matches':bad,'image_id':x['Image']});assert not bad and not x['State']['OOMKilled']
(E/'node-health.json').write_text(json.dumps(checks,indent=2))
(E/'resources-final.txt').write_text(subprocess.check_output(['free','-h'],text=True)+subprocess.check_output(['df','-h','/root'],text=True)+subprocess.check_output(['docker','stats','--no-stream','--format','{{.Name}} CPU={{.CPUPerc}} MEM={{.MemUsage}}'],text=True))
(E/'candidate-version.yaml').write_text(subprocess.check_output([str(R/'bin/dorad'),'version','--long'],text=True));(E/'candidate-sha256.txt').write_text(subprocess.check_output(['sha256sum',str(R/'bin/dorad'),str(R/'bin/libwasmvm.x86_64.so')],text=True))
(E/'relayer.log').write_text(subprocess.check_output(['docker','logs','vota-final-relayer'],stderr=subprocess.STDOUT,text=True))
for n in ['peer-init.log','link.log','link-retry.log','ica.log','ica-retry.log','acks.log','timeout.log','ordered.log','restart.log','postrestart.log']:
 if (R/n).exists():shutil.copyfile(R/n,E/n)
scripts=E/'scripts';scripts.mkdir(exist_ok=True)
for p in R.glob('*.py'):shutil.copyfile(p,scripts/p.name)
shutil.copyfile('/root/doravota-snapshot-rehearsal-20260911/source-v044/cmd/final-d37-prepare/main.go',scripts/'prepare.go.txt');shutil.copyfile(R/'fix-cache.go',scripts/'fix-cache.go.txt')
(E/'resource-actions.json').write_text(json.dumps({'stopped_old_containers':['vota-rc-state-sync','vota-inflight-relayer','vota-inflight-node0','vota-inflight-node1','vota-inflight-node2','vota-inflight-node3','vota-inflight-peer','vota-bridge-relayer','vota-bridge-ibc-peer'],'preserved':'old databases, original snapshot, baseline checkpoints, old Ping.pub four nodes','removed':'only unused-boundary-node0 temporary copy in this rehearsal directory (~7.2 GiB)','final_nodes_limit':'each 5 GiB and 2 CPUs','final_peer_limit':'3 GiB and 2 CPUs','final_relayer_limit':'1 GiB and 1 CPU'},indent=2))
(E/'sha256.json').write_text(json.dumps({str(p.relative_to(E)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(E.rglob('*')) if p.is_file() and p.name!='sha256.json'},indent=2))
print('public evidence captured; private key files excluded',flush=True)
