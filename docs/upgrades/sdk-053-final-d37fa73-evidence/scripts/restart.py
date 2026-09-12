import json,pathlib,subprocess,time,urllib.request
r=pathlib.Path('/root/vota-final-snapshot-rehearsal-d37fa73');e=r/'evidence'
assert json.loads((e/'ordered-summary.json').read_text())['send_after_reopen_passed']
def height():return int(json.load(urllib.request.urlopen('http://127.0.0.1:44651/status',timeout=5))['result']['sync_info']['latest_block_height'])
h=height();time.sleep(6)
subprocess.run(['docker','stop','-t','15','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['docker','stop','-t','30',*[f'vota-final-node{i}' for i in range(4)]],check=True,stdout=subprocess.DEVNULL)
subprocess.run(['docker','start',*[f'vota-final-node{i}' for i in range(4)]],check=True,stdout=subprocess.DEVNULL)
for _ in range(50):
 try:
  heights=[int(json.load(urllib.request.urlopen(f'http://127.0.0.1:{44651+i*10}/status',timeout=5))['result']['sync_info']['latest_block_height']) for i in range(4)]
  after=min(heights)
  if after>h+3:break
 except Exception:pass
 time.sleep(1)
else:raise Exception('restart did not resume blocks')
subprocess.run(['docker','start','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
(e/'restart-progress.json').write_text(json.dumps({'before_height':h,'after_height':after,'all_four_processes_restarted':True},indent=2))
subprocess.run(['python3',str(r/'collect.py'),'restart'],check=True)
print('four-node restart passed',flush=True)
