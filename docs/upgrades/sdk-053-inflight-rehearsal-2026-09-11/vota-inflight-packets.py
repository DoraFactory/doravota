import subprocess,json,time,importlib.util,urllib.request,hashlib,pathlib
T=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911/inflight-snapshot-rehearsal');E=T/'upgrade-evidence';sp=importlib.util.spec_from_file_location('tx',T/'vota-upgrade-txs.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
peer=json.loads((T/'ibc-peer-private.json').read_text())['address'];binary=str(T/'bin-bridge/dorad')
def get(p):return json.load(urllib.request.urlopen('http://127.0.0.1:43654'+p))
def balances():return get('/cosmos/bank/v1beta1/balances/'+m.TESTER)['balances']
def commits():return get('/ibc/core/channel/v1/channels/channel-18/ports/transfer/packet_commitments')['commitments']
def pq(args):return json.loads(subprocess.check_output([binary,'q']+args+['--home',str(T/'ibc-peer'),'--node','tcp://127.0.0.1:43751','-o','json'],text=True))
long=['--packet-timeout-timestamp','3600000000000']
(E/'pre-ack-pending-state.json').write_text(json.dumps({'commitments':commits(),'peer_balances':pq(['bank','balances',peer]),'peer_ack':pq(['ibc','channel','packet-ack','transfer','channel-0','1'])},indent=2))
assert len(commits())==1,'expected ack pending'
m.tx('pre-success-pending-send',['ibc-transfer','transfer','transfer','channel-18',peer,'10000000000000000000peaka']+long)
m.tx('pre-timeout-pending-send',['ibc-transfer','transfer','transfer','channel-18',peer,'20000000000000000000peaka','--packet-timeout-timestamp','60000000000'])
m.tx('pre-error-pending-send',['ibc-transfer','transfer','transfer','channel-18','not-a-valid-address','30000000000000000000peaka']+long)
x=json.loads(subprocess.check_output([binary,'tx','ibc-transfer','transfer','transfer','channel-0',m.TESTER,'40000000000000000000peaka','--packet-timeout-timestamp','3600000000000','--from','peer-validator','--home',str(T/'ibc-peer'),'--keyring-backend','test','--chain-id','vota-inflight-peer-1','--node','tcp://127.0.0.1:43751','--gas','500000','--fees','10000000000000000peaka','-y','-o','json'],text=True));assert x.get('code',0)==0;(E/'pre-incoming-pending-send.json').write_text(json.dumps(x))
for i in range(30):
 try:
  tx=json.load(urllib.request.urlopen('http://127.0.0.1:43751/tx?hash=0x'+x['txhash']))['result'];assert int(tx['tx_result']['code'])==0;break
 except urllib.error.HTTPError:time.sleep(1)
else:raise RuntimeError('peer tx missing')
(E/'pre-incoming-pending-result.json').write_text(json.dumps(tx,indent=2));c=commits();assert len(c)==4;(E/'pre-upgrade-pending-state.json').write_text(json.dumps({'vota_commitments':c,'vota_balances':balances(),'peer_commitments':pq(['ibc','channel','packet-commitments','transfer','channel-0'])},indent=2));print('PREPARED FOUR OUTGOING AND ONE INCOMING',flush=True)
