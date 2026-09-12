import subprocess,json,time,importlib.util,urllib.request,urllib.error,hashlib,pathlib
T=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911/inflight-snapshot-rehearsal');E=T/'upgrade-evidence';sp=importlib.util.spec_from_file_location('tx',T/'vota-upgrade-txs.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
peer=json.loads((T/'ibc-peer-private.json').read_text())['address'];b=str(T/'bin-bridge/dorad')
def get(p):return json.load(urllib.request.urlopen('http://127.0.0.1:43654'+p,timeout=15))
def pq(args):return json.loads(subprocess.check_output([b,'q']+args+['--home',str(T/'ibc-peer'),'--node','tcp://127.0.0.1:43751','-o','json'],text=True))
def amount(cs,denom):return int(next((c['amount'] for c in cs if c['denom']==denom),'0'))
def vb():return get('/cosmos/bank/v1beta1/balances/'+m.TESTER)['balances']
def pc():return pq(['ibc','channel','packet-commitments','transfer','channel-0'])['commitments']
def vc():return get('/ibc/core/channel/v1/channels/channel-18/ports/transfer/packet_commitments')['commitments']
def wait(f):
 for _ in range(120):
  if f():return
  time.sleep(1)
 raise Exception('not settled')
assert (E/'wasm-immediately-post-upgrade.json').exists()
assert len(vc())==4 and len(pc())==1
p=T/'relayer-bridge/config/config.yaml';s=p.read_text().replace('127.0.0.1:5183','127.0.0.1:5283').replace('127.0.0.1:5184','127.0.0.1:5284');p.write_text(s)
subprocess.run(['docker','run','-d','--name','vota-inflight-relayer','--network','host','--user','0:0','--log-opt','max-size=20m','--log-opt','max-file=3','-v',str(T)+':/work','--entrypoint','rly','ghcr.io/cosmos/relayer:latest','start','bridge-transfer','--home','/work/relayer-bridge'],check=True)
wait(lambda:not vc() and not pc())
start=json.loads((E/'inflight-start-balances.json').read_text());vv='ibc/'+hashlib.sha256(b'transfer/channel-18/peaka').hexdigest().upper();pv='ibc/'+hashlib.sha256(b'transfer/channel-0/peaka').hexdigest().upper()
expected=amount(start['vota'],'peaka')-117*10**18-9*10**16
assert amount(vb(),'peaka')==expected,(vb(),expected)
assert amount(vb(),vv)==40*10**18
pb=pq(['bank','balances',peer])['balances'];assert amount(pb,pv)==17*10**18
assert amount(pb,'peaka')==amount(start['peer']['balances'],'peaka')-40*10**18-2*10**16
r={'vota_before':start['vota'],'vota_after':vb(),'peer_after':pb,'expected_vota_native':str(expected),'outgoing_delivered':'17000000000000000000','timeout_refunded':'20000000000000000000','error_refunded':'30000000000000000000','incoming_received':'40000000000000000000','vota_commitments':vc(),'peer_commitments':pc(),'fees_vota':'90000000000000000','test_delegation':'100000000000000000000'};(E/'inflight-settlement.json').write_text(json.dumps(r,indent=2));print('ALL FIVE CROSS-UPGRADE CASES SETTLED',flush=True)
x=json.loads(subprocess.check_output([b,'tx','ibc-transfer','transfer','transfer','channel-0',m.TESTER,str(17*10**18)+pv,'--from','peer-validator','--home',str(T/'ibc-peer'),'--keyring-backend','test','--chain-id','vota-inflight-peer-1','--node','tcp://127.0.0.1:43751','--gas','500000','--fees','10000000000000000peaka','-y','-o','json'],text=True));assert x.get('code',0)==0;(E/'post-return-peer-submit.json').write_text(json.dumps(x))
wait(lambda:amount(vb(),'peaka')==expected+17*10**18)
m.tx('post-return-vota',['ibc-transfer','transfer','transfer','channel-18',peer,str(40*10**18)+vv])
wait(lambda:not vc() and not pc() and amount(pq(['bank','balances',peer])['balances'],'peaka')==amount(start['peer']['balances'],'peaka')-3*10**16)
assert amount(vb(),vv)==0 and amount(pq(['bank','balances',peer])['balances'],pv)==0
assert amount(vb(),'peaka')==amount(start['vota'],'peaka')-100*10**18-10*10**16
(E/'inflight-roundtrip.json').write_text(json.dumps({'vota':vb(),'peer':pq(['bank','balances',peer]),'native_principal_restored':True,'voucher_balances_zero':True,'fees_vota':'100000000000000000','test_delegation':'100000000000000000000','fees_peer':'30000000000000000'},indent=2));print('BOTH DIRECTIONS RETURNED PRINCIPAL',flush=True)
