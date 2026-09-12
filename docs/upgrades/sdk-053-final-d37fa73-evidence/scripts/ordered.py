import sys,importlib.util,json,subprocess,time,urllib.parse
sys.argv=['ordered.py','ordered'];spec=importlib.util.spec_from_file_location('m','/root/vota-final-snapshot-rehearsal-d37fa73/ibc.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);R=m.R;E=m.E
k=json.loads(subprocess.check_output([m.B,'keys','add','ordered-tester','--keyring-backend','test','--output','json','--home',str(R/'node0')],text=True,stderr=subprocess.DEVNULL));p=R/'ordered-private.json';p.write_text(json.dumps(k));p.chmod(0o600);owner=k['address'];conn='connection-54';port='icacontroller-'+owner
m.tx('snapshot','ordered-owner-fund',['bank','send',m.A,owner,'10000000000000000000peaka'])
orig=m.cli
def cli(c,args):
 if c=='snapshot' and args[0]=='tx':args[args.index('--from')+1]='ordered-tester'
 return orig(c,args)
m.cli=cli
m.tx('snapshot','ordered-register',['ica','controller','register',conn,'--ordering','ORDER_ORDERED'])
ica=m.wait(lambda:m.q('snapshot',['ica','controller','interchain-account',owner,conn]).get('address'))
def opened():return next((c for c in m.q('snapshot',['ibc','channel','channels'])['channels'] if c['port_id']==port and c['state']=='STATE_OPEN'),None)
ch=m.wait(opened);assert ch['ordering']=='ORDER_ORDERED';peer=json.loads((R/'peer-private.json').read_text())['address'];m.tx('peer','ordered-ica-fund',['bank','send','peer-validator',ica,'2000000000000000000peaka'])
msg=m.field(1,ica)+m.field(2,peer)+m.field(3,m.field(1,'peaka')+m.field(2,str(10**18)));import base64
packet=R/'ordered-packet.json';packet.write_text(json.dumps({'type':'TYPE_EXECUTE_TX','data':base64.b64encode(m.field(1,m.field(1,'/cosmos.bank.v1beta1.MsgSend')+m.field(2,msg))).decode(),'memo':''}))
b=m.bal('peer',peer);m.tx('snapshot','ordered-send',['ica','controller','send-tx',conn,str(packet)]);m.wait(lambda:m.bal('peer',ica)==10**18 and m.bal('peer',peer)==b+10**18)
time.sleep(6)
subprocess.run(['docker','stop','-t','15','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
try:
 t=m.tx('snapshot','ordered-timeout-send',['ica','controller','send-tx',conn,str(packet),'--packet-timeout-timestamp','10000000000']);time.sleep(20)
finally:subprocess.run(['docker','start','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
a={z['key']:z['value'] for z in next(e for e in t['tx_result']['events'] if e['type']=='send_packet')['attributes']};query=' AND '.join("timeout_packet."+key+"='"+a[key]+"'" for key in ['packet_src_port','packet_src_channel','packet_sequence'])
def timeout_found():
 y=m.get(44651,'tx_search?'+urllib.parse.urlencode({'query':'"'+query+'"'}));return y if y.get('result',{}).get('txs') else None
y=m.wait(timeout_found);(E/'ordered-timeout-result.json').write_text(json.dumps(y));assert all(int(t['tx_result']['code'])==0 for t in y['result']['txs'])
closed=m.q('snapshot',['ibc','channel','end',port,ch['channel_id']]);assert closed['channel']['state']=='STATE_CLOSED';assert m.bal('peer',ica)==10**18 and m.bal('peer',peer)==b+10**18
m.tx('snapshot','ordered-reregister',['ica','controller','register',conn,'--ordering','ORDER_ORDERED']);new=m.wait(opened);assert new['channel_id']!=ch['channel_id'];assert m.q('snapshot',['ica','controller','interchain-account',owner,conn])['address']==ica
m.tx('snapshot','ordered-send-after-reopen',['ica','controller','send-tx',conn,str(packet)]);m.wait(lambda:m.bal('peer',ica)==0 and m.bal('peer',peer)==b+2*10**18)
(E/'ordered-summary.json').write_text(json.dumps({'ica':ica,'old_channel':ch,'closed_channel':closed,'new_channel':new,'timeout_committed':True,'timeout_balance_unchanged':True,'address_preserved_on_reopen':True,'send_after_reopen_passed':True},indent=2));print('ordered ICA execution, timeout, reopen and re-execution passed',flush=True)
