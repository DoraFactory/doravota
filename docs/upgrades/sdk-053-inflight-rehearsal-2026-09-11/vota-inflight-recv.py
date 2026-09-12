import json,subprocess,urllib.request,urllib.parse,base64,time,pathlib
T=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911/inflight-snapshot-rehearsal');E=T/'upgrade-evidence';b=str(T/'bin-bridge/dorad');peer=json.loads((T/'ibc-peer-private.json').read_text())['address']
st=json.loads(subprocess.check_output([b,'q','ibc','client','state','07-tendermint-0','--node','tcp://127.0.0.1:43751','-o','json'],text=True));h=int(st['client_state']['latest_height']['revision_height'])
key=b'commitments/ports/transfer/channels/channel-18/sequences/1'
u='http://127.0.0.1:43651/abci_query?'+urllib.parse.urlencode({'path':'"/store/ibc/key"','data':'0x'+key.hex(),'height':h-1,'prove':'true'});r=json.load(urllib.request.urlopen(u))['result']['response'];assert int(r['height'])+1==h and int(r['code'])==0

def vi(n):
 a=bytearray()
 while n>127:a.append(n%128+128);n//=128
 a.append(n);return bytes(a)
proof=b''.join(b'\x0a'+vi(len(x))+x for x in [base64.b64decode(p['data']) for p in r['proofOps']['ops']])
tx=json.loads((E/'pre-ack-pending-send-result.json').read_text());attrs={a['key']:a['value'] for ev in tx['tx_result']['events'] if ev['type']=='send_packet' for a in ev['attributes']}
rn,rh=attrs['packet_timeout_height'].split('-');packet={'sequence':attrs['packet_sequence'],'source_port':attrs['packet_src_port'],'source_channel':attrs['packet_src_channel'],'destination_port':attrs['packet_dst_port'],'destination_channel':attrs['packet_dst_channel'],'data':base64.b64encode(attrs['packet_data'].encode()).decode(),'timeout_height':{'revision_number':rn,'revision_height':rh},'timeout_timestamp':attrs['packet_timeout_timestamp']}
msg={'@type':'/ibc.core.channel.v1.MsgRecvPacket','packet':packet,'proof_commitment':base64.b64encode(proof).decode(),'proof_height':{'revision_number':'20260911','revision_height':str(h)},'signer':peer}
t={'body':{'messages':[msg],'memo':'isolated pre-upgrade receive only','timeout_height':'0','extension_options':[],'non_critical_extension_options':[]},'auth_info':{'signer_infos':[],'fee':{'amount':[{'denom':'peaka','amount':'10000000000000000'}],'gas_limit':'1000000','payer':'','granter':''}},'signatures':[]}
p=E/'pre-recv-unsigned.json';p.write_text(json.dumps(t));signed=E/'pre-recv-signed.json'
subprocess.run([b,'tx','sign',str(p),'--from','peer-validator','--home',str(T/'ibc-peer'),'--keyring-backend','test','--chain-id','vota-inflight-peer-1','--node','tcp://127.0.0.1:43751','--output-document',str(signed)],check=True)
x=json.loads(subprocess.check_output([b,'tx','broadcast',str(signed),'--node','tcp://127.0.0.1:43751','-o','json'],text=True));assert x.get('code',0)==0
for i in range(30):
 try:
  z=json.load(urllib.request.urlopen('http://127.0.0.1:43751/tx?hash=0x'+x['txhash']))['result'];assert int(z['tx_result']['code'])==0,z;(E/'pre-recv-result.json').write_text(json.dumps(z,indent=2));print('RECV PASSED',z['height']);break
 except urllib.error.HTTPError:time.sleep(1)
else:raise Exception('not committed')
