import sys,importlib.util,json,subprocess,time,urllib.parse
sys.argv=['timeout.py','timeout'];spec=importlib.util.spec_from_file_location('m','/root/vota-final-snapshot-rehearsal-d37fa73/ibc.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
E=m.E;R=m.R;c='snapshot';other='peer';summary=json.loads((E/'ica-summary.json').read_text());ica=summary[c]['ica'];peer=json.loads((R/'peer-private.json').read_text())['address'];conn=summary[c]['connection']
x=json.loads((E/'snapshot-ica-send.json').read_text());a={z['key']:z['value'] for z in next(v for v in x['tx_result']['events'] if v['type']=='send_packet')['attributes']};port=a['packet_src_port'];channel=a['packet_src_channel'];before=m.q(c,['ibc','channel','end',port,channel]);(E/'ica-timeout-channel-before.json').write_text(json.dumps(before))
assert before['channel']['state']=='STATE_OPEN'
subprocess.run(['docker','stop','-t','15','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
balances=(m.bal(other,ica),m.bal(other,peer))
try:
 t=m.tx(c,'ica-timeout-send',['ica','controller','send-tx',conn,str(R/'snapshot-packet.json'),'--packet-timeout-timestamp','10000000000'])
 a={z['key']:z['value'] for z in next(v for v in t['tx_result']['events'] if v['type']=='send_packet')['attributes']}
 time.sleep(20)
finally:subprocess.run(['docker','start','vota-final-relayer'],check=True,stdout=subprocess.DEVNULL)
query=" AND ".join("timeout_packet."+k+"='"+a[k]+"'" for k in ['packet_src_port','packet_src_channel','packet_sequence'])
def find():
 y=m.get(44651,'tx_search?'+urllib.parse.urlencode({'query':'"'+query+'"'}));return y if y.get('result',{}).get('txs') else None
y=m.wait(find);(E/'ica-timeout-result.json').write_text(json.dumps(y));assert all(int(t['tx_result']['code'])==0 for t in y['result']['txs']);assert balances==(m.bal(other,ica),m.bal(other,peer))
after=m.q(c,['ibc','channel','end',port,channel]);(E/'ica-timeout-channel-after.json').write_text(json.dumps(after))
if before['channel']['ordering']=='ORDER_ORDERED':
 assert after['channel']['state']=='STATE_CLOSED'
 m.tx(c,'ica-timeout-reregister',['ica','controller','register',conn])
 def opened():
  channels=m.q(c,['ibc','channel','channels'])['channels'];return next((ch for ch in channels if ch['port_id']==port and ch['channel_id']!=channel and ch['state']=='STATE_OPEN'),None)
 reopened=m.wait(opened);assert m.q(c,['ica','controller','interchain-account',m.A,conn])['address']==ica
 m.tx(c,'ica-after-timeout-send',['ica','controller','send-tx',conn,str(R/'snapshot-packet.json')]);m.wait(lambda:m.bal(other,ica)==balances[0]-10**18 and m.bal(other,peer)==balances[1]+10**18)
else:reopened=None
(E/'ica-timeout-summary.json').write_text(json.dumps({'old_channel':channel,'before':before['channel'],'after':after['channel'],'timeout_committed':True,'balances_unchanged_on_timeout':True,'reopened':reopened,'ica_address_preserved':True if reopened else None,'send_after_reopen_passed':bool(reopened)},indent=2));print('ICA timeout and recovery passed',flush=True)
