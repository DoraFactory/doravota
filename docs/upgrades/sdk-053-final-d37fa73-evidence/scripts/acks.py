import json,pathlib,urllib.request,urllib.parse,time,base64
R=pathlib.Path('/root/vota-final-snapshot-rehearsal-d37fa73');E=R/'evidence';results={}
for c,port in [('snapshot',44751),('peer',44651)]:
 for action in ['send','wrong-signer']:
  label=c+'-ica-'+action;x=json.loads((E/(label+'.json')).read_text());ev=next(v for v in x['tx_result']['events'] if v['type']=='send_packet');a={z['key']:z['value'] for z in ev['attributes']}
  query=" AND ".join("write_acknowledgement."+k+"='"+a[k]+"'" for k in ['packet_dst_port','packet_dst_channel','packet_sequence'])
  url=f'http://127.0.0.1:{port}/tx_search?'+urllib.parse.urlencode({'query':'"'+query+'"','prove':'false'})
  for _ in range(40):
   y=json.load(urllib.request.urlopen(url));ts=y.get('result',{}).get('txs',[])
   if ts:break
   time.sleep(1)
  else:raise Exception('no acknowledgement '+label)
  (E/(label+'-ack-search.json')).write_text(json.dumps(y))
  ack=None
  for t in ts:
   assert int(t['tx_result']['code'])==0
   for v in t['tx_result']['events']:
    d={z['key']:z['value'] for z in v.get('attributes',[])}
    if v['type']=='write_acknowledgement' and all(d.get(k)==a[k] for k in ['packet_dst_port','packet_dst_channel','packet_sequence']):
     ack=json.loads(bytes.fromhex(d['packet_ack_hex']))
  assert ack is not None
  if action=='send':assert ack.get('result') and not ack.get('error'),ack
  else:assert ack.get('error') and not ack.get('result'),ack
  results[label]={'sequence':a['packet_sequence'],'source_channel':a['packet_src_channel'],'destination_channel':a['packet_dst_channel'],'ack':ack}
(E/'ica-ack-summary.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
