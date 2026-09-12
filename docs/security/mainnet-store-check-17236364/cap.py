from check import *
from concurrent.futures import ThreadPoolExecutor
r=json.load(open(OUT/'cap-owners-scan.json'))['result']['response']
pairs=[dict(fields(v)) for n,v in fields(base64.b64decode(r['value'])) if n==1]
def run(p):
 key=p[1];i=int.from_bytes(key[-8:],'big');r=q('cap-owner-'+str(i),'/store/capability/key',key,True)
 assert r['code']==0 and int(r['height'])==H and r['value']
 value=base64.b64decode(r['value'])
 owners=[{k:v.decode() for k,v in fields(o)} for n,o in fields(value) if n==1]
 return {'index':i,'owners':owners}
with ThreadPoolExecutor(max_workers=3) as ex: out=list(ex.map(run,pairs))
(OUT/'capabilities-decoded.json').write_text(json.dumps(out,indent=2))
channels=[]
r=json.load(open(OUT/'ibc-channels.json'))['result']['response'];b=base64.b64decode(r['value'])
for n,v in fields(b):
 if n==1:
  c=dict(fields(v));cp=dict(fields(c[3]));channels.append({'channel':c[7].decode(),'port':c[6].decode(),'state':c[1],'version':c[5].decode(),'counterparty_port':cp.get(1,b'').decode(),'counterparty_channel':cp.get(2,b'').decode()})
 if n==2: print('PAGINATION',fields(v))
(OUT/'channels-decoded.json').write_text(json.dumps(channels,indent=2))
print('COUNTS',len(out),len(channels));print(json.dumps(channels,indent=2))
