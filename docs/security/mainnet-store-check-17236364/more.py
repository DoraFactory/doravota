from check import *
import hashlib
j=json.load(open(OUT/'fee-account.json'))
b=base64.b64decode(j['result']['response']['value'])
mod=dict(fields(dict(fields(b))[1]))[2]
acc=dict(fields(dict(fields(mod))[1]))[1].decode()
print('FEE ACCOUNT',acc)
q('fee-balance','/cosmos.bank.v1beta1.Query/AllBalances',bs(1,acc.encode())+bs(2,b'\x18\x64\x20\x01'))
for name in ['fee-locked','cap-index']:
 r=json.load(open(OUT/(name+'.json')))['result']['response']
 for op in r['proofOps']['ops']:
  p=dict(fields(base64.b64decode(op['data'])))
  if op['type']=='ics23:simple':
   ex=dict(fields(p[1]));print(name,'store root',ex[2].hex(),'empty',ex[2]==hashlib.sha256(b'').digest())
q('cap-owners-scan','/store/capability/subspace',b'capability_index')
q('ibc-channels','/ibc.core.channel.v1.Query/Channels',bs(1,b'\x18\x64\x20\x01'))
header=rpc('block',{'height':str(H+1)});(OUT/'anchor-block.json').write_text(json.dumps(header,indent=2));print('anchor',header['result']['block']['header'])
