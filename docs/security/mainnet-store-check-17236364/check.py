import subprocess,json,urllib.request,urllib.parse,base64,pathlib
OUT=pathlib.Path('/tmp/vota-store-check'); RPC='https://vota-rpc.dorafactory.org'
H=17236364

def rpc(method,params):
 url=RPC+'/'+method+'?'+urllib.parse.urlencode(params)
 return json.loads(subprocess.check_output(["curl","-fsS","--max-time","25",url]))
def q(name,path,data,prove=False):
 j=rpc('abci_query',{'path':json.dumps(path),'data':'0x'+data.hex(),'height':str(H),'prove':str(prove).lower()})
 (OUT/(name+'.json')).write_text(json.dumps(j,indent=2))
 r=j.get('result',{}).get('response',{});print(name,'code',r.get('code'),'height',r.get('height'),'log',r.get('log'),'value',r.get('value'),'proof types',[x['type'] for x in (r.get('proofOps') or {}).get('ops',[])])
 return r
if __name__=='__main__':
 q('fee-locked','/store/feeibc/key',b'locked',True)
 q('cap-index','/store/capability/key',b'index',True)
 q('fee-packets','/ibc.applications.fee.v1.Query/IncentivizedPackets',b'\x0a\x04\x18\x64\x20\x01')
 q('fee-channels','/ibc.applications.fee.v1.Query/FeeEnabledChannels',b'\x0a\x04\x18\x64\x20\x01')
 q('fee-account','/cosmos.auth.v1beta1.Query/ModuleAccountByName',b'\x0a\x06feeibc')

def fields(b):
 def vi(i):
  x=s=0
  while True:
   c=b[i];i+=1;x|=(c&127)<<s
   if c<128:return x,i
   s+=7
 out=[];i=0
 while i<len(b):
  tag,i=vi(i);n,w=tag>>3,tag&7
  if w==0:v,i=vi(i)
  elif w==2:
   size,i=vi(i);v=b[i:i+size];i+=size
  elif w in (1,5):size=8 if w==1 else 4;v=b[i:i+size];i+=size
  else:raise ValueError(w)
  out.append((n,v))
 return out

def bs(n,b):
 def vi(x):
  o=b''
  while x>=128:o+=bytes([(x&127)|128]);x>>=7
  return o+bytes([x])
 return vi(n*8+2)+vi(len(b))+b
