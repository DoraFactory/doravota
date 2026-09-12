from pathlib import Path
import subprocess,json,os,time,urllib.request,base64,re,sys
R=Path('/root/vota-final-snapshot-rehearsal-d37fa73');E=R/'evidence';B=str(R/'bin/dorad');os.environ['LD_LIBRARY_PATH']=str(R/'bin')
A='dora1ny4nw32wzg70qxdtyy9a6fhkl809echuwj40f4'
def cli(chain,args):
 h=R/('node0' if chain=='snapshot' else 'peer');port=44651 if chain=='snapshot' else 44751
 return [B,*args,'--home',str(h),'--node',f'tcp://127.0.0.1:{port}']
def q(chain,args):return json.loads(subprocess.check_output(cli(chain,['query',*args,'-o','json']),text=True,stderr=subprocess.DEVNULL))
def get(port,path):return json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/{path}',timeout=8))
def tx(chain,label,args,gas='800000'):
 cmd=cli(chain,['tx',*args,'--from','upgrade-tester' if chain=='snapshot' else 'peer-validator','--keyring-backend','test','--chain-id','vota-final-d37fa73' if chain=='snapshot' else 'vota-final-peer-d37fa73','--gas',gas,'--fees','20000000000000000peaka','-y','-o','json'])
 x=json.loads(subprocess.check_output(cmd,text=True));assert int(x.get('code',0))==0,x
 port=44651 if chain=='snapshot' else 44751
 for _ in range(50):
  try:y=get(port,'tx?hash=0x'+x['txhash'])['result']
  except Exception:time.sleep(1);continue
  (E/(label+'.json')).write_text(json.dumps(y,indent=2));assert int(y['tx_result']['code'])==0,y;print(label,y['height'],flush=True);return y
 raise Exception('transaction timeout '+label)
def rly(*args):return subprocess.check_output(['docker','run','--rm','--network','host','--user','0:0','-v',str(R)+':/work','--entrypoint','rly','ghcr.io/cosmos/relayer:latest',*args,'--home','/work/relayer'],text=True)
def wait(fn):
 for _ in range(90):
  try:
   x=fn()
   if x:return x
  except Exception:pass
  time.sleep(1)
 raise Exception('condition timeout')
def bal(c,a):return int(next((x['amount'] for x in q(c,['bank','balances',a])['balances'] if x['denom']=='peaka'),'0'))
def field(n,b):
 if isinstance(b,str):b=b.encode()
 def vi(v):
  o=bytearray()
  while v>=128:o.append((v&127)|128);v>>=7
  o.append(v);return bytes(o)
 return vi(n*8+2)+vi(len(b))+b
mode=sys.argv[1]
if mode=='init':
 def d(*a):return subprocess.check_output([B,*a,'--home',str(R/'peer')],text=True,stderr=subprocess.DEVNULL)
 if not (R/'peer/config/genesis.json').exists(): d('init','final-ica-peer','--chain-id','vota-final-peer-d37fa73')
 k=json.loads(d('keys','add','peer-validator','--keyring-backend','test','--output','json'));p=R/'peer-private.json';p.write_text(json.dumps(k));p.chmod(0o600)
 p=R/'peer/config/genesis.json';g=json.loads(p.read_text().replace('"stake"','"peaka"'));g['app_state']['interchainaccounts']['host_genesis_state']['params']['allow_messages']=['*'];p.write_text(json.dumps(g))
 d('genesis','add-genesis-account',k['address'],'1000000000000000000000000peaka');d('genesis','gentx','peer-validator','100000000000000000000000peaka','--keyring-backend','test','--chain-id','vota-final-peer-d37fa73');d('genesis','collect-gentxs')
 p=R/'peer/config/config.toml';s=p.read_text().replace('pex = true','pex = false');s=re.sub(r'^pprof_laddr = .*','pprof_laddr = ""',s,flags=re.M);s=s.replace('timeout_commit = "5s"','timeout_commit = "1s"');p.write_text(s)
 subprocess.run(['docker','run','-d','--name','vota-final-peer','--network','host','--memory','3g','--cpus','2','--log-opt','max-size=20m','--log-opt','max-file=3','-v',str(R/'peer')+':/node','-v',str(R/'bin')+':/runtime:ro','-e','LD_LIBRARY_PATH=/runtime','golang:1.24.7-bookworm','/runtime/dorad','start','--home','/node','--rpc.laddr','tcp://127.0.0.1:44751','--p2p.laddr','tcp://127.0.0.1:44750','--address','tcp://127.0.0.1:44752','--grpc.address','127.0.0.1:44753','--api.address','tcp://127.0.0.1:44754','--minimum-gas-prices','10000000000peaka'],check=True,stdout=subprocess.DEVNULL)
 wait(lambda:int(get(44751,'status')['result']['sync_info']['latest_block_height'])>1)
 rly('config','init')
 for c,cid,port in [('snapshot','vota-final-d37fa73',44651),('peer','vota-final-peer-d37fa73',44751)]:
  cfg={'type':'cosmos','value':{'key':'relayer','chain-id':cid,'rpc-addr':f'http://127.0.0.1:{port}','account-prefix':'dora','keyring-backend':'test','gas-adjustment':1.5,'gas-prices':'10000000000peaka','timeout':'20s','output-format':'json','sign-mode':'direct','coin-type':118}}
  (R/(c+'-relayer.json')).write_text(json.dumps(cfg));rly('chains','add','--file','/work/'+c+'-relayer.json',c)
  k=rly('keys','add',c,'relayer');p=R/(c+'-relayer-private.json');p.write_text(k);p.chmod(0o600)
 print('peer and relayer configured',flush=True)
elif mode=='link':
 for c in ['snapshot','peer']:
  if (E/('fund-'+c+'-relayer.json')).exists():continue
  addr=rly('keys','show',c,'relayer').strip();tx(c,'fund-'+c+'-relayer',['bank','send',A if c=='snapshot' else 'peer-validator',addr,'50000000000000000000peaka'])
 rly('paths','new','vota-final-d37fa73','vota-final-peer-d37fa73','final-transfer');rly('tx','link','final-transfer')
 cfg=rly('config','show','--json');(E/'relayer-config.json').write_text(cfg)
 subprocess.run(['docker','run','-d','--name','vota-final-relayer','--network','host','--user','0:0','--memory','1g','--cpus','1','--log-opt','max-size=20m','--log-opt','max-file=3','-v',str(R)+':/work','--entrypoint','rly','ghcr.io/cosmos/relayer:latest','start','final-transfer','--home','/work/relayer'],check=True,stdout=subprocess.DEVNULL)
 print('link complete',flush=True)
elif mode=='ica':
 cfg=json.loads((E/'relayer-config.json').read_text());path=cfg['paths']['final-transfer'];conn={'snapshot':path['src']['connection-id'],'peer':path['dst']['connection-id']}
 peer=json.loads((R/'peer-private.json').read_text())['address'];summary={}
 for c,other,owner,recipient in [('snapshot','peer',A,peer),('peer','snapshot',peer,A)]:
  if not (E/(c+'-ica-register.json')).exists(): tx(c,c+'-ica-register',['ica','controller','register',conn[c]])
  addr=wait(lambda:q(c,['ica','controller','interchain-account',owner,conn[c]]).get('address'))
  tx(other,c+'-ica-fund',['bank','send','peer-validator' if other=='peer' else A,addr,'2000000000000000000peaka'])
  before=bal(other,recipient)
  def packet(sender,label):
   msg=field(1,sender)+field(2,recipient)+field(3,field(1,'peaka')+field(2,str(10**18)));data=field(1,field(1,'/cosmos.bank.v1beta1.MsgSend')+field(2,msg));f=R/(label+'.json');f.write_text(json.dumps({'type':'TYPE_EXECUTE_TX','data':base64.b64encode(data).decode(),'memo':''}));return str(f)
  tx(c,c+'-ica-send',['ica','controller','send-tx',conn[c],packet(addr,c+'-packet')]);wait(lambda:bal(other,addr)==10**18 and bal(other,recipient)==before+10**18)
  good=bal(other,recipient);tx(c,c+'-ica-wrong-signer',['ica','controller','send-tx',conn[c],packet(recipient,c+'-wrong-packet')]);time.sleep(12)
  assert bal(other,addr)==10**18 and bal(other,recipient)==good
  summary[c]={'ica':addr,'connection':conn[c],'balance':str(bal(other,addr)),'recipient_before':str(before),'recipient_after':str(good),'wrong_signer_balances_unchanged':True}
  (E/'ica-summary.json').write_text(json.dumps(summary,indent=2))
 print('bidirectional ICA execution and wrong-signer balance checks passed; acknowledgements still require verification',flush=True)
