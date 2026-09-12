import importlib.util,json,urllib.request,base64,pathlib,time
T=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911/inflight-snapshot-rehearsal');sp=importlib.util.spec_from_file_location('tx',T/'vota-upgrade-txs.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
c='dora1smg5qp5trjdkcekdjssqpjehdjf6n4cjss0clyvqcud3t3u3948s8rmgg4';B='http://127.0.0.1:43654'
def q(c,msg):return json.load(urllib.request.urlopen(B+'/cosmwasm/wasm/v1/contract/'+c+'/smart/'+base64.b64encode(json.dumps(msg).encode()).decode()))['data']
samples=json.loads((T/'upgrade-evidence/registry-business-samples.json').read_text());now=int(time.time());poll=q(c,{'get_next_poll_id':{}})
msg={'create_round':{'operator':samples['operator'],'vote_option_map':['A','B'],'round_info':{'title':'ISOLATED SDK upgrade regression','description':'Test fork only','link':''},'voting_time':{'start_time':str((now+30)*10**9),'end_time':str((now+7200)*10**9)},'circuit_type':'1','certification_system':'0','deactivate_enabled':False,'voice_credit_mode':{'unified':{'amount':'100'}},'registration_mode':{'sign_up_with_static_whitelist':{'whitelist':{'users':[{'addr':m.TESTER},{'addr':m.RECIPIENT}]}}},'max_votes_per_option':None}}
(T/'upgrade-evidence/create-round-message.json').write_text(json.dumps(msg,indent=2))
m.tx('old-registry-create-round',['wasm','execute',c,json.dumps(msg),'--amount','46000000000000000000peaka'],gas='10000000')
a=q(c,{'get_poll_address':{'poll_id':poll}});(T/'upgrade-evidence/wasm-test-round.json').write_text(json.dumps({'poll_id':poll,'address':a,'created_before_upgrade':True,'end_time':now+7200},indent=2));print('ROUND',a,flush=True)
queries=['get_round_info','get_voting_time','get_num_sign_up','get_msg_chain_length','get_period','get_all_result','get_state_tree_root']
r={}
for addr in [a]+list(samples['rounds'].values()):
 r[addr]={}
 for k in queries:
  try:r[addr][k]={'data':q(addr,{k:{}})}
  except urllib.error.HTTPError as e:r[addr][k]={'error':e.read().decode()}
(T/'upgrade-evidence/round-pre-queries.json').write_text(json.dumps(r,indent=2))
while time.time()<now+32:time.sleep(1)
m.tx('old-round-signup',['wasm','execute',a,json.dumps({'sign_up':{'pubkey':samples['pubkey']}}),'--amount','48000000000000000peaka'],gas='3000000')
print('signup count',q(a,{'get_num_sign_up':{}}),flush=True)
