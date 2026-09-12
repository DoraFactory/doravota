import pathlib,json,importlib.util,urllib.request,base64,time,subprocess
T=pathlib.Path('/root/doravota-snapshot-rehearsal-20260911/inflight-snapshot-rehearsal');E=T/'upgrade-evidence'
def mod(path,name):
 sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
m=mod(T/'vota-upgrade-txs.py','tx');p=T/'recipient-txs.py';p.write_text((T/'vota-upgrade-txs.py').read_text().replace("'--from','upgrade-tester'","'--from','upgrade-recipient'"));m2=mod(p,'tx2')
a=json.loads((E/'wasm-test-round.json').read_text())['address'];reg='dora1smg5qp5trjdkcekdjssqpjehdjf6n4cjss0clyvqcud3t3u3948s8rmgg4';B='http://127.0.0.1:43654'
def q(c,msg):return json.load(urllib.request.urlopen(B+'/cosmwasm/wasm/v1/contract/'+c+'/smart/'+base64.b64encode(json.dumps(msg).encode()).decode()))['data']
assert (E/'inflight-roundtrip.json').exists(),'finish IBC balance assertions before more sender transactions'
assert q(a,{'get_num_sign_up':{}})=='1'
m.tx('post-fund-recipient',['bank','send',m.TESTER,m.RECIPIENT,'2000000000000000000peaka'])
pub={'x':'5299619240641551281634865583518297030282874472190772894086521144482721001553','y':'16950150798460657717958625567821834550301663161624707787222815936182638968203'}
m2.tx('post-old-round-signup',['wasm','execute',a,json.dumps({'sign_up':{'pubkey':pub}}),'--amount','48000000000000000peaka'],gas='3000000');assert q(a,{'get_num_sign_up':{}})=='2'
message={'publish_message':{'messages':[{'data':['1']*10}],'enc_pub_keys':[pub]}}
m.tx('post-old-round-publish',['wasm','execute',a,json.dumps(message),'--amount','121000000000000000peaka'],gas='3000000');assert q(a,{'get_msg_chain_length':{}})=='1'
# This checks message acceptance and Poseidon hashing, not a decrypted valid vote or tally proof.
neg=[]
def fails(label,c,msg,check):
 before=q(c,check)
 try:m.tx(label,['wasm','execute',c,json.dumps(msg)],gas='3000000')
 except AssertionError:
  r=json.loads((E/(label+'-result.json')).read_text());assert int(r['tx_result']['code'])!=0;assert q(c,check)==before;neg.append({'label':label,'code':r['tx_result']['code'],'log':r['tx_result']['log']});return
 raise AssertionError('unexpected success '+label)
fails('post-registry-unauthorized',reg,{'update_amaci_code_id':{'code_id':1}},{'get_amaci_code_id':{}})
fails('post-round-underpaid-message',a,message,{'get_msg_chain_length':{}})
create=json.loads((E/'create-round-message.json').read_text());now=int(time.time());create['create_round']['voting_time']={'start_time':str((now+60)*10**9),'end_time':str((now+3600)*10**9)};create['create_round']['round_info']['title']='ISOLATED post-upgrade create';pid=q(reg,{'get_next_poll_id':{}})
m.tx('post-registry-create-round',['wasm','execute',reg,json.dumps(create),'--amount','46000000000000000000peaka'],gas='10000000');new=q(reg,{'get_poll_address':{'poll_id':pid}});assert new and new!=a
r={'old_round':a,'signups':q(a,{'get_num_sign_up':{}}),'messages':q(a,{'get_msg_chain_length':{}}),'new_round':new,'new_poll_id':pid,'negative_checks':neg,'limitations':['Encrypted message payload is synthetic, not a valid decrypted vote.','Successful Groth16 processing/tally/claim have not been tested.','Historical privileged operations are not impersonated.']};(E/'wasm-business-results.json').write_text(json.dumps(r,indent=2));print('REGISTRY AND OLD ROUND EXECUTION PASSED',flush=True)
