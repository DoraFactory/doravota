import json,subprocess,urllib.request,pathlib,sys,os
R=pathlib.Path('/root/vota-final-snapshot-rehearsal-d37fa73');E=R/'evidence';phase=sys.argv[1];H=17250314
os.environ['LD_LIBRARY_PATH']=str(R/'bin')
def get(i,p):return json.load(urllib.request.urlopen(f'http://127.0.0.1:{44651+i*10}/'+p,timeout=10))
statuses=[get(i,'status') for i in range(4)];height=min(int(x['result']['sync_info']['latest_block_height']) for x in statuses)-1;assert height>H
summary={'height':height,'binary_sha256':subprocess.check_output(['sha256sum',str(R/'bin/dorad')],text=True).split()[0],'nodes':[]}
for i in range(4):
 assert statuses[i]['result']['node_info']['network']=='vota-final-d37fa73'
 blocks={}
 for label,path in [('status','status'),('same-block',f'block?height={height}'),('first-block',f'block?height={H}'),('first-consensus',f'consensus_params?height={H}'),('first-results',f'block_results?height={H}'),('latest-consensus',f'consensus_params?height={height}'),('peers','net_info')]:
  x=get(i,path);(E/f'{phase}-node{i}-{label}.json').write_text(json.dumps(x));blocks[label]=x
 for label in ['first-consensus','latest-consensus']:assert blocks[label]['result']['consensus_params']['block']=={'max_bytes':'22020096','max_gas':'600000000'}
 cmd=[str(R/'bin/dorad'),'query','gov','params','--height',str(height),'--node',f'tcp://127.0.0.1:{44651+i*10}','--home',str(R/f'node{i}'),'--output','json'];p=json.loads(subprocess.check_output(cmd,text=True))['params'];(E/f'{phase}-node{i}-gov.json').write_text(json.dumps(p))
 assert p['min_deposit']==[{'denom':'peaka','amount':'100000000000000000000000'}];assert p['voting_period']=='120h0m0s' and p['max_deposit_period']=='120h0m0s';assert p['threshold']=='0.500000000000000000';assert p['expedited_min_deposit']==[{'denom':'peaka','amount':'110000000000000000000000'}];assert p['expedited_voting_period']=='24h0m0s';assert p['expedited_threshold']=='0.667000000000000000';assert p['min_deposit_ratio']=='0.000000000000000000' and p['proposal_cancel_ratio']=='0.000000000000000000'
 h=blocks['same-block']['result']['block']['header'];summary['nodes'].append({'node':i,'block_hash':blocks['same-block']['result']['block_id']['hash'],'app_hash':h['app_hash'],'gov':p})
for row in summary['nodes'][1:]:assert row['block_hash']==summary['nodes'][0]['block_hash'] and row['app_hash']==summary['nodes'][0]['app_hash'] and row['gov']==summary['nodes'][0]['gov']
(E/f'{phase}-summary.json').write_text(json.dumps(summary,indent=2));print(phase,'four-node same-height agreement, first and latest gas, gov checks passed at',height,flush=True)
