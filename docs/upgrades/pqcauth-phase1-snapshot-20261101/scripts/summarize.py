import json,pathlib,collections
R=pathlib.Path('/tmp/doravota-snapshot-20261101.hj0o2X');E=R/'evidence'
result=json.loads((E/'result.json').read_text())
events=json.loads((E/'events.json').read_text())
rows=[json.loads(x) for x in (E/'resources.jsonl').read_text().splitlines()]
summary={'result':result,'resources':{'sample_interval_seconds':0.5,'minimum_free_disk_bytes':min(r['disk_free'] for r in rows),'peak_sum_node_rss_bytes':max(sum(r['rss_bytes'].values()) for r in rows),'sampled_peak_cgroup_memory_bytes_including_file_cache':max(int(r['memory.current']) for r in rows if 'memory.current' in r),'last_memory_events':rows[-1].get('memory.events'),'peak_node_rss_bytes':{str(i):max(r['rss_bytes'].get(str(i),0) for r in rows) for i in range(4)}},'upgrade_timings':[]}
for phase,upgrade in [('v101-upgrade','v1.0.1'),('pqc-upgrade-recovery','v1.1.0')]:
 h=result[upgrade+'_height']
 for i in range(4):
  ev=[e for e in events if e['phase']==phase and e['node']==i and 'line' in e]
  begin=next(e for e in ev if 'Starting upgrade' in e['line'])
  done=next(e for e in ev if 'committed state' in e['line'] and int(json.loads(e['line']).get('height',-1))==h)
  fin=next(e for e in ev if 'finalized block' in e['line'] and int(json.loads(e['line']).get('height',-1))==h)
  summary['upgrade_timings'].append({'upgrade':upgrade,'node':i,'height':h,'handler_to_finalize_seconds':fin['monotonic']-begin['monotonic'],'handler_to_commit_seconds':done['monotonic']-begin['monotonic'],'process_start_to_commit_seconds':done['elapsed'],'method':'controller monotonic receive timestamps of node log lines; includes read/scheduling jitter'})
(E/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
