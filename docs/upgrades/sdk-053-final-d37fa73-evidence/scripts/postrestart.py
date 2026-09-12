import sys,importlib.util,json
sys.argv=['postrestart.py','postrestart'];spec=importlib.util.spec_from_file_location('m','/root/vota-final-snapshot-rehearsal-d37fa73/ibc.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert (m.E/'restart-progress.json').exists();s=json.loads((m.E/'ica-summary.json').read_text());peer=json.loads((m.R/'peer-private.json').read_text())['address'];out={}
for c,other,recipient in [('snapshot','peer',peer),('peer','snapshot',m.A)]:
 a=s[c]['ica'];before=m.bal(other,recipient);ibefore=m.bal(other,a);assert ibefore==10**18
 m.tx(c,c+'-ica-postrestart-send',['ica','controller','send-tx',s[c]['connection'],str(m.R/(c+'-packet.json'))]);m.wait(lambda:m.bal(other,a)==0 and m.bal(other,recipient)==before+10**18)
 out[c]={'ica':a,'balance_before':str(ibefore),'balance_after':str(m.bal(other,a)),'recipient_before':str(before),'recipient_after':str(m.bal(other,recipient))}
(m.E/'ica-postrestart-summary.json').write_text(json.dumps(out,indent=2));print('ICA both directions after restart passed',flush=True)
