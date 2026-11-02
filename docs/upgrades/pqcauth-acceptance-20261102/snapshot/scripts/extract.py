import hashlib, json, pathlib, shutil, subprocess, tarfile, time
R=pathlib.Path('/work')
target=R/'pristine'
target.mkdir(exist_ok=False)
archive=pathlib.Path('/source/source.tar.lz4')
assert archive.stat().st_size == 4977990807
h=hashlib.sha256()
with archive.open('rb') as f:
    for b in iter(lambda:f.read(4*1024*1024),b''): h.update(b)
assert h.hexdigest() == '680b7c73deb36aacce4ba2158064e50bef0be9d78286cc286070dd8cd2f5b59b'
p=subprocess.Popen(['/tools/lz4','-dc',str(archive)],stdout=subprocess.PIPE)
count=total=0
try:
    with tarfile.open(fileobj=p.stdout,mode='r|') as t:
        for m in t:
            path=pathlib.PurePosixPath(m.name)
            assert not path.is_absolute() and '..' not in path.parts, m.name
            assert path.parts and path.parts[0] in ('data','wasm'), m.name
            assert m.isfile() or m.isdir(), m.name
            assert shutil.disk_usage(R).free > 40*1024**3, 'disk reserve exhausted'
            total+=m.size
            assert total<12*1024**3, 'unexpected expanded size'
            out=target/path
            if m.isdir():out.mkdir(parents=True,exist_ok=True)
            else:
                out.parent.mkdir(parents=True,exist_ok=True)
                with t.extractfile(m) as src, out.open('xb') as dest:shutil.copyfileobj(src,dest,1024*1024)
            count+=1
    assert p.wait()==0
finally:
    if p.poll() is None:p.terminate();p.wait()
(R/'source-manifest.json').write_text(json.dumps({'source':'https://server-1.itrocket.net/mainnet/doravota/doravota_2026-11-01_18029707_snap.tar.lz4','height':18029707,'compressed_bytes':archive.stat().st_size,'expanded_bytes':total,'files_and_directories':count,'sha256':h.hexdigest(),'hash_provenance':'locally calculated, not a vendor signature','extracted_at':time.time()},indent=2))
print('EXTRACTED',count,total,h.hexdigest(),flush=True)
