"""Host-only commissioning test of the real TTY confirmation and saved grant."""
import json, os, pty, select, subprocess, sys, tempfile, time
from pathlib import Path
kit=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(kit))
import lab, custody as fs, worker as w
if sys.argv[1:]:
    with fs.root(Path(sys.argv[1])) as fd,fs.locked(fd,lab.TID) as job:
        w.approve(job,lab.TID,"bridge-fixture")
else:
    assert lab.disposable() is None
    with tempfile.TemporaryDirectory() as temp,fs.root(Path(temp)) as fd:
        w.seed(fd,lab.TID,fs.wire(w.envelope(lab.TID)))
        master,slave=pty.openpty()
        try:
            proc=subprocess.Popen([sys.executable,"-I","-S","-B",__file__,temp],stdin=slave,stdout=slave,stderr=slave,
                                  env={"LC_ALL":"C"},close_fds=True,cwd="/")
            buf=bytearray();limit=time.monotonic()+12;marker=("Type APPROVE "+lab.TID+": ").encode()
            while marker not in buf and time.monotonic()<limit:
                if select.select([master],[],[],0.2)[0]:buf.extend(os.read(master,4096))
            assert buf.count(marker)==1 and b'"maximum_edits":1' in buf and b'"one_free_inference":true' in buf
            os.write(master,("APPROVE "+lab.TID+"\n").encode())
            assert proc.wait(timeout=8)==0
            with fs.locked(fd,lab.TID) as job:
                _,g=w.load_grant(job,lab.TID)
                assert g["scope"]["mode"]=="bridge-fixture" and not fs.exists(job,"claim")
            print("PASS real Linux PTY: complete scope visible, one confirmation, one durable grant, zero execution claims")
        finally:
            os.close(master);os.close(slave)
            if proc.poll() is None:proc.kill();proc.wait()
