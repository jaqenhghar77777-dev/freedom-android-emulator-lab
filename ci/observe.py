"""Trace one fixed checker from exec to exit using an unprivileged external observer."""
import json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path
kit=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(kit))
import checker as ck, custody as fs, lab, worker as w

def observe():
    parent=lab.disposable()
    tracer="/data/data/com.termux/files/usr/bin/strace" if parent else shutil.which("strace")
    fs.need(tracer and Path(tracer).is_file(),"strace_unavailable")
    with tempfile.TemporaryDirectory(dir=parent) as td:
        path=Path(td)/"process-network.log"
        args=[tracer,"-f","-qq","-s","1024","-e","trace=process,network","-o",str(path),
              sys.executable,"-I","-S","-B",str(kit/"checker.py")]
        p=subprocess.run(args,input=ck.render(lab.GOOD),cwd="/",env={"LC_ALL":"C"},capture_output=True,
                         close_fds=True,timeout=15)
        if p.returncode:
            raise fs.Stop("independent_observer_unavailable: "+" | ".join(p.stderr.decode(errors="replace").splitlines()[:2]))
        fs.need(dict(fs.decode(p.stdout),checker_exit_code=p.returncode)==w.WIN,"observed_checker_result")
        data=path.read_bytes()
        rows=[x for x in data.decode("utf-8").splitlines() if x.strip()]
        calls=[]
        for row in rows:
            matched=re.match(r"^\s*(?:\d+\s+)?([a-z0-9_]+)\(",row)
            fs.need(matched is not None,"incomplete_or_unrecognized_trace")
            calls.append(matched[1])
        fs.need(calls.count("execve")==1 and calls[0]=="execve" and calls[-1] in ("exit_group","exit") and
                set(calls)<= {"execve","exit_group","exit"} and
                'execve("'+sys.executable+'"' in rows[0] and str(kit/"checker.py") in rows[0] and
                rows[0].rstrip().endswith("= 0"),"unexpected_process_or_network")
        return {"observer":"unprivileged-strace","startup_through_exit":True,"execve":1,"network_syscalls":0,
                "unexpected_children":0,"trace_sha256":fs.sha(data),"trace":rows}
if __name__=="__main__":
    try: print(json.dumps(observe(),indent=2))
    except (fs.Stop,OSError,ValueError) as exc:
        print(json.dumps({"status":"BLOCKED","reason":str(exc)}));sys.exit(2)
