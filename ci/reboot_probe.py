"""Real boot-id and replay check on a disposable emulator. Fixed synthetic mission IDs."""
import contextlib,os,signal,subprocess,sys
from pathlib import Path
kit=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(kit))
import custody as fs,lab,phone,worker as w
DONE="freedom-v10-c-reboot001"
PART="freedom-v10-c-partial01"
ROOT=phone.HOME/"freedom-finish-reboot"
def boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
def objects(job):
    with fs.private_dir(job,"work") as work:
        src,ids=w.snapshot(job,work)
        return {"sha":fs.sha(src),"ids":ids}
def prepare():
    with fs.root(phone.HOME) as h: fs.mkdir(h,ROOT.name)
    with fs.root(ROOT) as base:
        for tid in (DONE,PART):
            w.seed(base,tid,fs.wire(w.envelope(tid)))
            with fs.locked(base,tid) as job:
                lab.fixture_approval(job,tid)
                lab.answer(job,tid)
                if tid==DONE: saved=w.run(job,tid)
        p=subprocess.run([sys.executable,"-I","-S","-B",str(Path(__file__).absolute()),"interrupt"],cwd="/",
                         env={"LC_ALL":"C"},capture_output=True,timeout=15)
        fs.need(p.returncode==-signal.SIGKILL,"expected_interruption")
        pre={"boot":boot(),"build":w.build(),"seal":fs.sha(saved)}
        for tid in (DONE,PART):
            with fs.locked(base,tid) as job:pre[tid]=objects(job)
        fs.atomic_new(base,"pre.json",fs.wire(pre))
def verify():
    with fs.root(ROOT) as base:
        pre=fs.decode(fs.read_file(base,"pre.json"));now=boot()
        fs.need(now and pre["boot"]!=now and pre["build"]==w.build(),"distinct_android_boot_required")
        for tid in (DONE,PART):
            with fs.locked(base,tid) as job:
                fs.need(objects(job)==pre[tid],"reboot_object_drift")
                raw=w.run(job,tid);r=fs.decode(raw)["report"]
                if tid==DONE:fs.need(fs.sha(raw)==pre["seal"] and r["status"]=="PASS","sealed_replay")
                else:fs.need(r["status"]=="OUTCOME_UNKNOWN","uncertain_replayed")
                fs.need(w.run(job,tid)==raw and objects(job)==pre[tid],"mutation_on_recovery")
        obj={"build":pre["build"],"prior_boot":pre["boot"],"current_boot":now,"same_seal":True,
             "partial_outcome":"OUTCOME_UNKNOWN","same_inodes_and_hashes":True}
        if not fs.exists(base,"observed.json"):fs.atomic_new(base,"observed.json",fs.wire(obj))
        fs.need(fs.read_file(base,"observed.json")==fs.wire(obj),"reboot_evidence_changed")
        return obj
def main():
    fs.need(lab.disposable() is not None,"disposable_android_only");os.umask(0o077)
    if sys.argv[1:]==["prepare"]:prepare()
    elif sys.argv[1:]==["after"]:print(fs.wire(verify()).decode())
    elif sys.argv[1:]==["interrupt"]:
        with fs.root(ROOT) as b,fs.locked(b,PART) as j:
            w.run(j,PART,lambda p:os.kill(os.getpid(),signal.SIGKILL) if p=="edit" else None)
    else:raise fs.Stop("mode")
if __name__=="__main__":main()
