"""One local approval, shared v1 inference quota and a report-only mailbox path."""
import base64
import contextlib
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types
KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import worker as w
import custody as fs

HOME=Path("/data/data/com.termux/files/home")
PREFIX=Path("/data/data/com.termux/files/usr")
LIVE=HOME/".freedom-finish"
V1=HOME/".local/share/freedom-bridge-v10"
BRIDGE_SHA="73f0b8a71232edcdaefdf145e3d4c79c240e7f68c3facad50689afb07081d681"

def pinned_bridge():
    with fs.root(V1/"app") as parent:
        fd=os.open("bridge.py",fs.READ,dir_fd=parent)
        with os.fdopen(fd,"rb") as stream:
            s=os.fstat(fd)
            fs.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and
                    stat.S_IMODE(s.st_mode) in (0o600,0o700),"bridge_identity")
            data=stream.read(100001)
    fs.need(fs.sha(data)==BRIDGE_SHA,"unexpected_installed_bridge")
    module=types.ModuleType("pinned_bridge_v10")
    exec(compile(data,"<pinned-bridge-v10>","exec"),module.__dict__)
    return module

def read_path(p,limit=10000):
    with fs.root(p.parent) as fd: return fs.read_file(fd,p.name,limit)

def token(p,prefix):
    value=read_path(p,1024).decode("ascii").strip()
    fs.need(20<=len(value)<=512 and value.startswith(prefix),"invalid_credential")
    return value

@contextlib.contextmanager
def bridge_lock(b):
    with fs.root(b.LOCK.parent) as parent:
        fd=os.open(b.LOCK.name,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600,dir_fd=parent)
        try:
            s=os.fstat(fd)
            fs.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and
                    stat.S_IMODE(s.st_mode)==0o600,"unsafe_bridge_lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally: os.close(fd)

def inference(job,tid,g,b,gh,*,existing_only=False):
    if fs.exists(job,"answer.json"): return
    digest=g["scope"]["task_sha256"]
    with bridge_lock(b):
        jr,rp=b.journal_path(tid),b.receipt_path(tid)
        if os.path.lexists(jr):
            j=fs.decode(read_path(jr))
            fs.need(j.get("task_id")==tid and j.get("source_sha256")==digest and j.get("model")==w.MODEL
                    and j.get("kind")=="bounded_ai_answer_v1","bridge_claim_conflict")
            if os.path.lexists(rp): answer=read_path(rp)
            else: answer=b.canonical(b.make_receipt(tid,w.envelope(tid),digest,"outcome_unknown",ai_attempted=True))
        else:
            if existing_only: return
            fs.need(not os.path.lexists(b.grant_path(tid)) and not os.path.lexists(rp),"bridge_id_collision")
            if not w.current(g) or not b.battery_ok()[0] or b.attempts_today()>=b.DAILY_CAP: return
            key=token(b.OR_KEY,"sk-or-")
            if not b.free_eligible(b.request_json(b.OR_API+"/key",key,maxbytes=60000),
                                   b.request_json(b.OR_API+"/models",key,maxbytes=8000000)): return
            now,task=b.task_by_id(tid,gh)
            fs.need(fs.sha(now)==digest and task==w.registered(tid,now) and w.current(g),"task_changed_before_inference")
            b.claim_once(jr,b.canonical(dict(task_id=tid,source_sha256=digest,kind=task["kind"],
                                             utc_day=b.utc_day(),model=w.MODEL)))
            res=b.process_task(tid,task,digest,key)
            b.save_receipt(tid,res)
            answer=read_path(rp)
        fs.atomic_new(job,"answer.json",answer)

def submit(tid,title,b,gh):
    # An inbox writer can request one registered policy; it cannot issue a grant.
    raw=fs.wire(w.envelope(tid,title));path="inbox/"+tid+".json"
    current=b.get_remote(path,gh)
    if current is None:
        try:
            b.request_json(b.API_REPO+path,gh,method="PUT",payload={"message":"Request bounded synthetic repair",
                           "content":base64.b64encode(raw).decode("ascii")})
        except b.Stop: pass
        current=b.get_remote(path,gh)
    fs.need(current==raw,"inbox_conflict_or_unconfirmed")
    return fs.sha(raw)

def deliver(job,tid,saved,b,gh):
    fs.need(saved==w.sealed(job,tid) and len(saved)<=8192,"invalid_delivery")
    marker=fs.sha(saved).encode()
    if fs.exists(job,"delivered"):
        fs.need(fs.read_file(job,"delivered")==marker,"damaged_delivery_marker")
        return
    path="outbox/"+tid+".json"
    found=b.get_remote(path,gh)
    if found is None:
        try:
            b.request_json(b.API_REPO+path,gh,method="PUT",payload={
                "message":"Return sealed synthetic FREEDOM repair report","content":base64.b64encode(saved).decode("ascii")})
        except b.Stop: pass
        found=b.get_remote(path,gh)
    fs.need(found==saved,"unconfirmed_or_conflicting_outbox")
    fs.atomic_new(job,"delivered",marker)

def tick(job,tid,b,gh,*,evidence_mode="live-bridge"):
    fs.need(evidence_mode in ("live-bridge","bridge-fixture"),"adapter_mode")
    _,approved=w.load_grant(job,tid)
    fs.need(approved["scope"]["mode"]==evidence_mode,"wrong_adapter_mode")
    if fs.exists(job,"sealed.json") or fs.exists(job,"claim"):
        saved=w.run(job,tid)
    else:
        _,g=w.load_grant(job,tid);s=g["scope"]
        fs.need(s["mode"]==evidence_mode,"fixture_never_live")
        try: stable=w.scope(job,tid,evidence_mode)==s
        except (fs.Stop,OSError): stable=False
        if os.path.lexists(b.journal_path(tid)) and not fs.exists(job,"answer.json"):
            inference(job,tid,g,b,gh,existing_only=True)
        if stable and w.current(g) and not fs.exists(job,"withdrawn"):
            if not b.battery_ok()[0]: return None
            path="inbox/"+tid+".json"; expected=fs.read_file(job,"task.json",4096)
            fresh=b.get_remote(path,gh)
            if fresh==expected:
                inference(job,tid,g,b,gh)
                if fs.exists(job,"answer.json"): fresh=b.get_remote(path,gh)
            if fresh!=expected: fs.atomic_new(job,"withdrawn",s["task_sha256"].encode())
        saved=w.run(job,tid)
    if saved:
        fs.need(fs.decode(saved)["report"]["mode"]==evidence_mode,"fixture_never_live")
        if b.battery_ok()[0]: deliver(job,tid,saved,b,gh)
    return saved

def live_context():
    fs.need(os.getuid()!=0 and sys.executable.startswith(str(PREFIX)+"/") and
            os.environ.get("HOME")==str(HOME) and os.environ.get("PREFIX")==str(PREFIX) and
            os.environ.get("PATH")==str(PREFIX)+"/bin:/system/bin" and KIT==LIVE/"app","native_installed_context")
    return Path("/proc/self/attr/current").read_bytes().rstrip(b"\0\n").decode()

def schedule():
    import re
    cmd=str(PREFIX/"bin/termux-job-scheduler");launcher=str(KIT/"scheduled.sh")
    listing=subprocess.check_output([cmd,"--pending"],text=True,timeout=12).strip().splitlines()
    if listing!=["No jobs found"]:
        fs.need(0<len(listing)<=200,"unknown_job_listing")
        for line in listing:
            m=re.fullmatch(r"Pending Job ([0-9]+): (.+?)\s{4}.*",line)
            fs.need(m is not None,"unknown_job_listing")
            if int(m[1])==31741:
                fs.need(m[2]==launcher,"job_id_collision")
                return
    result=subprocess.check_output([cmd,"--script",launcher,"--job-id","31741","--period-ms","1800000",
                   "--network","any","--battery-not-low","true","--persisted","true"],text=True,timeout=20)
    fs.need("response 1" in result and "Pending Job 31741: "+launcher in result,"unverified_registration")

def main(args):
    fs.need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,"start_isolated")
    os.umask(0o077)
    if len(args) in (2,3) and args[0]=="emit":
        sys.stdout.buffer.write(fs.wire(w.envelope(args[1],args[2] if len(args)==3 else w.DEFAULT_GOAL)));return
    domain=live_context()
    with fs.root(LIVE) as base:
        profile=fs.decode(fs.read_file(base,"commissioned.json"))
        fs.need(profile==dict(build=w.build(),abi=os.uname().machine,domain=domain,policy=w.POLICY,approved=True),
                "matching_local_commissioning_attestation_required")
        b=pinned_bridge();gh=token(b.GH_KEY,"github_pat_")
        if len(args)==3 and args[0]=="submit-adjust":
            print(submit(args[1],args[2],b,gh));return
        if args==["review-next"]:
            pending=[t for t in b.list_task_ids(gh) if w.ID.fullmatch(t) and not fs.exists(base,t)]
            for t in pending:
                try:
                    raw,_=b.task_by_id(t,gh);w.registered(t,raw)
                except (fs.Stop,b.Stop,KeyError,TypeError,ValueError): continue
                args=["approve",t];break
            else:
                print("No pending registered repair goals");return
        if args==["pending"]:
            print("\n".join(t for t in b.list_task_ids(gh) if w.ID.fullmatch(t) and not fs.exists(base,t)));return
        if args==["schedule"]:
            fcntl.flock(base,fcntl.LOCK_EX|fcntl.LOCK_NB);schedule();return
        if len(args)==2 and args[0]=="approve":
            tid=args[1];w.envelope(tid);raw,task=b.task_by_id(tid,gh)
            fs.need(task==w.registered(tid,raw),"unsupported_goal")
            fcntl.flock(base,fcntl.LOCK_EX|fcntl.LOCK_NB)
            w.seed(base,tid,raw)
            with fs.locked(base,tid) as j: w.approve(j,tid,"live-bridge")
            return
        fs.need(args==["once"],"expected_pending_approve_once_schedule")
        for tid in sorted(fs.names(base)):
            if not w.ID.fullmatch(tid): continue
            try:
                with fs.locked(base,tid) as j:
                    if not fs.exists(j,"grant") or fs.exists(j,"delivered"):continue
                    tick(j,tid,b,gh)
            except (fs.Stop,b.Stop,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                print(tid,"paused")
if __name__=="__main__":
    try: main(sys.argv[1:])
    except (fs.Stop,OSError,ValueError,KeyError,EOFError): sys.exit("FREEDOM stopped; no new authority")
