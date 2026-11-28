"""Local one-shot mission engine. Callers hold the lock on the mission directory."""
import difflib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import custody as fs
import checker

MODEL="nvidia/nemotron-3.5-lightning:free"
POLICY="synthetic-adjust-postfix-v1"
ID=re.compile(r"freedom-v10-c-[a-z0-9]{8,24}",re.ASCII)
PROMPT=("Repair synthetic adjusted(x,d,cap); currently returns x. Return x+d clipped to [0,cap]. Domain: x,d=-4..4; cap=0..4. "
        "Observed examples (x,d,cap): (2,1,5) returned 2, expected 3; (1,-4,5) returned 1, expected 0. "
        "Reply only with a JSON array (1-31 postfix tokens). Push x,d,cap,zero. "
        "Binary add,sub,min,max pop right and left in that order. End with one value. No text or tools.")
WIN=dict(supplied=5,supplied_total=5,exhaustive=405,exhaustive_total=405,checker_exit_code=0)
BASELINE=dict(WIN,supplied=2,exhaustive=55)
LIFE=3600

DEFAULT_GOAL="Repair the synthetic bounded adjustment"
def envelope(tid,title=DEFAULT_GOAL):
    fs.need(type(tid) is str and ID.fullmatch(tid),"invalid_task_id")
    fs.need(type(title) is str and 1<=len(title)<=96 and title==title.strip() and
            all(32<=ord(ch)<127 for ch in title),"invalid_goal_label")
    return dict(schema_version=1,task_id=tid,title=title,
                kind="bounded_ai_answer_v1",execution_authorized=False,allow_shell_commands=False,
                allow_file_edits=False,allow_project_access=False,model=MODEL,prompt=PROMPT,model_inference_authorized=True)

def registered(tid,raw):
    fs.need(type(raw) is bytes and len(raw)<=4096,"task_size")
    task=fs.decode(raw)
    fs.need(type(task) is dict and fs.wire(task)==fs.wire(envelope(tid,task.get("title"))),"task_outside_policy")
    return task

def build():
    files=("worker.py","checker.py","custody.py","phone.py","scheduled.sh")
    values={}
    for name in files:
        path=KIT/name
        info=path.lstat()
        fs.need(stat.S_ISREG(info.st_mode) and info.st_uid in (0,os.getuid()) and info.st_nlink==1
                and not info.st_mode&0o022,"unsafe_installation_file")
        values[name]=fs.sha(path.read_bytes())
    return fs.sha(fs.wire(values))

def verify(actual):
    fs.need(len(actual)<=480,"checker_input")
    p=subprocess.run([sys.executable,"-I","-S","-B",str(KIT/"checker.py")],
                     cwd="/",env={"LC_ALL":"C"},input=actual,capture_output=True,close_fds=True,timeout=6)
    fs.need(p.returncode==0 and len(p.stdout)<=512,"independent_checker_rejected")
    result=fs.decode(p.stdout)
    result["checker_exit_code"]=p.returncode
    return result

def snapshot(job,work):
    name=os.stat("work",dir_fd=job,follow_symlinks=False)
    fs.need(stat.S_ISDIR(name.st_mode) and fs.identity(name)==fs.identity(os.fstat(work)),"work_name_changed")
    fs.need(set(fs.names(work))=={"adjust.py","tests.json"},"unexpected_workspace_entry")
    src,src_id=fs.read_object(work,"adjust.py",480)
    cases,test_id=fs.read_object(work,"tests.json")
    fs.need(cases==checker.VECTORS,"protected_tests_changed")
    return src,{"work":fs.identity(name),"source":src_id,"tests":test_id}

def seed(base,tid,raw):
    registered(tid,raw)
    fs.mkdir(base,tid)
    with fs.private_dir(base,tid) as job:
        fs.mkdir(job,"work")
        with fs.private_dir(job,"work") as work:
            fs.create_file(work,"adjust.py",checker.BASE)
            fs.create_file(work,"tests.json",checker.VECTORS)
        fs.atomic_new(job,"task.json",raw)

def scope(job,tid,mode):
    fs.need(mode in ("offline-fixture","bridge-fixture","live-bridge"),"mode")
    raw=fs.read_file(job,"task.json",4096)
    task=registered(tid,raw)
    with fs.private_dir(job,"work") as work:
        src,ids=snapshot(job,work)
    fs.need(src==checker.BASE,"source_changed")
    return dict(id=tid,policy=POLICY,mode=mode,goal_label=task["title"],task_sha256=fs.sha(raw),build_sha256=build(),
                source_sha256=fs.sha(src),tests_sha256=fs.sha(checker.VECTORS),objects=ids,
                job=fs.identity(os.fstat(job)),edit="work/adjust.py",one_free_inference=(mode!="offline-fixture"),
                maximum_edits=1,verification_calls=3,grant_seconds=LIFE,model=MODEL)

def approve(job,tid,mode,ask=input):
    fs.need(not fs.exists(job,"grant") and not fs.exists(job,"claim"),"id_already_used")
    shown=scope(job,tid,mode)
    fs.need(verify(checker.BASE)==BASELINE,"baseline_probe_changed")
    if mode!="offline-fixture":
        fs.need(sys.stdin.isatty() and sys.stdout.isatty(),"local_tty_required")
    print(fs.wire({"scope":shown,"goal":PROMPT,"before":checker.BASE.decode(),"protected_examples":checker.EXAMPLES,
                   "baseline":BASELINE,"report_path":"outbox/"+tid+".json"}).decode().rstrip())
    fs.need(ask("Type APPROVE "+tid+": ")=="APPROVE "+tid,"declined")
    fs.need(scope(job,tid,mode)==shown,"changed_during_approval")
    fs.atomic_new(job,"grant",fs.wire({"scope":shown,"issued":int(time.time())}))

def load_grant(job,tid):
    raw=fs.read_file(job,"grant")
    g=fs.decode(raw);s=g["scope"]
    fs.need(ID.fullmatch(tid) and s["id"]==tid and s["policy"]==POLICY and
            s["mode"] in ("offline-fixture","bridge-fixture","live-bridge") and s["job"]==fs.identity(os.fstat(job)) and
            s["build_sha256"]==build() and type(g["issued"]) is int and s["edit"]=="work/adjust.py"
            and s["maximum_edits"]==1 and s["model"]==MODEL and
            s["source_sha256"]==fs.sha(checker.BASE) and s["tests_sha256"]==fs.sha(checker.VECTORS),"invalid_grant")
    return raw,g

def current(g):
    return 0<=time.time()-g["issued"]<LIFE

def diff(before,after):
    return "".join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
                                        fromfile="before/adjust.py",tofile="after/adjust.py"))

def sealed(job,tid):
    raw=fs.read_file(job,"sealed.json",8192)
    env=fs.decode(raw); report=env["report"]
    gb,g=load_grant(job,tid)
    fs.need(set(env)=={"report","report_sha256"} and raw==fs.wire(env) and
            env["report_sha256"]==fs.sha(fs.wire(report)) and report["id"]==tid and
            report["grant_sha256"]==fs.sha(gb) and report["task_sha256"]==g["scope"]["task_sha256"]
            and report["mode"]==g["scope"]["mode"] and report["status"] in
            ("PASS","FAIL","ABSTAIN","OUTCOME_UNKNOWN"),"bad_seal")
    if report["status"]=="PASS":
        fs.need(fs.read_file(job,"claim")==fs.wire({"grant_sha256":fs.sha(gb)}) and
                report["after"]==WIN and report["before"]==BASELINE and report["changed"]==["work/adjust.py"]
                and report["after_sha256"]==fs.sha(checker.render(report["proposal"])) and
                report["protected_sha256"]==fs.sha(checker.VECTORS) and report["before_sha256"]==fs.sha(checker.BASE) and
                re.fullmatch("[0-9a-f]{64}",report["answer_receipt_sha256"]) and
                report["diff"]==diff(checker.BASE,checker.render(report["proposal"])),"invalid_pass")
    return raw

def finish(job,tid,gb,g,status,reason,**extra):
    report=dict(id=tid,policy=POLICY,goal_label=g["scope"]["goal_label"],status=status,reason=reason,mode=g["scope"]["mode"],
                grant_sha256=fs.sha(gb),task_sha256=g["scope"]["task_sha256"],
                before_sha256=fs.sha(checker.BASE),protected_sha256=fs.sha(checker.VECTORS),**extra)
    fs.atomic_new(job,"sealed.json",fs.wire({"report":report,"report_sha256":fs.sha(fs.wire(report))}))
    return sealed(job,tid)

def receipt(job,tid,s):
    raw=fs.read_file(job,"answer.json",8192);r=fs.decode(raw)
    fs.need(r["task_id"]==tid and r["source_sha256"]==s["task_sha256"] and
            r["schema_version"]==1 and r["kind"]=="bounded_ai_answer_v1" and
            r["worker"]=="freedom-v10-termux-tool-free" and r["remote_shell"] is False and
            r["project_access"] is False and r.get("ai_attempted") is True,"wrong_model_receipt")
    if r["status"]=="answered_unverified":
        fs.need(r.get("diagnostics",{}).get("finish_reason")=="stop","incomplete_answer")
    return raw,r

def run(job,tid,checkpoint=lambda point:None):
    if fs.exists(job,"sealed.json"): return sealed(job,tid)
    gb,g=load_grant(job,tid); s=g["scope"]
    seal=lambda status,reason,**kw:finish(job,tid,gb,g,status,reason,**kw)
    if fs.exists(job,"claim"):
        fs.need(fs.read_file(job,"claim")==fs.wire({"grant_sha256":fs.sha(gb)}),"damaged_claim")
        return seal("OUTCOME_UNKNOWN","prior_unsealed_claim")
    if not current(g):
        if fs.exists(job,"answer.json"):
            try:
                _,expired_receipt=receipt(job,tid,s)
            except (fs.Stop,OSError,KeyError,TypeError,ValueError,AttributeError):
                expired_receipt={}
            if expired_receipt.get("status")=="outcome_unknown":
                return seal("OUTCOME_UNKNOWN","inference_unknown_at_expiry")
        return seal("ABSTAIN","approval_expired")
    try: fs.need(scope(job,tid,s["mode"])==s,"scope_changed")
    except (fs.Stop,OSError): return seal("FAIL","preimage_or_protected_identity")
    if fs.exists(job,"withdrawn"):
        fs.need(fs.read_file(job,"withdrawn")==s["task_sha256"].encode(),"bad_withdrawal")
        return seal("ABSTAIN","mailbox_task_changed")
    if not fs.exists(job,"answer.json"): return None
    try: rb,r=receipt(job,tid,s)
    except (fs.Stop,OSError,ValueError,KeyError,TypeError,AttributeError):
        return seal("ABSTAIN","unbound_or_invalid_receipt")
    fs.atomic_new(job,"claim",fs.wire({"grant_sha256":fs.sha(gb)}));checkpoint("claim")
    if r["status"]!="answered_unverified":
        return seal("OUTCOME_UNKNOWN" if r["status"]=="outcome_unknown" else "ABSTAIN","inference_incomplete")
    try: candidate=checker.render(r["answer"])
    except (ValueError,KeyError,TypeError,RecursionError): return seal("ABSTAIN","proposal_outside_grammar")
    changed=False
    try:
        with fs.private_dir(job,"work") as work:
            before,ids=snapshot(job,work)
            fs.need(before==checker.BASE and ids==s["objects"],"preimage_changed")
            base_result=verify(before); staged_result=verify(candidate)
            if base_result!=BASELINE or staged_result!=WIN:
                return seal("FAIL","candidate_tests",before=base_result,candidate=staged_result,changed=[])
            fs.need(snapshot(job,work)==(before,ids),"changed_before_staging")
            fs.create_file(work,".candidate",candidate);checkpoint("stage")
            actual,cid=fs.read_object(work,".candidate",480)
            fs.need(actual==candidate and fs.read_object(work,"adjust.py")== (before,ids["source"])
                    and fs.read_object(work,"tests.json")== (checker.VECTORS,ids["tests"])
                    and fs.identity(os.stat("work",dir_fd=job,follow_symlinks=False))==ids["work"]
                    and current(g),"changed_before_commit")
            changed=True  # rename may have succeeded even when its directory fsync fails.
            fs.install_stage(work,".candidate","adjust.py");checkpoint("edit")
            actual,final_ids=snapshot(job,work)
            fs.need(actual==candidate and final_ids==dict(ids,source=cid),"wrong_committed_bytes")
            result=verify(actual);checkpoint("verified")
            fs.need(result==WIN and snapshot(job,work)==(actual,final_ids),"postverification_drift")
            delta=diff(before,actual)
            raw=seal("PASS","committed_and_verified",before=base_result,after=result,changed=["work/adjust.py"],
                     after_sha256=fs.sha(actual),answer_receipt_sha256=fs.sha(rb),proposal=r["answer"],diff=delta)
    except (fs.Stop,OSError,ValueError,subprocess.SubprocessError):
        if fs.exists(job,"sealed.json"): return sealed(job,tid)
        return seal("OUTCOME_UNKNOWN" if changed else "FAIL","commit_uncertain" if changed else "staging_or_checker_failure")
    checkpoint("seal")
    return raw
