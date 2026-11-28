"""Disposable synthetic mailbox and real Bridge contract, no external I/O."""
import base64
import contextlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import phone
import worker as w
import custody as fs
import checker

TID="freedom-v10-c-demov001"
GOOD='["x","d","add","zero","max","cap","min"]'

def disposable():
    fs.need(os.getuid()!=0,"nonroot_required")
    if hasattr(sys,"getandroidapilevel") or Path("/system/bin/getprop").exists():
        prop=lambda k: subprocess.check_output(["/system/bin/getprop",k],env={},cwd="/",text=True,timeout=5).strip()
        fs.need(prop("ro.kernel.qemu")=="1" and prop("ro.product.cpu.abi") in ("x86_64","arm64-v8a"),
                "disposable_emulator_required")
        return str(phone.HOME)
    return None

class Mailbox:
    def __init__(self,base,tid,answer=GOOD):
        self.tid=tid;self.answer=answer;self.posts=0;self.puts=0;self.free=True;self.battery=True
        self.ambiguous=False;self.down=False;self.paid=False;self.crash_inference=False
        self.inbox="inbox/"+tid+".json";self.outbox="outbox/"+tid+".json"
        self.objects={self.inbox:fs.wire(w.envelope(tid))}
        v=base/"v1";v.mkdir(mode=0o700);app=v/"app";app.mkdir(mode=0o700)
        src=app/"bridge.py";shutil.copyfile(KIT/"ci/bridge_v10_reference.py",src);src.chmod(0o700)
        with mock.patch.object(phone,"V1",v): self.b=phone.pinned_bridge()
        b=self.b
        for attr in ["GRANTS","JOURNALS","RECEIPTS","UPLOADED"]:
            d=v/attr.lower();d.mkdir(mode=0o700);setattr(b,attr,d)
        b.LOCK=v/"lock";b.OR_KEY=v/"fake.key";b.OR_KEY.write_bytes(b"sk-or-synthetic-fixture-only");b.OR_KEY.chmod(0o600)
        b.request_json=self.transport;b.battery_ok=lambda:(self.battery,"fixture")
    def transport(self,url,key,method="GET",payload=None,**unused):
        b=self.b
        if url.startswith(b.API_REPO):
            path=url[len(b.API_REPO):]
            fs.need(path in (self.inbox,self.outbox),"unexpected_mailbox_path")
            if method=="PUT":
                fs.need(path==self.outbox and path not in self.objects,"no_overwrite")
                self.puts+=1
                if self.down: raise b.Stop("synthetic transport unavailable")
                self.objects[path]=base64.b64decode(payload["content"],validate=True)
                if self.ambiguous: raise b.Stop("synthetic lost acknowledgement")
                return {}
            if path not in self.objects: return None
            return {"encoding":"base64","content":base64.b64encode(self.objects[path]).decode()}
        if url==b.OR_API+"/key": return {"data":{"is_free_tier":self.free,"free_model_daily_requests":{"remaining":1}}}
        if url==b.OR_API+"/models":
            return {"data":[{"id":w.MODEL,"pricing":{"prompt":"1" if self.paid else "0","completion":"0"}}]}
        fs.need(url==b.OR_API+"/chat/completions" and method=="POST" and payload["model"]==w.MODEL
                and payload["provider"]=={"allow_fallbacks":False} and payload["messages"][-1]["content"]==w.PROMPT,
                "misrouted_inference")
        self.posts+=1
        if self.crash_inference: raise KeyboardInterrupt("synthetic death after inference claim")
        return {"choices":[{"message":{"content":self.answer},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":65,"completion_tokens":15,"completion_tokens_details":{"reasoning_tokens":0}}}

def fixture_approval(j,tid,live=False):
    # Only test code supplies the confirmation; production has no fixture flag.
    with contextlib.ExitStack() as stack:
        if live:
            stack.enter_context(mock.patch.object(sys.stdin,"isatty",return_value=True))
            stack.enter_context(mock.patch.object(sys.stdout,"isatty",return_value=True))
        w.approve(j,tid,"bridge-fixture" if live else "offline-fixture",lambda _: "APPROVE "+tid)

def answer(j,tid,program=GOOD,status="answered_unverified",**override):
    _,g=w.load_grant(j,tid)
    fields=dict(schema_version=1,task_id=tid,source_sha256=g["scope"]["task_sha256"],
                kind="bounded_ai_answer_v1",worker="freedom-v10-termux-tool-free",remote_shell=False,
                project_access=False,ai_attempted=True,status=status,answer=program,diagnostics={"finish_reason":"stop"})
    fields.update(override)
    fs.atomic_new(j,"answer.json",fs.wire(fields))

def demo():
    os.umask(0o077);tmp=Path(tempfile.mkdtemp(prefix="freedom-demo-",dir=disposable()))
    box=Mailbox(tmp,TID); root=tmp/"missions";root.mkdir(mode=0o700)
    with fs.root(root) as base:
        w.seed(base,TID,box.objects[box.inbox])
        with fs.locked(base,TID) as j:
            fixture_approval(j,TID,True)
            first=phone.tick(j,TID,box.b,"fixture-mailbox",evidence_mode="bridge-fixture")
            src=(root/TID/"work/adjust.py")
            inode=src.stat().st_ino
            second=phone.tick(j,TID,box.b,"fixture-mailbox",evidence_mode="bridge-fixture")
            fs.need(first==second==box.objects[box.outbox] and inode==src.stat().st_ino and
                    box.posts==1 and box.puts==1,"demo_replay")
            result=fs.decode(first)
            fs.need(result["report"]["status"]=="PASS","demo_failed")
            (tmp/"before.py").write_bytes(checker.BASE);(tmp/"remote_report.json").write_bytes(box.objects[box.outbox])
            record=dict(transport="OFFLINE controlled model and GitHub doubles",authorization="simulated terminal confirmation",
                        worker="actual nonroot CPython filesystem + clean checker",machine=platform.machine(),
                        python=platform.python_version(),uid=os.getuid(),synthetic_model_posts=box.posts,
                        synthetic_mailbox_creates=box.puts,unchanged_inode_on_replay=True,
                        saved_and_returned_identical=True,seal_sha256=fs.sha(first),root=str(tmp),report=result)
            (tmp/"demo.json").write_bytes(fs.wire(record))
            print(json.dumps(record,indent=2))
    return tmp
if __name__=="__main__":
    demo()
