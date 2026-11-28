"""Native non-root integration and adversarial tests. No network or real credentials."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import lab
import worker as w
import custody as fs
import phone
import checker as ck

class Intake(unittest.TestCase):
    def test_write_then_readback_is_idempotent(self):
        class Port:
            API_REPO="https://example.invalid/";Stop=RuntimeError
            def __init__(self):self.current=None;self.creates=0
            def get_remote(self,path,key):
                self.path=path;return self.current
            def request_json(self,url,key,method,payload):
                import base64
                self.creates+=1;self.current=base64.b64decode(payload["content"])
                raise self.Stop("ambiguous network acknowledgement")
        port=Port();title="Keep adjusted values between zero and the cap"
        h=phone.submit(lab.TID,title,port,None);self.assertEqual(phone.submit(lab.TID,title,port,None),h)
        self.assertEqual(port.creates,1);self.assertEqual(w.registered(lab.TID,port.current)["title"],title)
        with self.assertRaises(fs.Stop):phone.submit(lab.TID,"Other label",port,None)
        self.assertEqual(port.creates,1)
    def test_label_cannot_expand_approved_policy(self):
        raw=w.envelope(lab.TID,"A goal for Luna");raw["allow_file_edits"]=True
        with self.assertRaises(fs.Stop):w.registered(lab.TID,fs.wire(raw))
        raw=w.envelope(lab.TID);raw["prompt"]="replace the checker"
        with self.assertRaises(fs.Stop):w.registered(lab.TID,fs.wire(raw))
        for label in ("","bad\nlabel","a"*97):
            with self.assertRaises(fs.Stop):w.envelope(lab.TID,label)
    def test_legacy_stage_b_requires_real_alias_evidence(self):
        import commission
        diag={"rc":0,"nlink":2,"abi":"x86_64","context":"u:r:runas_app:s0"}
        def record():
            return ("FREEDOM_ALIAS_DIAGNOSTIC "+json.dumps(diag)+"\n"+
                    "STAGE_B_PASS: disposable Android native Python preflight\n").encode()
        self.assertEqual(commission.legacy_stage_b(record()),fs.sha(record()))
        diag["nlink"]=1
        with self.assertRaises(fs.Stop):commission.legacy_stage_b(record())
        diag["nlink"]=2;diag["rc"]=1
        with self.assertRaises(fs.Stop):commission.legacy_stage_b(record())
    def test_duplicate_task_field(self):
        raw=fs.wire(w.envelope(lab.TID))
        with self.assertRaises(fs.Stop):w.registered(lab.TID,raw.replace(b'{"',b'{"schema_version":1,"',1))
    def test_stale_finite_choice_cannot_author_code(self):
        with self.assertRaises(ValueError):ck.render('{"choice":"ready"}')
class Grammar(unittest.TestCase):
    def test_exact_good_source(self):
        self.assertEqual(ck.render(lab.GOOD),ck.HEADER+b"min(max((x + d), 0), cap)\n")
    def test_two_distinct_working_programs(self):
        other=ck.render('["cap","zero","d","x","add","max","min"]')
        self.assertNotEqual(other,ck.render(lab.GOOD))
        self.assertEqual(w.verify(other),w.WIN)
    def test_baseline(self):
        self.assertEqual(w.verify(ck.BASE),w.BASELINE)
    def test_maximum_tokens(self):
        p=["x"]+["zero","add"]*15
        self.assertEqual(w.verify(ck.render(json.dumps(p,separators=(",",":")))),w.BASELINE)
    def test_clean_verifier_with_inheritable_canary(self):
        with tempfile.TemporaryFile(dir=lab.disposable()) as f, mock.patch.dict(os.environ,{"FREEDOM_FAKE_SECRET":"canary"}):
            os.set_inheritable(f.fileno(),True)
            self.assertEqual(w.verify(ck.render(lab.GOOD)),w.WIN)
    def test_bad_child_flags(self):
        p=subprocess.run([sys.executable,str(KIT/"checker.py")],input=ck.BASE,capture_output=True)
        self.assertNotEqual(p.returncode,0)
    def test_explicit_leaked_descriptor_is_rejected(self):
        with tempfile.TemporaryFile(dir=lab.disposable()) as f:
            p=subprocess.run([sys.executable,"-I","-S","-B",str(KIT/"checker.py")],input=ck.BASE,cwd="/",
                             env={"LC_ALL":"C"},pass_fds=(f.fileno(),),capture_output=True)
            self.assertNotEqual(p.returncode,0)
    def test_credential_environment_is_rejected(self):
        p=subprocess.run([sys.executable,"-I","-S","-B",str(KIT/"checker.py")],input=ck.BASE,cwd="/",
                         env={"FREEDOM_SYNTHETIC":"x"},capture_output=True)
        self.assertNotEqual(p.returncode,0)
def invalid_proposal(s):
    def test(self):
        with self.assertRaises((ValueError,RecursionError)): ck.render(s)
    return test
for name,value in {"numbers":"[0]","object":'{"program":["x"]}',"dupe":'{"x":1,"x":2}',"unicode":'["χ"]',
    "path":'["../tests.json"]',"command":'["sh"]',"import":'["import"]',"nested":'[["x"]]',"bool":"[true]",
    "null":"null","stack":'["max"]',"leftover":'["x","d"]',"empty":"[]","markdown":"not JSON","long":" "*257,
    "too_many":json.dumps(["x"]*32),"newline":'["x"]\n'}.items():
    setattr(Grammar,"test_reject_proposal_"+name,invalid_proposal(value))
def invalid_source(s):
    def test(self):
        with self.assertRaises((ValueError,SyntaxError,UnicodeError)): ck.verify(ck.HEADER+s+b"\n")
    return test
for name,value in {"attribute":b"x.real","index":b"x[0]","helper":b"abs(x)","exp":b"x**d","loop":b"[x for x in d]",
    "append":b"x\npass","constant":b"False","keyword":b"min(x, cap=0)","spelling":b"(x)",
    "comment":b"x #","highbit":bytes([0xe1]),"size":b"x"*481}.items():
    setattr(Grammar,"test_reject_source_"+name,invalid_source(value))

class Mission(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=lab.disposable());self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.tid=lab.TID
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.fd=self.stack.enter_context(fs.root(self.base));self.task=fs.wire(w.envelope(self.tid))
        w.seed(self.fd,self.tid,self.task);self.j=self.stack.enter_context(fs.locked(self.fd,self.tid))
        self.d=self.base/self.tid;self.src=self.d/"work/adjust.py";self.tests=self.d/"work/tests.json"
    def grant(self,live=False):
        with contextlib.redirect_stdout(io.StringIO()): lab.fixture_approval(self.j,self.tid,live)
    def ready(self,answer=lab.GOOD):
        self.grant();lab.answer(self.j,self.tid,answer)
    def report(self):
        raw=w.run(self.j,self.tid);return None if raw is None else fs.decode(raw)["report"]
    def test_no_grant(self):
        with self.assertRaises(FileNotFoundError): self.report()
        self.assertFalse((self.d/"claim").exists())
    def test_no_tty_production(self):
        with self.assertRaises(fs.Stop),mock.patch.object(sys.stdin,"isatty",return_value=False):
            w.approve(self.j,self.tid,"live-bridge",lambda _:"APPROVE "+self.tid)
        self.assertFalse((self.d/"grant").exists())
    def test_review_decline(self):
        with self.assertRaises(fs.Stop),contextlib.redirect_stdout(io.StringIO()):
            w.approve(self.j,self.tid,"offline-fixture",lambda _:"DECLINE")
        self.assertFalse((self.d/"grant").exists())
    def test_scope_changes_during_review(self):
        def drift(_):
            self.src.write_bytes(b"changed");return "APPROVE "+self.tid
        with self.assertRaises(fs.Stop),contextlib.redirect_stdout(io.StringIO()):
            w.approve(self.j,self.tid,"offline-fixture",drift)
        self.assertFalse((self.d/"grant").exists())
    def test_wait_for_answer(self):
        self.grant();self.assertIsNone(self.report());self.assertFalse((self.d/"claim").exists())
    def test_pass_actual_bytes(self):
        self.ready();r=self.report();self.assertEqual(r["status"],"PASS");self.assertEqual(r["before"],w.BASELINE)
        self.assertEqual(r["after"],w.WIN);self.assertEqual(r["after_sha256"],fs.sha(self.src.read_bytes()))
        self.assertEqual(self.tests.read_bytes(),ck.VECTORS)
        with mock.patch.object(w,"verify",side_effect=AssertionError("unexpected replay")):
            self.assertEqual(self.report(),r)
    def test_bad_code_fail_preserves_inode(self):
        self.ready('["x"]');old=self.src.stat().st_ino
        self.assertEqual(self.report()["status"],"FAIL");self.assertEqual(self.src.stat().st_ino,old)
    def test_outside_grammar_abstains(self):
        self.ready('["shell"]');self.assertEqual(self.report()["status"],"ABSTAIN");self.assertEqual(self.src.read_bytes(),ck.BASE)
    def test_receipt_task_binding(self):
        self.grant();lab.answer(self.j,self.tid,source_sha256="a"*64)
        self.assertEqual(self.report()["status"],"ABSTAIN");self.assertFalse((self.d/"claim").exists())
    def test_inference_unknown(self):
        self.grant();lab.answer(self.j,self.tid,status="outcome_unknown");self.assertEqual(self.report()["status"],"OUTCOME_UNKNOWN")
    def test_changed_task(self):
        self.ready();(self.d/"task.json").write_bytes(self.task+b" ");self.assertEqual(self.report()["status"],"FAIL")
    def test_expired_even_with_answer(self):
        self.ready()
        with mock.patch.object(w.time,"time",return_value=0): self.assertEqual(self.report()["status"],"ABSTAIN")
    def test_changed_source_hash(self):
        self.ready();self.src.write_bytes(self.src.read_bytes()+b" ");self.assertEqual(self.report()["status"],"FAIL")
    def test_extra_project_entry(self):
        self.ready();(self.src.parent/"extra").touch();self.assertEqual(self.report()["status"],"FAIL")
    def test_wrong_private_mode(self):
        self.ready();self.tests.chmod(0o644);self.assertEqual(self.report()["status"],"FAIL")
    def test_same_content_new_inode(self):
        self.ready();tmp=self.d/"swap";tmp.write_bytes(self.src.read_bytes());tmp.chmod(0o600);tmp.replace(self.src)
        self.assertEqual(self.report()["status"],"FAIL")
    def test_workspace_swap(self):
        self.ready();p=self.d/"work";p.rename(self.d/"old");shutil.copytree(self.d/"old",p)
        self.assertEqual(self.report()["status"],"FAIL")
    def test_source_symlink(self):
        self.ready();decoy=self.base/"decoy";self.src.rename(decoy);self.src.symlink_to(decoy)
        self.assertEqual(self.report()["status"],"FAIL");self.assertEqual(decoy.read_bytes(),ck.BASE)
    def test_protected_symlink(self):
        self.ready();decoy=self.base/"decoy";self.tests.rename(decoy);self.tests.symlink_to(decoy)
        self.assertEqual(self.report()["status"],"FAIL")
    def hardlink(self,p):
        self.ready();dst=self.base/"alias"
        ln="/system/bin/ln" if Path("/system/bin/ln").exists() else shutil.which("ln")
        r=subprocess.run([ln,str(p),str(dst)],cwd="/",env={"LC_ALL":"C"},capture_output=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr.decode(errors="replace")[:400])
        a=p.stat();b=dst.stat();self.assertEqual((a.st_dev,a.st_ino,a.st_nlink),(b.st_dev,b.st_ino,2))
        self.assertEqual(b.st_nlink,2);self.assertEqual(self.report()["status"],"FAIL")
        self.assertFalse((self.d/"claim").exists())
    def test_hardlink_source(self): self.hardlink(self.src)
    def test_hardlink_protected(self): self.hardlink(self.tests)
    def test_fifo(self):
        self.ready();self.src.unlink();os.mkfifo(self.src,0o600);self.assertEqual(self.report()["status"],"FAIL")
    def test_dirty_stage(self):
        self.ready();(self.src.parent/".candidate").write_bytes(b"stale")
        self.assertEqual(self.report()["status"],"FAIL")
    def test_duplicate_and_traversal_ids(self):
        for tid in ("../x","/tmp/x","freedom-v10-c-a/bcdefgh","freedom-v10-c-abc"):
            with self.assertRaises(fs.Stop): w.envelope(tid)
        with self.assertRaises(FileExistsError): w.seed(self.fd,self.tid,self.task)
    def test_flock_excludes_concurrent_worker(self):
        with self.assertRaises(BlockingIOError):
            with fs.locked(self.fd,self.tid): pass
    def test_bad_seal_never_replays(self):
        self.ready();self.report();p=self.d/"sealed.json";p.write_bytes(p.read_bytes().replace(b"PASS",b"FAIL"))
        with self.assertRaises(fs.Stop),mock.patch.object(w,"verify",side_effect=AssertionError("replay")): self.report()
    def test_changed_after_commit(self):
        self.ready()
        def fault(stage):
            if stage=="edit": self.src.write_bytes(ck.BASE)
        result=fs.decode(w.run(self.j,self.tid,fault))["report"]
        self.assertEqual(result["status"],"OUTCOME_UNKNOWN");self.assertEqual(self.report(),result)
    def test_checker_failure_after_commit(self):
        self.ready()
        with mock.patch.object(w,"verify",side_effect=[w.BASELINE,w.WIN,fs.Stop("lost verifier")]):
            self.assertEqual(self.report()["status"],"OUTCOME_UNKNOWN")
    def test_directory_anchor_symlink(self):
        target=self.base/"other";target.symlink_to(self.d,target_is_directory=True)
        with self.assertRaises(OSError):
            with fs.root(target):pass
    def crash(self,stage):
        self.ready()
        # Release the fixture lock. The process to be killed acquires its own lock.
        fcntl.flock(self.j,fcntl.LOCK_UN)
        r=subprocess.run([sys.executable,"-I","-S","-B",str(KIT/"test_finish.py"),"crash",str(self.base),stage],
                         env={"LC_ALL":"C"},cwd="/",capture_output=True,timeout=10)
        self.assertEqual(r.returncode,-signal.SIGKILL,r.stderr)
        fcntl.flock(self.j,fcntl.LOCK_EX|fcntl.LOCK_NB)
        expected=ck.render(lab.GOOD) if stage in ("edit","verified","seal") else ck.BASE
        self.assertEqual(self.src.read_bytes(),expected);inode=self.src.stat().st_ino
        with mock.patch.object(w,"verify",side_effect=AssertionError("replayed verifier")):
            first=self.report();self.assertEqual(self.report(),first)
        self.assertEqual(first["status"],"PASS" if stage=="seal" else "OUTCOME_UNKNOWN")
        self.assertEqual(self.src.stat().st_ino,inode)
    def bridge(self):
        self.grant(True);self.box=lab.Mailbox(self.base,self.tid)
        return self.box
    def tick(self):
        return phone.tick(self.j,self.tid,self.box.b,"fixture-mailbox",evidence_mode="bridge-fixture")
    def test_bridge_full_workflow(self):
        b=self.bridge();r=self.tick()
        self.assertEqual(fs.decode(r)["report"]["status"],"PASS");self.assertEqual(b.objects[b.outbox],r)
        self.assertEqual(self.tick(),r);self.assertEqual((b.posts,b.puts),(1,1));self.assertEqual(b.b.attempts_today(),1)
    def test_no_standalone_edit_for_fixture(self):
        b=self.bridge()
        with self.assertRaises(fs.Stop):phone.tick(self.j,self.tid,b.b,"fixture")
        self.assertEqual(b.posts,0)
    def test_battery_and_quota(self):
        b=self.bridge();b.battery=False;self.assertIsNone(self.tick());b.battery=True
        b.b.attempts_today=lambda:3
        self.assertIsNone(self.tick());self.assertEqual(b.posts,0);self.assertFalse((self.d/"claim").exists())
    def test_free_eligibility(self):
        b=self.bridge();b.free=False;self.assertIsNone(self.tick());b.free=True;b.paid=True
        self.assertIsNone(self.tick());self.assertEqual(b.posts,0)
    def test_changed_mailbox_source(self):
        b=self.bridge();b.objects[b.inbox]+=b" "
        self.assertEqual(fs.decode(self.tick())["report"]["status"],"ABSTAIN");self.assertEqual(b.posts,0)
    def test_changed_before_edit(self):
        b=self.bridge();orig=b.transport
        def swapped(url,*args,**kw):
            value=orig(url,*args,**kw)
            if url.endswith("/chat/completions"): b.objects[b.inbox]+=b" "
            return value
        b.b.request_json=swapped
        self.assertEqual(fs.decode(self.tick())["report"]["status"],"ABSTAIN");self.assertEqual(self.src.read_bytes(),ck.BASE)
    def test_crashed_inference_consumes_once(self):
        b=self.bridge();b.crash_inference=True
        with self.assertRaises(KeyboardInterrupt):self.tick()
        self.assertEqual(fs.decode(self.tick())["report"]["status"],"OUTCOME_UNKNOWN");self.assertEqual(b.posts,1)
    def test_expired_uncertain_inference_preserved(self):
        b=self.bridge();b.crash_inference=True
        with self.assertRaises(KeyboardInterrupt):self.tick()
        with mock.patch.object(w.time,"time",return_value=0):
            self.assertEqual(fs.decode(self.tick())["report"]["status"],"OUTCOME_UNKNOWN")
        self.assertEqual(b.posts,1);self.assertEqual(self.src.read_bytes(),ck.BASE)
    def test_dirfd_listing_portable_branch(self):
        with mock.patch.object(os,"supports_fd",set()):
            self.ready();self.assertEqual(self.report()["status"],"PASS")
    def test_prior_v1_grant_collision(self):
        b=self.bridge();b.b.claim_once(b.b.grant_path(self.tid),b"{}")
        with self.assertRaises(fs.Stop):self.tick()
        self.assertEqual(b.posts,0)
    def test_ambiguous_put_readback(self):
        b=self.bridge();b.ambiguous=True;self.assertEqual(self.tick(),b.objects[b.outbox])
        self.tick();self.assertEqual((b.puts,b.posts),(1,1))
    def test_upload_outage_resends_seal(self):
        b=self.bridge();b.down=True
        with self.assertRaises(fs.Stop):self.tick()
        seal=(self.d/"sealed.json").read_bytes();inode=self.src.stat().st_ino;b.down=False
        with mock.patch.object(w,"verify",side_effect=AssertionError("edit replay")):self.assertEqual(self.tick(),seal)
        self.assertEqual((self.src.stat().st_ino,b.posts),(inode,1))
    def test_resend_without_workspace_answer_or_inbox(self):
        b=self.bridge();b.down=True
        with self.assertRaises(fs.Stop):self.tick()
        sealed=(self.d/"sealed.json").read_bytes()
        shutil.rmtree(self.src.parent);(self.d/"answer.json").unlink();del b.objects[b.inbox];b.down=False
        with mock.patch.object(w,"verify",side_effect=AssertionError("reexecution")):
            self.assertEqual(self.tick(),sealed)
        self.assertEqual(b.posts,1)
    def test_low_battery_defers_sealed_report_only(self):
        b=self.bridge();b.down=True
        with self.assertRaises(fs.Stop):self.tick()
        saved=(self.d/"sealed.json").read_bytes();puts=b.puts;b.down=False;b.battery=False
        self.assertEqual(self.tick(),saved);self.assertEqual(b.puts,puts)
        b.battery=True;self.assertEqual(self.tick(),saved);self.assertEqual(b.posts,1)
    def test_conflicting_outbox_preserved(self):
        b=self.bridge();b.objects[b.outbox]=b"other"
        with self.assertRaises(fs.Stop):self.tick()
        self.assertEqual(b.objects[b.outbox],b"other");self.assertEqual(b.puts,0)
def interrupt_test(stage):
    def test(self): self.crash(stage)
    return test
for k in ("claim","stage","edit","verified","seal"):setattr(Mission,"test_sigkill_"+k,interrupt_test(k))

if __name__=="__main__":
    os.umask(0o077);lab.disposable()
    if len(sys.argv)==4 and sys.argv[1]=="crash":
        base=Path(sys.argv[2]);stage=sys.argv[3]
        with fs.root(base) as fd,fs.locked(fd,lab.TID) as j:
            w.run(j,lab.TID,lambda point:os.kill(os.getpid(),signal.SIGKILL) if point==stage else None)
        raise SystemExit(3)
    unittest.main(verbosity=2)
