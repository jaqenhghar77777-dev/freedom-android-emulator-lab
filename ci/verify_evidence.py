"""Independently reopen the shipped records and execute the shipped before/after bytes."""
import sys
from pathlib import Path
kit=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(kit))
import checker, custody as fs, worker

def check():
    e=kit/"evidence"
    raw=(e/"sealed.json").read_bytes();obj=fs.decode(raw);r=obj["report"]
    assert raw==fs.wire(obj)==(e/"returned.json").read_bytes()
    assert fs.sha(fs.wire(r))==obj["report_sha256"]
    before=(e/"before/adjust.py").read_bytes();after=(e/"after/adjust.py").read_bytes()
    pairs=[("task.json","task_sha256"),("grant.json","grant_sha256"),("protected-tests.json","protected_sha256"),
           ("model-receipt-fixture.json","answer_receipt_sha256")]
    for name,key in pairs: assert fs.sha((e/name).read_bytes())==r[key]
    assert (e/"protected-tests.json").read_bytes()==checker.VECTORS
    assert r["mode"]=="bridge-fixture" and r["status"]=="PASS" and r["changed"]==["work/adjust.py"]
    assert before==checker.BASE and fs.sha(before)==r["before_sha256"]
    assert after==checker.render(r["proposal"]) and fs.sha(after)==r["after_sha256"]
    assert r["before"]==worker.verify(before)==worker.BASELINE
    assert r["after"]==worker.verify(after)==worker.WIN
    assert r["diff"]==worker.diff(before,after)==(e/"repair.diff").read_text()
    assert fs.decode((e/"grant.json").read_bytes())["scope"]["build_sha256"]==worker.build()
    print("PASS actual Python bytes, task, grant, response and test hashes, report seal, returned bytes and diff")
    print("Before",r["before"],"after",r["after"])
    print("SHA-256 of exact returned envelope",fs.sha(raw))
if __name__=="__main__":check()
