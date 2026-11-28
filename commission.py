"""Issue a synthetic commissioning observation on a disposable native Termux emulator."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import checker as ck
import custody as fs
import lab
import phone
import worker as w

REQUIRED_TESTS=91

def tests_digest():
    names=("test_finish.py","lab.py","commission.py","ci/bridge_v10_reference.py","ci/observe.py","ci/reboot_probe.py")
    return fs.sha(fs.wire({name:fs.sha((KIT/name).read_bytes()) for name in names}))

def native_identity():
    prop="/system/bin/getprop"
    def get(name):
        return subprocess.check_output([prop,name],cwd="/",env={},timeout=5,text=True).strip()
    fs.need(os.getuid()!=0 and sys.executable.startswith(str(phone.PREFIX)+"/"),"native_termux_required")
    context=Path("/proc/self/attr/current").read_bytes().rstrip(b"\0\n").decode()
    return dict(abi=get("ro.product.cpu.abi"),api=get("ro.build.version.sdk"),domain=context.split(":")[2],
                emulator=get("ro.kernel.qemu")=="1",uname=os.uname().machine)

def legacy_stage_b(lines):
    fs.need(len(lines)<=16000,"oversized_stage_b_record")
    rows=lines.decode("utf-8").splitlines()
    entries=[json.loads(l.split(" ",1)[1]) for l in rows if l.startswith("FREEDOM_ALIAS_DIAGNOSTIC ")]
    fs.need(len(entries)==1 and entries[0].get("rc")==0 and entries[0].get("nlink")==2 and
            entries[0].get("abi")=="x86_64" and ":runas_app:" in entries[0].get("context","") and
            "STAGE_B_PASS: disposable Android native Python preflight" in rows,
            "positive_stage_b_record_required")
    return fs.sha(lines)

def capture():
    fs.need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,"isolated_python_required")
    lab.disposable();identity=native_identity()
    fs.need(identity["emulator"] and identity["abi"] in ("x86_64","arm64-v8a"),"emulator_required")
    sys.path.insert(0,str(KIT/"ci"))
    import observe,reboot_probe
    observed=observe.observe()
    recovered=reboot_probe.verify()
    historical=None
    if identity["abi"]=="x86_64":
        historical=legacy_stage_b((KIT/"stage-b-evidence.txt").read_bytes())
    # Inherit no key variables. The tests and demo use controlled transports.
    env={"HOME":str(phone.HOME),"PATH":str(phone.PREFIX)+"/bin:/system/bin","LC_ALL":"C"}
    def child(name):
        p=subprocess.run([sys.executable,"-I","-S","-B",str(KIT/name)],cwd="/",env=env,capture_output=True,timeout=240)
        sys.stderr.buffer.write(p.stderr)
        fs.need(p.returncode==0,"failed_"+name)
        return p.stdout,p.stderr
    tests_out,tests_err=child("test_finish.py")
    import re
    passed=re.search(rb"^Ran (\d+) tests? in .*?\n\s*OK\s*$",tests_err,re.M)
    fs.need(passed is not None and int(passed[1])==REQUIRED_TESTS,"missing_or_partial_test_summary")
    for tag in (b"test_hardlink_source",b"test_hardlink_protected",b"test_sigkill_edit",b"test_upload_outage_resends_seal"):
        fs.need(any(tag in line and line.endswith(b" ... ok") for line in tests_err.splitlines()),"missing_required_test")
    stdout,_=child("lab.py")
    # First line is the printed local scope; the remainder is a JSON evidence record.
    demo=json.loads(stdout.split(b"\n",1)[1]);r=demo["report"]["report"]
    fs.need(r["status"]=="PASS" and r["mode"]=="bridge-fixture" and r["after"]==w.WIN
            and demo["saved_and_returned_identical"] is True,"demo_evidence")
    return dict(schema=1,policy=w.POLICY,build=w.build(),suite=tests_digest(),identity=identity,
                stage_b_log_sha256=historical,independent_trace=observed,reboot=recovered,hardlink_source_and_tests=True,tests_passed=int(passed[1]),suite_stdout_stderr_sha256=fs.sha(tests_out+tests_err),
                demo_seal_sha256=demo["seal_sha256"],fixture_transport=True)
if __name__=="__main__":
    print("FREEDOM_COMMISSION "+fs.wire(capture()).decode().rstrip())
