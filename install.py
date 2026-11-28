"""Later release installation by local operator using independently pinned emulator attestations."""
import os
from pathlib import Path
import re
import sys
KIT=Path(__file__).resolve().parent
sys.path.insert(0,str(KIT))
import commission as c
import custody as fs
import phone
import worker as w

def read_attestation(path,pin):
    fs.need(re.fullmatch("[0-9a-f]{64}",pin),"invalid_external_pin")
    fd=os.open(path,fs.READ)
    with os.fdopen(fd,"rb") as f:
        import stat
        info=os.fstat(fd)
        fs.need(stat.S_ISREG(info.st_mode) and info.st_size<=8192 and info.st_nlink==1,"invalid_attestation_file")
        raw=f.read(8193)
    fs.need(fs.sha(raw)==pin,"attestation_pin_mismatch")
    a=fs.decode(raw)
    fs.need(a["schema"]==1 and a["policy"]==w.POLICY and a["build"]==w.build() and a["suite"]==c.tests_digest()
            and a["identity"]["emulator"] is True and a["hardlink_source_and_tests"] is True and
            a["fixture_transport"] is True and type(a["tests_passed"]) is int and a["tests_passed"]==c.REQUIRED_TESTS and
            all(re.fullmatch("[0-9a-f]{64}",a[k]) for k in ("demo_seal_sha256","suite_stdout_stderr_sha256")),
            "incompatible_attestation")
    trace=a["independent_trace"];reboot=a["reboot"]
    fs.need(trace["observer"]=="unprivileged-strace" and trace["startup_through_exit"] is True and
            trace["execve"]==1 and trace["network_syscalls"]==0 and trace["unexpected_children"]==0 and
            re.fullmatch("[0-9a-f]{64}",trace["trace_sha256"]) and reboot["build"]==a["build"] and
            reboot["prior_boot"]!=reboot["current_boot"] and reboot["same_seal"] is True and
            reboot["same_inodes_and_hashes"] is True and reboot["partial_outcome"]=="OUTCOME_UNKNOWN",
            "missing_independent_trace_or_reboot")
    return a

def install(args):
    fs.need(len(args)==4 and sys.stdin.isatty() and sys.stdout.isatty() and
            sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,"local_review_required")
    target=c.native_identity()
    x=read_attestation(args[0],args[1]);arm=read_attestation(args[2],args[3])
    fs.need(x["identity"]["abi"]=="x86_64" and x["identity"]["uname"]=="x86_64" and x["identity"]["api"]=="35"
            and x["identity"]["domain"]=="runas_app" and re.fullmatch("[0-9a-f]{64}",x.get("stage_b_log_sha256") or ""),"wrong_x86_evidence")
    fs.need(target["abi"]=="arm64-v8a" and arm["identity"]["abi"]==target["abi"] and
            target["uname"]==arm["identity"]["uname"]=="aarch64" and
            arm["identity"]["api"]==target["api"] and arm["identity"]["domain"]==target["domain"] and
            target["domain"].startswith("untrusted_app"),"matching_disposable_arm_app_evidence_required")
    # Operator checks the x86 Stage B SUCCESS and the origin of both pinned reports independently.
    print("Build",w.build(),"attestation digests",args[1],args[3],"target",target)
    fs.need(input("Type INSTALL REVIEWED SYNTHETIC WORKER after verifying both CI records: ")==
            "INSTALL REVIEWED SYNTHETIC WORKER","declined")
    fs.need(not os.path.lexists(phone.LIVE),"existing_installation_no_overwrite")
    os.umask(0o077)
    with fs.root(phone.HOME) as home:
        fs.mkdir(home,phone.LIVE.name)
        with fs.private_dir(home,phone.LIVE.name) as base:
            fs.mkdir(base,"app")
            with fs.private_dir(base,"app") as app:
                for name in ("worker.py","checker.py","custody.py","phone.py","scheduled.sh"):
                    fs.create_file(app,name,(KIT/name).read_bytes())
                fd=os.open("scheduled.sh",fs.READ,dir_fd=app)
                try: os.fchmod(fd,0o700);os.fsync(fd)
                finally: os.close(fd)
                os.fsync(app)
            fs.atomic_new(base,"release-evidence.json",fs.wire({"x86_sha256":args[1],"arm_sha256":args[3]}))
            domain=Path("/proc/self/attr/current").read_bytes().rstrip(b"\0\n").decode()
            fs.atomic_new(base,"commissioned.json",fs.wire(dict(build=w.build(),abi=os.uname().machine,domain=domain,
                                                                 policy=w.POLICY,approved=True)))
    print("Installed in private Termux storage. Schedule requires a separate one-time local action.")
if __name__=="__main__":
    install(sys.argv[1:])
