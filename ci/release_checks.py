"""Host-only checks of the deployment evidence reader. Uses only synthetic records."""
import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
kit=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(kit))
import commission as c,install,custody as fs,worker as w
class Release(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)/"r.json"
        self.r=dict(schema=1,policy=w.POLICY,build=w.build(),suite=c.tests_digest(),identity={"emulator":True},
                    hardlink_source_and_tests=True,fixture_transport=True,tests_passed=c.REQUIRED_TESTS,
                    independent_trace=dict(observer="unprivileged-strace",startup_through_exit=True,execve=1,
                    network_syscalls=0,unexpected_children=0,trace_sha256="a"*64),
                    reboot=dict(build=w.build(),prior_boot="before",current_boot="after",same_seal=True,
                                same_inodes_and_hashes=True,partial_outcome="OUTCOME_UNKNOWN"),
                    demo_seal_sha256="a"*64,suite_stdout_stderr_sha256="b"*64)
    def export(self):
        raw=fs.wire(self.r);self.p.write_bytes(raw);return fs.sha(raw)
    def test_good(self):self.assertEqual(install.read_attestation(self.p,self.export()),self.r)
    def test_unpinned(self):
        self.export()
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,"0"*64)
    def test_prior_build(self):
        self.r["build"]="1"*64
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_partial_tests(self):
        self.r["tests_passed"]-=1
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_alias_gate_missing(self):
        self.r["hardlink_source_and_tests"]=False
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_missing_independent_observation(self):
        self.r["independent_trace"]["startup_through_exit"]=False
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_same_boot_does_not_count(self):
        self.r["reboot"]["current_boot"]=self.r["reboot"]["prior_boot"]
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_non_emulator(self):
        self.r["identity"]["emulator"]=False
        with self.assertRaises(fs.Stop):install.read_attestation(self.p,self.export())
    def test_arm_requires_normal_app_domain_before_prompt(self):
        x=dict(self.r,identity=dict(emulator=True,uname="x86_64",abi="x86_64",api="35",domain="runas_app"),stage_b_log_sha256="0"*64)
        a=dict(self.r,identity=dict(emulator=True,uname="aarch64",abi="arm64-v8a",api="37",domain="runas_app"))
        with mock.patch.object(sys.stdin,"isatty",return_value=True),mock.patch.object(sys.stdout,"isatty",return_value=True),mock.patch.object(c,"native_identity",return_value=a["identity"]),mock.patch.object(install,"read_attestation",side_effect=[x,a]),mock.patch("builtins.input",side_effect=AssertionError("approval reached")),self.assertRaises(fs.Stop):
            install.install(["x","pin","a","pin"])
if __name__=="__main__":unittest.main(verbosity=2)
