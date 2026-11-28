#!/usr/bin/env python3
"""FREEDOM Bridge v1.0 (Termux): single scheduled, tool-free GitHub worker.

Remote JSON is always DATA, not code or authorization. Only phone-local SHA256-bound
approvals permit work. No OpenCode, plugins, DSHBox, remote shell, or project files.
Never rerun a claimed task; recover only previously saved receipts.
"""
import argparse
import base64
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPO = "jaqenhghar77777-dev/freedom-bridge-inbox"
API_REPO = "https://api.github.com/repos/" + REPO + "/contents/"
OR_API = "https://openrouter.ai/api/v1"
MODEL = "nvidia/nemotron-3.5-lightning:free"
BASE = Path.home() / ".local" / "share" / "freedom-bridge-v10"
CODE_DIR = BASE / "app"
STATE = BASE / "state"
GRANTS = STATE / "grants"
JOURNALS = STATE / "journal"
RECEIPTS = STATE / "receipts"
UPLOADED = STATE / "uploaded"
LOCK = STATE / ".lock"
GH_KEY = BASE / "mailbox.token"
OR_KEY = Path.home() / ".config" / "freedom-bridge" / "openrouter.key"
IDENTITY = re.compile(r"^freedom-v10-[a-z0-9-]{4,48}$")
MAX_TASK = 4096
MAX_INBOX = 128
DAILY_CAP = 3
JOB_ID = 31740
PERIOD_MS = 1800000

class Stop(Exception):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc_day():
    return datetime.now(timezone.utc).date().isoformat()


def secure_dir(p):
    if p.is_symlink():
        raise Stop("Unsafe symlink directory")
    p.mkdir(parents=True, mode=0o700, exist_ok=True)
    m = p.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o077:
        raise Stop("Unsafe directory owner/permissions: " + p.name)


def setup_dirs():
    os.umask(0o077)
    for p in (BASE, CODE_DIR, STATE, GRANTS, JOURNALS, RECEIPTS, UPLOADED):
        secure_dir(p)


def read_file(path, maxbytes=10000):
    if path.is_symlink():
        raise Stop("Unsafe symlink: " + path.name)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != os.getuid() or (m.st_mode & 0o077):
            raise Stop("Unsafe file permissions: " + path.name)
        raw = f.read(maxbytes + 1)
    if len(raw) > maxbytes:
        raise Stop("Local file oversized")
    return raw


def atomic_save(path, raw, overwrite=False):
    if path.is_symlink():
        raise Stop("Unsafe output symlink")
    if path.exists() and not overwrite:
        raise Stop("Existing state must not be overwritten")
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        if not overwrite and path.exists():
            raise Stop("State already exists")
        os.replace(name, path)
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def claim_once(path, raw):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Stop("Already claimed: never replay this task") from None
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def json_local(path):
    try:
        return json.loads(read_file(path))
    except (ValueError, UnicodeError) as e:
        raise Stop("Invalid local state: " + path.name) from e


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Stop("Duplicate JSON field rejected")
        out[k] = v
    return out


def validate(raw, source_name):
    if len(raw) > MAX_TASK:
        raise Stop("Task oversized")
    try:
        d = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as e:
        raise Stop("Invalid task JSON") from e
    if not isinstance(d, dict):
        raise Stop("Expected JSON object")
    base = {"schema_version", "task_id", "title", "kind", "execution_authorized", "allow_shell_commands", "allow_file_edits", "allow_project_access"}
    if not base.issubset(d) or type(d["schema_version"]) is not int or d["schema_version"] != 1:
        raise Stop("Unsupported task schema")
    tid = d["task_id"]
    if not isinstance(tid, str) or not IDENTITY.fullmatch(tid) or source_name != tid + ".json":
        raise Stop("Task filename/id mismatch")
    if (not isinstance(d["title"], str) or not 1 <= len(d["title"]) <= 120 or
        any(ord(c) < 32 for c in d["title"])):
        raise Stop("Invalid title")
    for k in ("execution_authorized", "allow_shell_commands", "allow_file_edits", "allow_project_access"):
        if d[k] is not False:
            raise Stop("Remote execution permission rejected")
    if d["kind"] == "fixed_add_two_integers_v1":
        if set(d) != base | {"payload", "expected_result", "data_processing_authorized", "allow_model_inference"}:
            raise Stop("Unexpected arithmetic task fields")
        if d["data_processing_authorized"] is not True or d["allow_model_inference"] is not False:
            raise Stop("Invalid arithmetic flags")
        payload = d["payload"]
        if not isinstance(payload, dict) or set(payload) != {"numbers"}:
            raise Stop("Invalid arithmetic payload")
        nums = payload["numbers"]
        if not isinstance(nums, list) or len(nums) != 2 or any(type(v) is not int or abs(v) > 1000 for v in nums):
            raise Stop("Only two bounded integers allowed")
        if type(d["expected_result"]) is not int or abs(d["expected_result"]) > 2000:
            raise Stop("Invalid expected result")
    elif d["kind"] == "bounded_ai_answer_v1":
        if set(d) != base | {"model", "prompt", "model_inference_authorized"}:
            raise Stop("Unexpected AI task fields")
        if d["model"] != MODEL or d["model_inference_authorized"] is not True:
            raise Stop("Only the exact free model permitted")
        if not isinstance(d["prompt"], str) or not (1 <= len(d["prompt"]) <= 500) or any(ord(c) < 32 and c not in "\n\t" for c in d["prompt"]):
            raise Stop("Invalid prompt")
    else:
        raise Stop("Task operation not allowlisted")
    return d


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request_json(url, bearer, method="GET", payload=None, maxbytes=200000, timeout=25):
    if not url.startswith((API_REPO, OR_API + "/")):
        raise Stop("Unapproved network destination")
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/vnd.github+json" if url.startswith(API_REPO) else "application/json", "User-Agent": "freedom-v10-tool-free", "Content-Type": "application/json"}
    try:
        with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=timeout) as res:
            body = res.read(maxbytes+1)
            if len(body) > maxbytes:
                raise Stop("Network response too large")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise Stop("API HTTP " + str(e.code)) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise Stop("API access or JSON failed") from e


def read_token(path, prefix=None):
    raw = read_file(path, 1024).decode("ascii").strip()
    if len(raw) < 20 or len(raw) > 512 or (prefix and not raw.startswith(prefix)):
        raise Stop("Invalid credential format: " + path.name)
    return raw


def get_remote(path, gh):
    if not (path == "inbox" or re.fullmatch(r"(?:inbox|outbox)/freedom-v10-[a-z0-9-]{4,48}\.json|outbox/v10-freedom-v10-[a-z0-9-]{4,48}\.json", path)):
        raise Stop("Disallowed GitHub read path")
    d = request_json(API_REPO + path, gh, maxbytes=1_000_000 if path == "inbox" else 200_000)
    if d is None:
        return None
    if path == "inbox":
        if not isinstance(d, list) or len(d) > MAX_INBOX:
            raise Stop("Inbox listing unavailable or too large")
        return d
    if not isinstance(d, dict) or d.get("encoding") != "base64" or not isinstance(d.get("content"), str):
        raise Stop("Invalid GitHub file envelope")
    try:
        body = base64.b64decode("".join(d["content"].split()), validate=True)
    except (ValueError, base64.binascii.Error):
        raise Stop("Invalid GitHub base64") from None
    if len(body) > 10000:
        raise Stop("Remote file too large")
    return body


def publish(tid, receipt, gh):
    path = "outbox/v10-" + tid + ".json"
    raw = canonical(receipt)
    existing = get_remote(path, gh)
    if existing is not None:
        if existing != raw:
            raise Stop("Conflicting outbox receipt: no overwrite")
        return "already_uploaded"
    # Creating a new remote file is the only GitHub mutation permitted.
    try:
        request_json(API_REPO + path, gh, method="PUT", payload={"message":"Publish FREEDOM v1.0 tool-free receipt", "content":base64.b64encode(raw).decode("ascii")}, maxbytes=200000)
        return "uploaded"
    except Stop:
        # A timed-out PUT could actually have succeeded. Check once and never edit.
        if get_remote(path, gh) == raw:
            return "uploaded_verified_after_ambiguous_error"
        raise


def publish_saved_once(tid, receipt, gh):
    """Upload the exact saved report once; never re-run the underlying task."""
    marker = UPLOADED / (tid + ".json")
    digest = sha(canonical(receipt))
    if marker.exists():
        m = json_local(marker)
        if not isinstance(m, dict) or m.get("receipt_sha256") != digest:
            raise Stop("Uploaded receipt marker mismatch")
        return "already_uploaded_locally"
    result = publish(tid, receipt, gh)
    claim_once(marker, canonical({"task_id":tid,"receipt_sha256":digest}))
    return result


def answer_response(d):
    if not isinstance(d, dict) or "error" in d or not isinstance(d.get("choices"), list) or not d["choices"]:
        return None, {"finish_reason":None}, "invalid_completion"
    c = d["choices"][0]
    c = c if isinstance(c, dict) else {}
    msg = c.get("message")
    answer = msg.get("content") if isinstance(msg, dict) else None
    usage = d.get("usage") if isinstance(d.get("usage"), dict) else {}
    detail = usage.get("completion_tokens_details")
    detail = detail if isinstance(detail, dict) else {}
    valid = lambda v: v if type(v) is int and 0 <= v < 1000000 else None
    diag = {"finish_reason": c.get("finish_reason") if c.get("finish_reason") in ("stop", "length", "error", "content_filter") else "other", "prompt_tokens": valid(usage.get("prompt_tokens")), "completion_tokens": valid(usage.get("completion_tokens")), "reasoning_tokens": valid(detail.get("reasoning_tokens"))}
    if "error" in c or not isinstance(answer, str) or not answer.strip() or c.get("finish_reason") != "stop":
        return None, diag, "empty_or_incomplete_answer"
    return answer.strip()[:1500], diag, None


def zero_prices(prices):
    if not isinstance(prices, dict) or "prompt" not in prices or "completion" not in prices:
        return False
    try:
        nums = [Decimal(str(v)) for v in prices.values()]
        return len(nums) >= 2 and all(v.is_finite() and v == 0 for v in nums)
    except (InvalidOperation, ValueError, TypeError):
        return False


def free_eligible(key_doc, models_doc):
    k = key_doc.get("data") if isinstance(key_doc, dict) else None
    m = models_doc.get("data") if isinstance(models_doc, dict) else None
    if not isinstance(k, dict) or k.get("is_free_tier") is not True or not isinstance(m, list):
        return False
    rem = k.get("free_model_daily_requests")
    if not isinstance(rem, dict) or type(rem.get("remaining")) is not int or rem["remaining"] < 1:
        return False
    model = next((x for x in m if isinstance(x, dict) and x.get("id") == MODEL), None)
    return bool(model and zero_prices(model.get("pricing")))


def battery_ok():
    cmd = shutil.which("termux-battery-status")
    if not cmd:
        return False, "Termux:API battery status unavailable"
    try:
        p = subprocess.run([cmd], capture_output=True, text=True, timeout=8)
        d = json.loads(p.stdout) if p.returncode == 0 else None
        pct = d.get("percentage") if isinstance(d, dict) else None
        status = str(d.get("status", "")).upper() if isinstance(d, dict) else ""
        if type(pct) is not int or not 0 <= pct <= 100:
            return False, "Battery reading unknown"
        if pct < 20 and status not in ("CHARGING", "FULL"):
            return False, "Battery below 20%"
        return True, "Battery threshold passed"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False, "Battery status probe failed"


def attempts_today():
    result = 0
    for p in JOURNALS.glob("*.json"):
        j = json_local(p)
        if not isinstance(j, dict):
            raise Stop("Invalid journal record")
        if j.get("kind") == "bounded_ai_answer_v1" and j.get("utc_day") == utc_day():
            result += 1
    return result


def journal_path(tid):
    if not IDENTITY.fullmatch(tid):
        raise Stop("Invalid task ID")
    return JOURNALS / (tid + ".json")


def receipt_path(tid):
    if not IDENTITY.fullmatch(tid):
        raise Stop("Invalid task ID")
    return RECEIPTS / (tid + ".json")


def grant_path(tid):
    if not IDENTITY.fullmatch(tid):
        raise Stop("Invalid task ID")
    return GRANTS / (tid + ".json")


def task_by_id(tid, gh):
    if not IDENTITY.fullmatch(tid):
        raise Stop("Unrecognized task id")
    raw = get_remote("inbox/" + tid + ".json", gh)
    if raw is None:
        raise Stop("Task missing from private inbox")
    return raw, validate(raw, tid + ".json")


def list_task_ids(gh):
    entries = get_remote("inbox", gh)
    result = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        name = e.get("name")
        if (isinstance(name, str) and name.endswith(".json") and
            IDENTITY.fullmatch(name[:-5]) and e.get("type") == "file" and
            e.get("path") == "inbox/" + name and type(e.get("size")) is int and e["size"] <= MAX_TASK):
            result.append(name[:-5])
    return sorted(result)


def approve(tid):
    require_termux()
    gh = read_token(GH_KEY)
    raw, task = task_by_id(tid, gh)
    h = sha(raw)
    if grant_path(tid).exists() or journal_path(tid).exists():
        raise Stop("Already approved or attempted: no replacement")
    print("\n=== PHONE-LOCAL APPROVAL ===")
    print("Task ID:", tid)
    print("SHA-256:", h)
    print("Title:", task["title"])
    print("Operation:", task["kind"])
    if task["kind"] == "bounded_ai_answer_v1":
        print("Model:", task["model"], "(one free-model call max)")
        print("FULL GOAL:\n" + task["prompt"])
    else:
        print("FULL GOAL: Add", task["payload"]["numbers"], "and compare with", task["expected_result"])
    print("Remote shell/code/files: DISABLED")
    confirmation = input("Type APPROVE " + tid + " to grant this exact SHA: ").strip()
    if confirmation != "APPROVE " + tid:
        raise Stop("Not approved")
    claim_once(grant_path(tid), canonical({"task_id":tid, "source_sha256":h, "kind":task["kind"], "model":task.get("model"), "approved_locally":True}))
    print("APPROVED locally. Any content change invalidates this grant.")


def make_receipt(tid, task, source_sha, status, **details):
    # Only allow known safe fields; never expose credentials or arbitrary raw errors.
    receipt = {"schema_version":1,"task_id":tid,"source_sha256":source_sha,"kind":task["kind"],"status":status,"worker":"freedom-v10-termux-tool-free","remote_shell":False,"project_access":False}
    receipt.update(details)
    return receipt


def save_receipt(tid, receipt):
    # Save the result BEFORE publishing. Never redo inference after an upload error.
    p = receipt_path(tid)
    if p.exists():
        if read_file(p) != canonical(receipt):
            raise Stop("Conflicting saved receipt")
        return
    claim_once(p, canonical(receipt))


def process_task(tid, task, source_hash, or_key):
    if task["kind"] == "fixed_add_two_integers_v1":
        actual = sum(task["payload"]["numbers"])
        return make_receipt(tid, task, source_hash, "passed" if actual == task["expected_result"] else "failed_expected_result", actual_result=actual, expected_result=task["expected_result"], ai_attempted=False)
    report = make_receipt(tid, task, source_hash, "inference_failed", ai_attempted=True)
    try:
        d = request_json(OR_API + "/chat/completions", or_key, method="POST", payload={
            "model": MODEL, "messages": [{"role":"system","content":"Answer concisely in under 100 words; do not claim tools, tests or files."}, {"role":"user","content":task["prompt"]}],
            "max_tokens":900, "reasoning":{"enabled":False}, "provider":{"allow_fallbacks":False}, "stream":False,
        }, maxbytes=100000, timeout=40)
        answer, diag, err = answer_response(d)
        report.update({"status":"answered_unverified" if err is None else "inference_failed", "diagnostics":diag})
        if err is None:
            report["answer"] = answer
        else:
            report["error_class"] = err
    except Stop as e:
        report["error_class"] = str(e)[:70]  # No raw HTTP bodies, no credentials.
    return report


def do_once(allow_unchecked_battery=False):
    setup_dirs()
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise Stop("Unsafe worker lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("SKIP: another worker is active")
            return
        ok, why = battery_ok()
        if not ok and not allow_unchecked_battery:
            print("BATTERY SAFE STOP:", why)
            return
        gh = read_token(GH_KEY)
        # Recover receipts, even if the remote task was deleted. Only a saved
        # receipt may be re-uploaded; an original task is never retried.
        for p in sorted(RECEIPTS.glob("*.json")):
            tid = p.stem
            receipt = json_local(p)
            if not IDENTITY.fullmatch(tid) or not isinstance(receipt, dict) or receipt.get("task_id") != tid:
                raise Stop("Saved receipt corrupt")
            if (UPLOADED / (tid + ".json")).exists():
                marker = json_local(UPLOADED / (tid + ".json"))
                if not isinstance(marker, dict) or marker.get("receipt_sha256") != sha(canonical(receipt)):
                    raise Stop("Uploaded receipt marker mismatch")
                continue
            print("UPLOAD SAVED RECEIPT:", tid, "(no new work)")
            print("GITHUB:", publish_saved_once(tid, receipt, gh))
            return
        # A claim left by a crash is never replayed, including after 429,
        # timeout, or power loss. Publish outcome_unknown instead.
        for p in sorted(JOURNALS.glob("*.json")):
            tid = p.stem
            if receipt_path(tid).exists():
                continue
            j = json_local(p)
            if (not IDENTITY.fullmatch(tid) or not isinstance(j, dict) or
                j.get("task_id") != tid or not isinstance(j.get("source_sha256"), str) or
                j.get("kind") not in ("fixed_add_two_integers_v1", "bounded_ai_answer_v1")):
                raise Stop("Invalid claimed journal")
            report = {"schema_version":1,"task_id":tid,"source_sha256":j["source_sha256"],"kind":j["kind"],
                      "status":"outcome_unknown","worker":"freedom-v10-termux-tool-free",
                      "remote_shell":False,"project_access":False,"ai_attempted":j["kind"] == "bounded_ai_answer_v1"}
            save_receipt(tid, report)
            print("UNKNOWN OUTCOME:", tid, "(zero retry)")
            print("GITHUB:", publish_saved_once(tid, report, gh))
            return
        tids = list_task_ids(gh)
        for tid in tids:
            if not grant_path(tid).exists() or journal_path(tid).exists():
                continue
            g = json_local(grant_path(tid))
            raw, task = task_by_id(tid, gh)
            digest = sha(raw)
            if (not isinstance(g, dict) or g.get("source_sha256") != digest or
                g.get("task_id") != tid or g.get("kind") != task["kind"] or
                g.get("model") != task.get("model") or g.get("approved_locally") is not True):
                print("REJECTED CHANGED TASK:", tid, "(approval invalid)")
                continue
            or_key = None
            if task["kind"] == "bounded_ai_answer_v1":
                if attempts_today() >= DAILY_CAP:
                    print("DAILY CAP: three claims reached; pause until next UTC day")
                    return
                or_key = read_token(OR_KEY, "sk-or-")
                key_doc = request_json(OR_API + "/key", or_key, maxbytes=60000)
                models_doc = request_json(OR_API + "/models", or_key, maxbytes=8000000)
                if not free_eligible(key_doc, models_doc):
                    print("FREE MODEL NOT VERIFIED — no inference")
                    return
            claim_once(journal_path(tid), canonical({"task_id":tid,"source_sha256":digest,
                "kind":task["kind"],"utc_day":utc_day(),"model":task.get("model")}))
            result = process_task(tid, task, digest, or_key)
            save_receipt(tid, result)
            print("RESULT:", tid, result["status"])
            print("GITHUB:", publish_saved_once(tid, result, gh))
            return
        print("IDLE: no new locally approved tasks")
    finally:
        os.close(fd)


def set_mailbox_token():
    require_termux()
    setup_dirs()
    print("Use a GitHub fine-grained PAT, repository: freedom-bridge-inbox ONLY, Contents read/write.")
    print("No tokens will be printed or published. Never reuse a broad personal GitHub token.")
    if input("Type MAILBOX ONLY after selecting that exact repository: ").strip() != "MAILBOX ONLY":
        raise Stop("Token setup cancelled")
    token = getpass.getpass("Paste restricted GitHub token (hidden): ").strip()
    if not (token.startswith("github_pat_") and 25 < len(token) <= 512):
        raise Stop("Expected a fine-grained GitHub PAT")
    if GH_KEY.exists():
        raise Stop("Mailbox token already installed; no overwrite")
    if not isinstance(request_json(API_REPO + "inbox", token), list):
        raise Stop("Token cannot read the mailbox inbox; credential not stored")
    claim_once(GH_KEY, (token+"\n").encode("ascii"))
    print("Mailbox-only credential stored (0600). Scope must still be enforced on GitHub.")


def require_termux():
    prefix = os.environ.get("PREFIX", "")
    if prefix != "/data/data/com.termux/files/usr":
        raise Stop("Run setup/worker only in native Termux (not DSHBox)")


def install():
    require_termux()
    setup_dirs()
    target = CODE_DIR / "bridge.py"
    origin = Path(__file__).resolve()
    content = origin.read_bytes()
    if target.exists():
        if read_file(target, 250000) != content:
            raise Stop("Installed code differs. No automatic upgrades")
        print("ALREADY INSTALLED")
        return
    claim_once(target, content)
    os.chmod(target, 0o700)
    # Scheduler invokes only this local wrapper. It never reads code from GitHub.
    launcher = CODE_DIR / "scheduled.sh"
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    py = Path(prefix)/"bin"/"python3"
    script = "#!/bin/sh\nexec '" + str(py) + "' '" + str(target) + "' --once\n"
    claim_once(launcher, script.encode())
    os.chmod(launcher, 0o700)
    print("INSTALLED:", target)


def schedule(enable):
    require_termux()
    setup_dirs()
    command = shutil.which("termux-job-scheduler")
    if not command:
        raise Stop("Termux:API unavailable. Install compatible Termux:API app + termux-api package first")
    if enable:
        if not GH_KEY.is_file():
            raise Stop("Install mailbox-only credential first")
        launcher = CODE_DIR/"scheduled.sh"
        if not launcher.is_file():
            raise Stop("Install local worker first")
        # Request only; Android may defer during Doze or battery-saving modes.
        args = [command, "--script",str(launcher),"--job-id",str(JOB_ID),"--period-ms",str(PERIOD_MS),"--network","any","--battery-not-low","true","--persisted","true"]
    else:
        args = [command, "--cancel", "--job-id", str(JOB_ID)]
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop("Android scheduler call failed") from None
    if p.returncode:
        raise Stop("Android scheduler rejected the request")
    print("SCHEDULE REQUEST", "SUBMITTED" if enable else "CANCELLED", "— timing not guaranteed by Android")


def status():
    setup_dirs()
    grants = [p.stem for p in GRANTS.glob("*.json")]
    attempted = [p.stem for p in JOURNALS.glob("*.json")]
    reports = [p.stem for p in RECEIPTS.glob("*.json")]
    print("FREEDOM v1.0 status | GitHub credential:", "configured" if GH_KEY.exists() else "NOT CONFIGURED")
    print("Local approvals:", len(grants), "Claims:", len(attempted), "Saved receipts:", len(reports), "Uploaded:",len(list(UPLOADED.glob("*.json"))))
    print("Today's AI claim cap:", attempts_today(), "/", DAILY_CAP)
    print("No generalized agents. No remote execution authority.")


def self_test():
    # Pure offline tests; never touch user's GitHub or API credentials.
    def arithmetic(tid="freedom-v10-pilot-007"):
        return {"schema_version":1,"task_id":tid,"title":"Simple arithmetic pilot","kind":"fixed_add_two_integers_v1","payload":{"numbers":[17,25]},"expected_result":42,"data_processing_authorized":True,"allow_model_inference":False,"execution_authorized":False,"allow_shell_commands":False,"allow_file_edits":False,"allow_project_access":False}
    a = arithmetic(); raw=canonical(a)
    assert validate(raw,a["task_id"]+".json") == a
    try:
        validate(raw.replace(b'"title":', b'"title":"dup","title":'),a["task_id"]+".json");raise AssertionError()
    except Stop:pass
    assert sum(a["payload"]["numbers"])==42
    try: validate(raw,"mismatch.json");raise AssertionError()
    except Stop: pass
    b=dict(a);b["allow_shell_commands"]=True
    try: validate(canonical(b), b["task_id"]+".json");raise AssertionError()
    except Stop: pass
    b=dict(a);b["payload"]={"numbers":[17,2000]}
    try: validate(canonical(b), b["task_id"]+".json");raise AssertionError()
    except Stop: pass
    b=dict(a);b["expected_result"]=41
    assert validate(canonical(b),b["task_id"]+".json")["expected_result"] == 41
    assert sha(raw)!=sha(raw.replace(b'17',b'18',1))
    assert zero_prices({"prompt":"0","completion":"0","request":"0"})
    assert not zero_prices({"prompt":"0.001","completion":"0"})
    assert not zero_prices({"prompt":"0","completion":None})
    kd={"data":{"is_free_tier":True,"free_model_daily_requests":{"remaining":2}}}
    md={"data":[{"id":MODEL,"pricing":{"prompt":"0","completion":"0"}}]}
    assert free_eligible(kd,md)
    assert not free_eligible({"data":{"is_free_tier":False,"free_model_daily_requests":{"remaining":2}}},md)
    assert not free_eligible(kd,{"data":[{"id":MODEL,"pricing":{"prompt":"0.01","completion":"0"}}]})
    ai={"schema_version":1,"task_id":"freedom-v10-ai-008","title":"Small answer","kind":"bounded_ai_answer_v1","model":MODEL,"prompt":"Say hello","model_inference_authorized":True,"execution_authorized":False,"allow_shell_commands":False,"allow_file_edits":False,"allow_project_access":False}
    assert validate(canonical(ai),ai["task_id"]+".json")==ai
    ai["model"]="openai/gpt-4"
    try: validate(canonical(ai),ai["task_id"]+".json");raise AssertionError()
    except Stop: pass
    answer,diag,err=answer_response({"choices":[{"message":{"content":"Safe answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3}})
    assert answer=="Safe answer" and not err and diag["completion_tokens"]==3
    answer,diag,err=answer_response({"choices":[{"message":{"content":""},"finish_reason":"length"}]})
    assert answer is None and err is not None
    # Durable replay semantics in disposable local state.
    with tempfile.TemporaryDirectory(prefix="freedom-v10-test-") as root:
        p=Path(root)/"journal.json"
        claim_once(p,canonical({"status":"claimed"}))
        assert json.loads(p.read_bytes())["status"]=="claimed"
        try: claim_once(p,b"again");raise AssertionError()
        except Stop: pass
        receipt=Path(root)/"receipt.json"
        claim_once(receipt,canonical({"status":"saved","answer":"42"}))
        assert json.loads(receipt.read_bytes())["answer"]=="42"
    print("21/21 OFFLINE ASSERTIONS PASS — no GitHub, AI, or background job")


def main():
    ap=argparse.ArgumentParser(description="FREEDOM v1.0 tool-free scheduled worker")
    options=ap.add_mutually_exclusive_group(required=True)
    for flag in ("--self-test","--status","--set-mailbox-token","--install","--once","--schedule","--unschedule"):
        options.add_argument(flag,action="store_true")
    options.add_argument("--approve",metavar="TASK_ID")
    args=ap.parse_args()
    if args.self_test:
        self_test()
    elif args.status:
        status()
    elif args.set_mailbox_token:
        set_mailbox_token()
    elif args.install:
        install()
    elif args.approve:
        setup_dirs();approve(args.approve)
    elif args.once:
        require_termux()
        do_once()
    elif args.schedule:
        schedule(True)
    elif args.unschedule:
        schedule(False)

if __name__ == "__main__":
    try:
        main()
    except (Stop, OSError, ValueError, RuntimeError) as e:
        print("SAFE STOP:", str(e)[:150])
        sys.exit(1)
