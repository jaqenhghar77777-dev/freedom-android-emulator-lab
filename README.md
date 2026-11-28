# FREEDOM Finish Line – supervised synthetic Python repair

**Host result: restricted GO for a disposable, non-root Linux lab with fixture transport. Android deployment is gated.** This release repairs an actual Python module. The model can compose a new expression. The only mutable project file is a synthetic `work/adjust.py`.

## Run it

Use a fresh disposable Linux workspace with native Python 3.10 or newer and an unprivileged account. The shipped implementation uses the standard library. No API credentials or package installation are needed for these commands.

```sh
sha256sum -c SHA256SUMS
python3 -I -S -B test_finish.py
python3 -I -S -B ci/verify_evidence.py
python3 -I -S -B lab.py
```

The demo makes a new mode-0700 temporary workspace, runs the original Bridge inference code against a controlled model response, repairs the local Python file and returns its seal to a byte-checking mock GitHub mailbox. It then polls the same mission again. Its output identifies the retained directory so you can inspect the actual files. The first line shows the complete authorization. The fixture supplies the confirmation. A separate test drives the real terminal confirmation through a Linux PTY.

| Check executed in this session | Result |
| --- | --- |
| New native worker, checker, custody, intake and Bridge integration tests | 91 passed |
| Release evidence gates | 9 passed |
| Original commissioning package's regression suite | 42 passed |
| Real Linux PTY | One complete review, one confirmation, one durable grant |
| Synthetic adjustment | Supplied examples 2/5 → 5/5. Exhaustive cases 55/405 → 405/405 |
| Linux kill and recovery | SIGKILL after claim, staging, rename, verification and sealing. No second edit |
| Preserved receipt | Exact local and returned bytes match. Recovery also passed after deleting the original workspace, answer and inbox task |
| Independent Linux syscall trace | Host denied PTRACE_TRACEME. See evidence/process-observer.json |
| New Android run / live free-model proposal | Unverified |

The earlier 341 cases belong to the previous counter pilot. The 405 cases here exhaust all combinations of x and d from -4 through 4 and cap from 0 through 4. Fixed training examples also exercise the upper cap 5. The demo proposal was supplied by the fixture. Receipt 010 in the input package is genuine historical model evidence for the earlier choice protocol.

## One approval on the phone

1. An authorized mailbox writer calls `phone.py emit ID "goal label"` to produce the registered task, or calls the supplied `phone.submit(ID, label, bridge, mailbox_credential)` interface to create the exact inbox bytes and read them back. A commissioned phone offers `submit-adjust ID "goal label"` through its launcher. An ID has the prefix `freedom-v10-c-` plus 8–24 lowercase letters or digits. Equal submissions are idempotent. A conflicting inbox entry is preserved. Luna or another free frontend needs a separate, authorized mailbox connection. This release includes the writer interface and a ready-made example.
2. `review-next` on the local terminal displays the human title, actual source, observed failures, full model prompt, sole edit path, protected tests, model, one-hour expiry, build and task fingerprints, and report destination. The local user types one confirmation. The scheduler cannot approve. A remote title labels the request. The registered goal, permitted operations and oracle remain fixed. Other goals require another reviewed policy.
3. The local Python supervisor revalidates the source, inode identities and raw mailbox bytes. It uses the original Bridge's existing battery check, shared three-per-UTC-day quota, free-tier and zero-price checks, provider routing, inference journal and saved result. It acquires the original Bridge lock for that transaction. The exact Nemotron free route may be unavailable or reject the request. An uncertain consumed inference is never repeated.
4. The model receives actual examples of the defect. It returns up to 31 postfix tokens, at most 256 printable ASCII characters. The only values are x, d, cap and zero. The only binary operations are add, sub, min and max. Two different programs pass the suite. The worker renders the proposal into a canonical Python function. A separate isolated CPython process independently validates the AST, reconstructs every source byte and then executes that approved function on primitive integers. It tests the candidate and reopens and retests the committed bytes.
5. A separate recurring sidecar job returns the sealed result to `outbox/ID.json`. The original Bridge's job 31740, executable, grants and `outbox/v10-ID.json` receipts retain their existing behavior. Its shared inference journal does receive the normal claim and receipt of the approved model request. The sidecar checks whether its proposed slot 31741 is in use before registration. Android controls wake timing.

## What the implementation trusts

The production files are `phone.py`, `worker.py`, `checker.py`, `custody.py` and `scheduled.sh`. Only the phone supervisor uses provider and mailbox credentials. Only fixed local Python code handles model data. The checker starts with absolute argv, cwd /, a minimal environment, closed extra FDs, no site initialization, and no bytecode writes. The runtime audit hook rejects new file opens, socket events and process creation during evaluation. Independent startup-through-exit observation is a separate gate.

The filesystem worker uses fixed names under private directory descriptors, exclusive claims, no-follow opens, nonblocking file opens, single-link regular-file checks, ownership and permissions, precise preimages, device/inode checks, fsync and same-directory atomic rename. It rechecks the protected file, workspace identity and exact source across the commit. The portable directory-list fallback resolves only an already-held directory descriptor through procfs and rechecks its identity. Normal execution never needs to create a hard link. Both real positive alias fixtures remain mandatory for release.

A PASS describes exactly one committed module and includes its diff, the fingerprints of the grant, task, input, output, protected tests and model receipt, and the actual checker exit codes and test counts. FAIL describes unsuccessful preconditions or testing. ABSTAIN covers expiry, changed remote task, unsuitable model output or failed inference. OUTCOME_UNKNOWN preserves an uncertain inference or edit. After an unsealed edit claim, restart quarantines the mission and never resumes or rolls it back. For a sealed mission, retry sends the original bytes and checks GitHub readback. A corrupt seal or damaged grant pauses the mission. A partly created job without authorization cannot run. A new attempt requires a new ID and approval.

The Android app UID, operator, private directory hierarchy, fixed release, native runtime and kernel are trusted. Code with that same UID could compromise local state or secrets. The hash seal detects corruption and binds evidence. It does not authenticate against a hostile same-UID process. The model cannot supply a path, command, plugin, import, test, tool argument or arbitrary Python. The OpenCode/PRoot and Landlock experiments remain outside the execution path. This release exposes a small Python expression language, with deterministic local investigation and tests. It does not grant free-form coding or real-project access.

## Android Stage B and release

The public lab still showed exactly three runs when checked. At commit 7bff62eefcb1d3112a5849f38ecc040f52b58d97, Stage B captured ln's stderr but discarded it before raising hardlink_creation_failed. The original errno is absent. The debug process had the runas_app SELinux domain. The cause of the command failure remains unknown. No Samsung test was performed.

| Historical CI result | Link |
| --- | --- |
| Stage A boot, Termux install and non-root bootstrap passed | https://github.com/jaqenhghar77777-dev/freedom-android-emulator-lab/actions/runs/45797867421 |
| Native Python lacked os.link | https://github.com/jaqenhghar77777-dev/freedom-android-emulator-lab/actions/runs/45804793203 |
| /system/bin/ln returned nonzero | https://github.com/jaqenhghar77777-dev/freedom-android-emulator-lab/actions/runs/45813133920 |

The ZIP includes the instrumented original Stage B, pinned Stage A APK and GitHub Actions references, and a ready-to-run CI workflow. Unpack at the root of the existing public emulator lab on branch `freedom-finish-line-lab`. Only that public repository is allowed to run the bundled jobs. The GitHub connector rejected writes with HTTP 403. The attached Linux host had no Android SDK, emulator, adb or KVM. The instrumented Android job was not run in this session.

The diagnostic records the exact ln status and sanitized stderr, the parent and file devices, link count, UID, mode, Python build, ABI and SELinux context. If ln fails, a second ordinary unprivileged link request on a new synthetic filename records libc errno when available. A matching audit denial can help attribute a permission error. The second request cannot clear a failed ln gate. The complete worker tests still run after a Stage B failure, and the workflow remains failed.

**Commissioning requires both** a disposable x86-64 Android 15 run including the historical Stage B gate, and a disposable native ARM64 run matching the eventual target's Android API level and SELinux app domain. Both need the entire worker suite, real hard-link rejection on source and tests, an independent tracer covering checker startup through exit, and a real reboot with inode/hash stability and exact seal replay. A missing observable blocks release. No root privileges, policy changes or production credentials are used by the worker or these probes.

For the ARM64 lab, use the same verified release files in an app-private native Termux directory on a disposable emulator. The test-only observer uses the free Termux strace package. In the actual Termux app context, run `python -I -S -B ci/reboot_probe.py prepare`, reboot that disposable emulator, and run `python -I -S -B commission.py`. The latter verifies the two distinct boot IDs, traces a fixed checker, runs the full suite and emits a FREEDOM_COMMISSION record. An x86 run under adb run-as cannot substitute for this record. Treat unavailable app-domain tracing as a blocked gate. The public lab workflow performs the x86 procedure automatically and records its observations in the job log.

## Later installation

Deployment is unapproved today. After reviewing successful disposable runs, save each canonical JSON line after the FREEDOM_COMMISSION prefix, including its newline. Independently pin the two files' SHA-256 digests from the reviewed records. Verify the release archive separately, then run in the native Termux terminal:

```sh
python -I -S -B install.py x86.json X86_REVIEWED_SHA256 arm.json ARM_REVIEWED_SHA256
```

The installer checks build and suite hashes, observed capabilities, actual ABI, Android API and SELinux domain. It asks for one local installation confirmation and stages private files in a fresh ~/.freedom-finish directory. It refuses to replace an installed release. It never registers a job during installation. Use `~/.freedom-finish/app/scheduled.sh schedule` once to register and `~/.freedom-finish/app/scheduled.sh review-next` for a pending mission. The same launcher defaults to the scheduled reconciliation when invoked without arguments. The human review of the provenance of the detached evidence hashes is a trust assumption.

The first supervised live commissioning mission still needs a genuine new Nemotron program, one recorded model claim, an actual phone-local commit, protected-test verification and a matching remote seal after scheduled delivery. This is also the test of the user's complete goal-to-report experience.

## Source and evidence

The supplied v0.1 handoff, v0.2 supervised workflow, v0.3 commissioning and v0.4 Stage A archives were opened. Their digests are in evidence/source-provenance.json. The pinned Bridge bytes in ci/bridge_v10_reference.py are used for the offline integration tests. Production loads the installed Bridge only after verifying that exact digest. The original finite-repair worker remains available unchanged in the supplied archives. The new file custody code is adapted from its reviewed primitives.

evidence/ contains the real before and after modules, diff, protected vectors, task, grant, permanent claim, model fixture receipt, saved and returned reports, actual logs, historical Android excerpts and the independent-observer failure. ci/verify_evidence.py reopens these files, checks the binding and reruns CPython on the exact copies. The SHA256SUMS manifest covers every shipped file except itself.
