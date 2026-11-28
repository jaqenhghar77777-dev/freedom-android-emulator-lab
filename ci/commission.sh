#!/usr/bin/env bash
# Disposable x86-64 API 35 emulator only. Keep independent checks running when Stage B fails.
set -euo pipefail
[[ "$GITHUB_ACTIONS" == true ]]
[[ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" == 1 ]]
bash ci/stage_a.sh
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
set +e
bash ci/stage_b.sh 2>&1 | tee "$out/stage-b.log"
b=${PIPESTATUS[0]}
set -e
adb logcat -b all -d 2>/dev/null | grep -E 'avc: *denied.*\{ *link *\}.*(freedom-b-|name="file"|errno-fixture)' | tail -5 || :
p=/data/data/com.termux/files/usr
h=/data/data/com.termux/files/home
d=$h/freedom-finish-lab
run="run-as com.termux $p/bin/env -i HOME=$h PREFIX=$p TMPDIR=$p/tmp PATH=$p/bin:/system/bin LANG=C.UTF-8"
adb shell "run-as com.termux /system/bin/sh -c 'umask 077 && mkdir $d && mkdir $d/ci'"
for f in custody.py checker.py worker.py phone.py scheduled.sh lab.py test_finish.py commission.py ci/bridge_v10_reference.py ci/reboot_probe.py ci/observe.py; do
  adb shell -T "run-as com.termux /system/bin/sh -c 'umask 077 && cat > $d/$f'" < "$f"
done
n=0
adb shell "$run $p/bin/python -I -S -B $d/test_finish.py" || n=$?
if [[ "$b" != 0 ]]; then
  echo "Original Stage B failed (rc=$b); no Android clearance."
  exit "$b"
fi
[[ "$n" == 0 ]]
grep -E '^(FREEDOM_ALIAS_DIAGNOSTIC |STAGE_B_PASS: )' "$out/stage-b.log" | tr -d '\r' > "$out/alias.txt"
adb shell -T "run-as com.termux /system/bin/sh -c 'umask 077 && cat > $d/stage-b-evidence.txt'" < "$out/alias.txt"
adb shell "$run $p/bin/bash -c 'apt-get install -y strace'"
adb shell "$run $p/bin/python -I -S -B $d/ci/reboot_probe.py prepare"
# adb reboot is restricted to the identified disposable CI emulator, with no root or policy changes.
[[ "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" == 1 ]]
adb reboot
adb wait-for-device
for i in $(seq 1 90); do
  [[ "$(adb shell getprop sys.boot_completed | tr -d '\r')" == 1 ]] && break
  sleep 2
done
[[ "$(adb shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]
adb shell "$run $p/bin/python -I -S -B $d/ci/reboot_probe.py after"
adb shell "$run $p/bin/python -I -S -B $d/commission.py"
