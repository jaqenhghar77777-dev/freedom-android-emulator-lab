#!/usr/bin/env bash
# Stage A only: confirms an Android emulator can boot, installs official Termux
# GitHub debug APK, and tests non-root app identity and bootstrap availability.
# Does not execute FREEDOM, install Python, touch a real device, or use secrets.
set -Eeuo pipefail

# The workflow runs only on GitHub Actions, but this alone does not prove the
# device is disposable; independent emulator identity is checked below.
[[ "${GITHUB_ACTIONS:-}" == "true" ]] || { echo 'SAFE STOP: Not in CI'; exit 20; }
[[ -n "${ANDROID_HOME:-}${ANDROID_SDK_ROOT:-}" ]] || { echo 'SAFE STOP: Android SDK not configured'; exit 21; }

adb wait-for-device
boot=$(adb shell getprop sys.boot_completed | tr -d '\r')
[[ "$boot" == "1" ]] || { echo 'SAFE STOP: Android has not finished booting'; exit 22; }
fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
model=$(adb shell getprop ro.product.model | tr -d '\r')
abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
# Safety gate: only an emulator image should continue.
if [[ "$fingerprint" != *generic* && "$fingerprint" != *sdk_gphone* && "$fingerprint" != *emulator* ]]; then
  echo 'SAFE STOP: Android fingerprint not recognized as emulator'; exit 23
fi
[[ "$abi" == "x86_64" ]] || { echo "SAFE STOP: Unexpected ABI $abi"; exit 24; }
[[ "$(adb shell id -u | tr -d '\r')" != "0" ]] || { echo 'SAFE STOP: ADB unexpectedly root'; exit 25; }
echo "EMULATOR VERIFIED: model=$model abi=$abi"

# Explicit, versioned official Termux debug build; no untrusted mirrors.
# A first live CI run must independently review APK provenance/signature.
release_tag='v0.118.3'
apk_name='termux-app_v0.118.3+github-debug_universal.apk'
apk_url="https://github.com/termux/termux-app/releases/download/${release_tag}/termux-app_v0.118.3%2Bgithub-debug_universal.apk"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
curl --fail --location --silent --show-error --retry 2 --max-time 150 --output "$workdir/$apk_name" "$apk_url"
[[ "$(stat -c '%s' "$workdir/$apk_name")" -gt 1000000 ]] || { echo 'SAFE STOP: APK unusually small'; exit 26; }
echo "TERMUX_APK_SHA256=$(sha256sum "$workdir/$apk_name" | awk '{print $1}')"
adb install "$workdir/$apk_name"

# Debug build is required for run-as to enter the app UID without root.
adb shell 'run-as com.termux id' || { echo 'SAFE STOP: Termux run-as failed'; exit 27; }
adb shell am start -n com.termux/.app.TermuxActivity >/dev/null

# Termux initializes its native bootstrap on first launch. It might not
# initialize automatically in every emulator image; fail closed if not.
ready=0
for i in $(seq 1 60); do
  if adb shell 'run-as com.termux sh -c "test -x files/usr/bin/bash"' >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  echo 'NOT READY: Termux bootstrap did not become available'; exit 28
fi

echo 'STAGE_A_PASS: emulator + non-root Termux debug UID + native bootstrap available'
echo 'NO_CODING_EXECUTED=1 NO_CREDENTIALS_USED=1 ANDROID_GO_GRANTED=0'
