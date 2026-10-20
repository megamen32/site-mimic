#!/usr/bin/env bash
# Capture an Android app's traffic on an emulator, with the app's own
# (decrypted) HTTP flows written to JSONL.
#
# Sequence: install + VERIFY the APK -> mitmdump -> global HTTP proxy on ->
# cold start -> open the target URL -> watch -> stop -> summarize.
#
# The version check is not optional: a capture labelled with one version
# while the emulator still runs another produces a profile of the wrong
# client, and nothing in the artifact says so. Never trust the file name —
# trust `dumpsys package`.
#
# Usage:
#   sh capture.sh
#
# Environment:
#   ADB            adb binary (default: adb)
#   SERIAL         emulator serial
#   PKG            package to capture (default ru.oneme.app)
#   APK            APK to install (optional; skip to keep the installed one)
#   EXPECT_VERSION versionName the installed app must have (skip to disable
#                  the check — but then you are on your own)
#   URL            deep link to open (optional)
#   COMPONENT      activity to start (default: derived from the package)
#   OUT_DIR        output directory (default: ./avd-capture)
#   FLOWS          output JSONL (default: $OUT_DIR/flows.jsonl)
#   MITM_PORT      mitmdump port on the host (default 8888)
#   PROXY          proxy address the emulator uses (default 10.0.2.2, the
#                  emulator's route to the host loopback)
#   WATCH_SECONDS  how long to watch (default 60)
#   IGNORE_HOSTS   regex of hosts to tunnel instead of decrypting
set -euo pipefail

ADB=${ADB:-adb}
SERIAL=${SERIAL:-}
PKG=${PKG:-ru.oneme.app}
APK=${APK:-}
EXPECT_VERSION=${EXPECT_VERSION:-}
URL=${URL:-}
OUT_DIR=${OUT_DIR:-avd-capture}
FLOWS=${FLOWS:-$OUT_DIR/flows.jsonl}
MITM_PORT=${MITM_PORT:-8888}
PROXY=${PROXY:-10.0.2.2}
WATCH_SECONDS=${WATCH_SECONDS:-60}
IGNORE_HOSTS=${IGNORE_HOSTS:-}

if [ -n "$SERIAL" ]; then
  ADB_ARGS=(-s "$SERIAL")
else
  ADB_ARGS=()
fi
adb_() { "$ADB" "${ADB_ARGS[@]}" "$@"; }

mkdir -p "$OUT_DIR"
MITM_LOG=$OUT_DIR/mitmdump.log

echo "=== 0. preconditions ==="
adb_ get-state >/dev/null 2>&1 || { echo "no device: $ADB ${ADB_ARGS[*]:-}"; exit 1; }
adb_ shell settings put global http_proxy :0 >/dev/null 2>&1 || true

if [ -n "$APK" ]; then
  echo "=== 1. install APK ($APK) ==="
  adb_ uninstall "$PKG" >/dev/null 2>&1 || true
  adb_ install -r "$APK" 2>&1 | tail -1
  if [ -n "$EXPECT_VERSION" ]; then
    GOT=$(adb_ shell dumpsys package "$PKG" 2>/dev/null | grep -m1 versionName | sed 's/.*versionName=//' | tr -d '\r ')
    echo "installed versionName: $GOT (expected: $EXPECT_VERSION)"
    case "$GOT" in
      *"$EXPECT_VERSION"*) : ;;
      *) echo "FATAL: version mismatch — capture ABORTED"; exit 2 ;;
    esac
  fi
else
  echo "=== 1. no APK given — using the installed $PKG ==="
  adb_ shell dumpsys package "$PKG" 2>/dev/null | grep -m1 versionName || true
fi

echo "=== 2. mitmdump on :$MITM_PORT ==="
MITM_ARGS=(--listen-host 0.0.0.0 --listen-port "$MITM_PORT"
           --set flow_detail=1 --set ssl_insecure=true
           -s "$(dirname "$0")/../win/addon.py")
if [ -n "$IGNORE_HOSTS" ]; then
  MITM_ARGS+=(--ignore-hosts "$IGNORE_HOSTS")
fi
CAPTURE_FLOWS="$FLOWS" mitmdump "${MITM_ARGS[@]}" >"$MITM_LOG" 2>&1 &
MITM=$!
sleep 4
if ! kill -0 "$MITM" 2>/dev/null; then
  echo "FATAL: mitmdump died — see $MITM_LOG"
  tail -20 "$MITM_LOG"
  exit 1
fi
echo "mitm is up on :$MITM_PORT"

cleanup() {
  adb_ shell settings put global http_proxy :0 >/dev/null 2>&1 || true
  kill "$MITM" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 3. proxy on, cold start ==="
adb_ shell settings put global http_proxy "$PROXY:$MITM_PORT"
adb_ shell am force-stop "$PKG" >/dev/null 2>&1 || true
sleep 1
if [ -n "$COMPONENT" ]; then
  adb_ shell am start -n "$COMPONENT" >/dev/null 2>&1 || true
else
  adb_ shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
fi
sleep 10

if [ -n "$URL" ]; then
  echo "=== 4. open $URL ==="
  adb_ shell am start -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1 || true
  sleep 5
fi

echo "=== 5. watch ${WATCH_SECONDS}s ==="
sleep "$WATCH_SECONDS"

echo "=== 6. stop ==="
adb_ shell am force-stop "$PKG" >/dev/null 2>&1 || true

echo "=== 7. summary ==="
python3 - "$FLOWS" <<'PY'
import collections
import json
import sys

path = sys.argv[1]
try:
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
except FileNotFoundError:
    print("no flows file — the app did not reach the proxy")
    raise SystemExit(0)

hosts = collections.Counter(r.get("host", "") for r in rows)
uas = collections.Counter()
for r in rows:
    for k, v in (r.get("request_headers") or []):
        if k.lower() == "user-agent":
            uas[v] += 1
            break

print(f"{len(rows)} flows")
print("top hosts:")
for h, c in hosts.most_common(15):
    print(f"  {c:4} {h}")
if uas:
    print("user agents:")
    for ua, c in uas.most_common(4):
        print(f"  x{c} {ua}")
PY
echo "flows: $FLOWS"
echo "mitm log: $MITM_LOG"
