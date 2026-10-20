#!/usr/bin/env bash
# Capture a real Chrome's TLS ClientHello + request headers on macOS.
#
#   Chrome (own --user-data-dir, --proxy-server)        mitmproxy :18080
#        |                                                   |
#        | CDP (--remote-debugging-port)                   | mitm_capture_addon.py
#        v                                                   v
#   cdp_headers.py  ------------------------------>  capture.jsonl (JSON per line)
#
# Why this shape: macOS has no packet-filter path an ordinary user may take
# (no iptables REDIRECT, no pf rules without sudo), and the rootless
# equivalent of the phone's transparent redirect is an *explicit* proxy. The
# proxy is handed to one Chrome launch on the command line, so the system
# proxy settings, the keychain and the user's own Chrome profile are never
# touched -- only a throwaway profile in a temp directory is written.
#
# The mitmproxy CA is NOT installed anywhere. No sudo, no keychain change, no
# "trust this certificate" dialog to click. Chrome is told to ignore
# certificate errors for this one instance (--ignore-certificate-errors) and
# the CDP leg calls Security.setIgnoreCertificateErrors, so an untrusted CA
# is enough. The ClientHello is read before the certificate is presented
# anyway, which is why the hello survives even when the browser refuses the
# proxy certificate outright.
#
# Usage:
#   tools/mac/capture.sh <url> [--out FILE] [--seconds N] [--headless]
#
# Environment:
#   SITE_MIMIC_VENV  where the mitmproxy venv lives
#                    (default ~/.local/share/site-micic/venv; created on first
#                    use -- no sudo, no system-wide install)
#   CHROME           Chrome binary (default: the installed Google Chrome)
#   MITM_PORT        proxy port (default 18080; shifted if the port is busy)
#   CDP_PORT         remote debugging port (default 19222; shifted if busy)
#   HEADLESS         1 -> run Chrome headless (default 0: a real window, so
#                        the captured headers are the headed ones)
#
# Output: one JSONL file. Records carry "source": "mitm" (the proxy leg --
# kind "hello" and kind "http") or "cdp" (the browser leg -- kind "request",
# "response", "finished"). Measure it with:
#
#   go run ./cmd/hellofp <capture.jsonl>
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

VENV="${SITE_MIMIC_VENV:-$HOME/.local/share/site-mimic/venv}"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
MITM_PORT="${MITM_PORT:-18080}"
CDP_PORT="${CDP_PORT:-19222}"
HEADLESS="${HEADLESS:-0}"
WATCH_SECONDS=25
OUT=""

ADDON="$REPO_ROOT/tools/phone/mitm_capture_addon.py"
CDP_TOOL="$REPO_ROOT/tools/phone/cdp_headers.py"

die() { echo "FATAL: $*" >&2; exit 1; }

usage() {
  cat <<EOF
usage: $(basename "$0") <url> [--out FILE] [--seconds N] [--headless]

  <url>            page to load (e.g. https://example.com/)
  --out FILE       capture JSONL (default: $PWD/mac-capture/capture.jsonl)
  --seconds N      how long the CDP leg watches (default: $WATCH_SECONDS)
  --headless       run Chrome headless (changes the UA; the default is a
                   real window)

environment: SITE_MIMIC_VENV, CHROME, MITM_PORT, CDP_PORT, HEADLESS
EOF
}

URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out)     OUT="${2:-}"; shift 2 || true ;;
    --out=*)   OUT="${1#*=}"; shift ;;
    --seconds) WATCH_SECONDS="${2:-}"; shift 2 || true ;;
    --seconds=*) WATCH_SECONDS="${1#*=}"; shift ;;
    --headless) HEADLESS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)        echo "unknown option: $1" >&2; usage; exit 2 ;;
    *)
      if [ -z "$URL" ]; then URL="$1"; shift
      else echo "unexpected argument: $1" >&2; usage; exit 2; fi ;;
  esac
done

URL="${URL:-}"
[ -n "$URL" ] || { echo "FATAL: no URL given" >&2; usage; exit 2; }
case "$URL" in
  http://*|https://*) : ;;
  *) die "the URL must start with http:// or https:// (got '$URL')" ;;
esac

[ -x "$CHROME" ] || die "no Chrome at $CHROME (set CHROME=/path/to/chrome)"
[ -f "$ADDON" ]   || die "missing addon: $ADDON"
[ -f "$CDP_TOOL" ] || die "missing CDP tool: $CDP_TOOL"

OUT="${OUT:-$PWD/mac-capture/capture.jsonl}"
mkdir -p "$(dirname -- "$OUT")"

# --- helpers ---------------------------------------------------------------

# Is a TCP port free on the loopback? Prints a usable port: the preferred one
# if it is free, otherwise one the OS hands out. A capture must not fail
# because somebody left a mitmproxy on 18080.
pick_port() {
  python3 - "$1" <<'PY'
import socket, sys
pref = int(sys.argv[1])
s = socket.socket()
try:
    s.bind(("127.0.0.1", pref))
    print(pref)
except OSError:
    s.close()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
    s.close()
PY
}

# Wait until something accepts a connection on a port.
wait_port() {
  python3 - "$1" "${2:-15}" <<'PY'
import socket, sys, time
port, timeout = int(sys.argv[1]), float(sys.argv[2])
deadline = time.time() + timeout
while time.time() < deadline:
    with socket.socket() as s:
        s.settimeout(0.5)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            sys.exit(0)
    time.sleep(0.2)
sys.exit(1)
PY
}

# Kill a process we started -- by PID, never by pattern. A pattern would also
# match the user's own Chrome and our own command line; the phone README says
# it the same way. Chrome's helper processes are children of the browser
# process, so they are walked down too.
kill_tree() {
  local pid="$1" child
  [ -n "$pid" ] || return 0
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill -TERM "$pid" 2>/dev/null || true
}

kill_tree_hard() {
  local pid="$1" child
  [ -n "$pid" ] || return 0
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree_hard "$child"
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# --- the mitmproxy venv ----------------------------------------------------
# mitmproxy lives in a virtualenv under the user's home. No sudo, no system
# install, nothing added to the repository's go.mod: the capture chain is
# Python and shell.
if [ ! -x "$VENV/bin/mitmdump" ]; then
  echo "== mitmproxy venv =="
  echo "creating $VENV (mitmproxy + websocket-client)"
  python3 -m venv "$VENV" || die "cannot create the venv at $VENV"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip \
    || die "pip upgrade failed -- see the output above"
  "$VENV/bin/python" -m pip install --quiet mitmproxy websocket-client \
    || die "pip install failed -- no network? the venv stays at $VENV"
fi
MITMDUMP="$VENV/bin/mitmdump"
VPY="$VENV/bin/python"

# --- the throwaway Chrome profile -----------------------------------------
# Everything the run writes lives here: the profile, the logs and the raw
# capture. It is a temp directory this script created, and it is removed on
# the way out -- exactly that directory, by explicit path.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/site-mimic-mac.XXXXXX")"
PROFILE_DIR="$WORK_DIR/chrome-profile"
MITM_OUT="$WORK_DIR/mitm.jsonl"
CDP_OUT="$WORK_DIR/cdp.jsonl"
MITM_LOG="$WORK_DIR/mitmdump.log"
CHROME_LOG="$WORK_DIR/chrome.log"
mkdir -p "$PROFILE_DIR"

CHROME_PID=""
MITM_PID=""

stop_chrome() {
  [ -n "$CHROME_PID" ] || return 0
  kill_tree "$CHROME_PID"
  sleep 1
  kill_tree_hard "$CHROME_PID"
  CHROME_PID=""
}

stop_mitm() {
  [ -n "$MITM_PID" ] || return 0
  kill -TERM "$MITM_PID" 2>/dev/null || true
  wait "$MITM_PID" 2>/dev/null || true
  MITM_PID=""
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  stop_chrome || true
  stop_mitm || true
  if [ -d "$WORK_DIR" ]; then
    # Only ever this run's own mktemp directory.
    case "$WORK_DIR" in
      "${TMPDIR:-/tmp}"/site-mimic-mac.*) rm -rf "$WORK_DIR" ;;
      *) echo "WARN: leaving $WORK_DIR alone (not a path this script made)" >&2 ;;
    esac
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

# --- 1. the proxy ----------------------------------------------------------
MITM_PORT="$(pick_port "$MITM_PORT")"
CDP_PORT="$(pick_port "$CDP_PORT")"

echo "== mitmproxy on 127.0.0.1:$MITM_PORT =="
# ssl_insecure      -- the target's own chain may not validate
# connection_strategy=lazy -- do not dial the origin before the client speaks
# block_global=false -- a local receiver (127.0.0.1) is not "global"
"$MITMDUMP" --mode regular --listen-host 127.0.0.1 --listen-port "$MITM_PORT" \
  --set ssl_insecure=true \
  --set connection_strategy=lazy \
  --set block_global=false \
  -s "$ADDON" \
  --set out_jsonl="$MITM_OUT" >"$MITM_LOG" 2>&1 &
MITM_PID=$!

if ! wait_port "$MITM_PORT" 20; then
  echo "FATAL: mitmproxy did not open 127.0.0.1:$MITM_PORT" >&2
  tail -20 "$MITM_LOG" >&2 || true
  exit 1
fi
echo "mitmproxy is up (pid $MITM_PID)"

# --- 2. the dedicated Chrome ----------------------------------------------
# A separate instance with its own profile: the user's Chrome may be running
# with their accounts, and it must not be touched, let alone killed. The
# profile is empty and disposable, the mock keychain keeps Chrome away from
# the login keychain, and the proxy is a flag on this one launch -- the
# system proxy settings stay as they are.
echo "== Chrome (throwaway profile, proxy 127.0.0.1:$MITM_PORT) =="
CHROME_ARGS=(
  --user-data-dir="$PROFILE_DIR"
  --remote-debugging-port="$CDP_PORT"
  --proxy-server="http://127.0.0.1:$MITM_PORT"
  --ignore-certificate-errors
  --disable-quic
  --use-mock-keychain
  --password-store=basic
  --no-first-run
  --no-default-browser-check
  --disable-background-networking
  --disable-component-update
  --disable-sync
  --disable-default-apps
)
# --disable-quic matters: Chrome would otherwise speak HTTP/3 over UDP and
# there would be no TCP ClientHello to capture at all -- the same trap the
# phone path hits with the iptables REJECT rule.
[ "$HEADLESS" = "1" ] && CHROME_ARGS+=(--headless=new)
CHROME_ARGS+=("$URL")

"$CHROME" "${CHROME_ARGS[@]}" >"$CHROME_LOG" 2>&1 &
CHROME_PID=$!
echo "chrome is up (pid $CHROME_PID)"

if ! wait_port "$CDP_PORT" 25; then
  echo "FATAL: Chrome's DevTools port 127.0.0.1:$CDP_PORT did not open" >&2
  tail -20 "$CHROME_LOG" >&2 || true
  exit 1
fi

# --- 3. the headers, from the browser itself ------------------------------
# The proxy leg sees the wire headers; the CDP leg sees what Chrome is about
# to send. CDP reports the browser-added headers only -- Host, Accept,
# Accept-Encoding, Accept-Language, Connection and the sec-fetch-* quartet
# are added by the network stack and are NOT in requestWillBeSent -- so both
# legs are kept and the two are read together.
echo "== CDP header capture (${WATCH_SECONDS}s) =="
if "$VPY" "$CDP_TOOL" --cdp "127.0.0.1:$CDP_PORT" --url "$URL" \
      --out "$CDP_OUT" --seconds "$WATCH_SECONDS"; then
  echo "cdp leg done"
else
  echo "WARN: the CDP leg failed -- the proxy leg still holds the hello" >&2
fi

# --- 4. stop, then merge ---------------------------------------------------
stop_chrome
stop_mitm

echo "== merge =="
python3 - "$MITM_OUT" "$CDP_OUT" "$OUT" <<'PY'
import json
import os
import sys

mitm_path, cdp_path, out_path = sys.argv[1:4]
rows = []
for path, source in ((mitm_path, "mitm"), (cdp_path, "cdp")):
    if not os.path.exists(path):
        continue
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec.setdefault("source", source)
            rows.append(rec)

tmp = out_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    for rec in rows:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
os.replace(tmp, out_path)

counts = {}
for rec in rows:
    k = rec.get("kind", "?")
    counts[k] = counts.get(k, 0) + 1
print("records: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
print("total: %d -> %s" % (len(rows), out_path))
PY

echo "== measure =="
echo "go run ./cmd/hellofp '$OUT'"
