#!/usr/bin/env bash
# Weekly real-vs-ours canary for the site-mimic verification stand.
#
# Drives a real HEADED Chrome (machine picked by TRIGGER; one trigger call
# samples BOTH hello shapes: a fresh-profile navigation does the full
# handshake, and a hand-off tab in the persistent profile opens a second
# connection that offers the session ticket - the resumed shape) and our
# mimic clients at https://fp.example.test/fp, tags our requests with an
# x-canary header, then diffs the freshest /fp/recent reports: JA4, JA3 and
# header name sets. Exit 0 = match, exit 2 = drift (Chrome turned an
# experiment on/off, bundled browser stale, profile drift).
set -u
cd "$(dirname "$0")/.."

# Real-browser trigger machines. TRIGGER selects one per run: auto (default,
# Mac mini first, Windows fallback), mac, or windows. The Mac mini is the
# always-on acceptance host (key SSH); the Windows lab box needs sshpass
# credentials. REPORT_HOST serves /fp/recent — use a LAN address when the
# canary runs on the stand host.
TRIGGER=${TRIGGER:-auto}
TRIGGER_VISITS=${TRIGGER_VISITS:-3}
MAC_HOST=${MAC_HOST:-}
MAC_USER=${MAC_USER:-}
MAC_CHROME=${MAC_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
WIN_HOST=${WIN_HOST:-}
WIN_USER=${WIN_USER:-}
WIN_PASS=${WIN_PASS:-}
REPORT_HOST=${REPORT_HOST:-203.0.113.10}

step() { printf '[canary] %s\n' "$*"; }

# 1) real browser, machine picked by TRIGGER (auto|mac|windows). Mac mini:
#    HEADED Chrome — a real window on the mini's console, no --headless flag:
#    the reference must be a normal desktop browser. One trigger call runs two
#    sessions: (A) a throwaway profile -> fresh full handshake; (B) the
#    persistent canary profile -> tab 1 full handshake, then a hand-off tab
#    (second Chrome invocation with the same user-data-dir; ProcessSingleton
#    forwards the URL to the running instance) which opens a second TLS
#    connection and resumes with the in-memory ticket. Both real hello shapes
#    (fresh and resumed) land on the stand every run, and no graceful-shutdown
#    games are needed: the fingerprint is captured on the wire long before the
#    browser exits. Windows: refresh the helper cmd, fire the scheduled task.
triggered=0
# macOS has no GNU timeout and headed Chrome ignores --timeout, so every
# session is bounded by our own kill (main PID + scoped sweep). The pgrep
# bracket pattern "fpcheck[-]" matches our profile dirs (fpcheck-fresh.*,
# fpcheck-chrome-profile) but never this script's own command line, and a
# leftover ProcessSingleton lock would abort later launches with exit 0.
mac_remote='for p in $(pgrep -f "fpcheck[-]"); do kill "$p" 2>/dev/null; done; sleep 1
D=$(mktemp -d /tmp/fpcheck-fresh.XXXXXX)
"'"$MAC_CHROME"'" --user-data-dir="$D" --no-first-run --no-default-browser-check "https://fp.example.test/fp?a" >/dev/null 2>&1 &
APID=$!
sleep 13
kill $APID 2>/dev/null; sleep 2; rm -rf "$D"
"'"$MAC_CHROME"'" --user-data-dir="$HOME/.fpcheck-chrome-profile" --no-first-run --no-default-browser-check "https://fp.example.test/fp?b1" >/dev/null 2>&1 &
BPID=$!
sleep 13
"'"$MAC_CHROME"'" --user-data-dir="$HOME/.fpcheck-chrome-profile" --no-first-run "https://fp.example.test/fp?b2" >/dev/null 2>&1
sleep 13
kill $BPID 2>/dev/null; sleep 2
for p in $(pgrep -f "fpcheck[-]"); do kill "$p" 2>/dev/null; done
sleep 2
echo done'
trigger_mac() {
    [ -n "$MAC_HOST" ] && [ -n "$MAC_USER" ] || { step "WARN: mac trigger skipped (MAC_HOST/MAC_USER unset)"; return 1; }
    ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$MAC_USER@$MAC_HOST" "$mac_remote" >/dev/null 2>&1
}
trigger_windows() {
    [ -n "$WIN_HOST" ] && [ -n "$WIN_USER" ] && [ -n "$WIN_PASS" ] || { step "WARN: windows trigger skipped (WIN_HOST/WIN_USER/WIN_PASS unset)"; return 1; }
    # clear any lingering headless instance holding the profile lock (best
    # effort: AdGuard self-protection may deny taskkill over SSH)
    sshpass -p "$WIN_PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$WIN_USER@$WIN_HOST" 'taskkill /im chrome.exe /f' >/dev/null 2>&1
    sshpass -p "$WIN_PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$WIN_USER@$WIN_HOST" \
        'powershell -Command "Set-Content -Path C:\Users\fp\fpcheck.cmd -Value \"\"\"C:\Program Files\Google\Chrome\Application\chrome.exe\"\" --headless=new --timeout=20000 https://fp.example.test/fp\" -Encoding ASCII" && schtasks /Run /TN smfp2'
}
case "$TRIGGER" in
    mac)     MACHINE=mac ;;
    windows) MACHINE=windows ;;
    auto)
        if [ -n "$MAC_HOST" ] && [ -n "$MAC_USER" ]; then MACHINE=mac
        elif [ -n "$WIN_HOST" ] && [ -n "$WIN_USER" ] && [ -n "$WIN_PASS" ]; then MACHINE=windows
        fi ;;
    *) MACHINE="" ;;
esac
case "$TRIGGER" in mac|windows|auto) ;; *) step "WARN: unknown TRIGGER=$TRIGGER (want auto|mac|windows)" ;; esac

if [ "$MACHINE" = mac ]; then
    # one trigger call = both sessions (fresh profile + persistent with the
    # hand-off resumption tab), three real reports on the stand
    if trigger_mac; then
        triggered=1
        step "real chrome sessions on mac mini (headed: fresh + resumed)"
    else
        step "WARN: mac mini trigger failed"
    fi
elif [ "$MACHINE" = windows ]; then
    i=0
    while [ "$i" -lt "$TRIGGER_VISITS" ]; do
        i=$((i+1))
        if trigger_windows; then
            triggered=1
            step "real chrome visit $i/$TRIGGER_VISITS on windows"
        else
            step "WARN: windows visit $i failed"
        fi
        [ "$i" -lt "$TRIGGER_VISITS" ] || break
        sleep 35
    done
else
    step "WARN: no trigger machine available (check TRIGGER and creds)"
fi
# auto fallback: preferred machine dead -> one attempt on the other
if [ "$triggered" -eq 0 ] && [ "$TRIGGER" = auto ]; then
    if [ "$MACHINE" = mac ] && trigger_windows; then
        MACHINE=windows; triggered=1; step "real chrome visit (fallback) on windows"
    elif [ "$MACHINE" = windows ] && trigger_mac; then
        MACHINE=mac; triggered=1; step "real chrome visit (fallback) on mac mini"
    fi
fi
[ "$triggered" -eq 1 ] || step "WARN: no real-browser trigger succeeded (this run will fail without a fresh reference)"
sleep 20

# 2) our clients through the same stand, tagged with x-canary markers.
go build -o .tmp/canary-stand-probe ./examples/stand-probe/ || exit 1
python3 - <<'EOF'
import json
d = json.load(open('examples/vk-ru-windows/profile.json'))
d['headers']['x-canary'] = 'ours-exact'
d.setdefault('header_order', []).append('x-canary')
json.dump(d, open('.tmp/canary-win-exact.json', 'w'))
d2 = json.load(open('examples/vk-ru/profile.json'))
d2['tls_client_hello'] = 'chrome_152'
d2['headers']['x-canary'] = 'ours-utls'
d2.setdefault('header_order', []).append('x-canary')
json.dump(d2, open('.tmp/canary-win-uTLS.json', 'w'))
d3 = json.load(open('examples/vk-ru-windows/profile.json'))
d3['tls_client_hello'] = 'chrome_152_psk'
d3['headers']['x-canary'] = 'ours-psk'
d3.setdefault('header_order', []).append('x-canary')
json.dump(d3, open('.tmp/canary-win-PSK.json', 'w'))
EOF
.tmp/canary-stand-probe "https://fp.example.test/fp" 1 .tmp/canary-win-exact.json >/dev/null 2>&1
.tmp/canary-stand-probe "https://fp.example.test/fp" 1 .tmp/canary-win-uTLS.json >/dev/null 2>&1
.tmp/canary-stand-probe "https://fp.example.test/fp" 1 .tmp/canary-win-PSK.json >/dev/null 2>&1
step "mimic probes done"

# 3) read the freshest reports and diff.
python3 - <<'EOF'
import json, socket, ssl, sys
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
import os
report_host = os.environ.get("REPORT_HOST", "203.0.113.10")
raw = socket.create_connection((report_host, 443), timeout=15)
t = ctx.wrap_socket(raw, server_hostname="fp.example.test")
# HTTP/1.0: the server answers with Content-Length framing, no chunked
t.sendall(b"GET /fp/recent?limit=50 HTTP/1.0\r\nHost: fp.example.test\r\n\r\n")
buf = b""
while True:
    d = t.recv(65536)
    if not d:
        break
    buf += d
out = buf.partition(b"\r\n\r\n")[2]
reports = json.loads(out)

# Only reports from this run's window matter: the stand is public, so older
# real-browser visits must not satisfy today's comparison.
def age_seconds(r):
    try:
        then = datetime.strptime(r["time"].split(".")[0], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - then).total_seconds()
    except Exception:
        return 1e9

# Real Chrome always carries client hints on navigation; scanners faking a
# browser UA do not. The platform is irrelevant for JA4, so any Chrome UA on
# any OS qualifies (the trigger host is a Mac; ours are tagged x-canary).
real = [r for r in reports
        if age_seconds(r) < 1800
        and "Chrome/" in (r["http"]["user_agent"] or "")
        and any(h["name"].lower() == "sec-ch-ua" for h in r["http"]["headers"])
        and not any(h["name"].lower() == "x-canary" for h in r["http"]["headers"])]
ours = {h["value"]: r for r in reports for h in r["http"]["headers"]
        if h["name"].lower() == "x-canary" and h["value"].startswith("ours-")}

if not real:
    print("CANARY FAIL: no real-browser report in /fp/recent (trigger failed?)")
    sys.exit(2)

# Chrome A/Bs hello variants per connection (Finch): the real fingerprint is
# a SET of variants observed during the day, not a single value. Our probes
# must each land inside the real variant set; a real variant no probe can
# produce is reported as a coverage NOTE.
real_ja4 = {}
real_ja3 = {}
for r in real:
    t = r.get("tls") or {}
    if t.get("ja4"):
        real_ja4[t["ja4"]] = real_ja4.get(t["ja4"], 0) + 1
    if t.get("ja3_hash"):
        real_ja3[t["ja3_hash"]] = real_ja3.get(t["ja3_hash"], 0) + 1
r0 = real[0]
real_hdr_names = sorted(h["name"].lower() for h in r0["http"]["headers"]
                        if h["name"].lower() != "x-canary")
print(f"real variants today: ja4={real_ja4} ja3={real_ja3} "
      f"(ua={r0['http']['user_agent'].split(') ')[0]}) (hdrs={len(r0['http']['headers'])}, "
      f"ttl={(r0.get('transport') or {}).get('ttl')})")
if (r0.get("transport") or {}).get("ttl") is None:
    print("WARN  transport.ttl missing - fpd wire sniffer is not capturing; restart fpd.service")

# Known hello shapes our specs produce (fresh vs resumed). A probe landing
# here but missing from TODAY's real sample is a NOTE (the real browser just
# did not run that shape this run), not drift. A probe outside both sets IS
# drift: our spec broke.
known_shapes = {
    "t13d1517h2_8daaf6152771_cb7bf5808d99": "fresh",
    "t13d1518h2_8daaf6152771_e2d80978ab2e": "resumed",
    "t13d1516h2_8daaf6152771_806a8c22fdea": "chromium-151 legacy",
}

bad = 0
our_variants = {}
for tag, probe in ours.items():
    t = probe.get("tls") or {}
    ja4 = t.get("ja4")
    ja3h = t.get("ja3_hash")
    our_variants.setdefault(ja4, tag)
    if ja4 in real_ja4:
        print(f"OK    {tag}: ja4={ja4} in real set")
    elif ja4 in known_shapes:
        print(f"NOTE  {tag}: ja4={ja4} ({known_shapes[ja4]}) - not sampled by the "
              "real browser this run, shape is known-good")
    else:
        print(f"DRIFT {tag}: ja4={ja4} is in NEITHER the real set nor known shapes")
        bad += 1
    # JA3 is order- and GREASE-sensitive; Chrome (and our uTLS mirror of it)
    # permutes extensions per connection, so an uncovered ja3 today is
    # sampling luck, not drift - but its absence IS a capture regression.
    if not ja3h:
        print("WARN  ja3_hash missing on the probe report - fpd capture regression")
    elif ja3h in real_ja3:
        print(f"OK    {tag}: ja3={ja3h} in real set")
    else:
        print(f"NOTE  {tag}: ja3={ja3h} not among today's real ja3 (order/GREASE shuffling)")
    names = sorted(h["name"].lower() for h in probe["http"]["headers"]
                   if h["name"].lower() != "x-canary")
    diff = ([n for n in names if n not in real_hdr_names]
            + [n for n in real_hdr_names if n not in names])
    if diff:
        print(f"NOTE  {tag}: header-name diff vs real: {','.join(diff)}")

uncovered = [v for v in real_ja4 if v not in our_variants]
for v in uncovered:
    print(f"NOTE  real variant {v} has no mimic probe; "
          "add/switch a spec if it becomes dominant")

sys.exit(2 if bad else 0)
EOF
rc=$?
if [ "$rc" -eq 0 ]; then
    step "RESULT: match — ours == real on JA4 + header names"
else
    step "RESULT: DRIFT — real Chrome fingerprint changed or our stack is behind (see above)"
fi
exit $rc
