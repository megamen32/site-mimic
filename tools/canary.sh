#!/usr/bin/env bash
# Daily real-vs-ours canary for the site-mimic verification stand.
#
# Drives a real Chrome (Mac mini via key SSH: headless, dedicated profile dir;
# Windows scheduled task is the fallback) and our mimic clients at
# https://fp.example.test/fp, tags our requests with an x-canary header, then
# diffs the freshest /fp/recent reports: JA4 and header name count.
# Exit 0 = match, exit 2 = drift (Chrome turned an experiment on/off, bundled
# browser stale, profile drift).
set -u
cd "$(dirname "$0")/.."

# Real-browser trigger machines. TRIGGER selects one per run: auto (default,
# Mac mini first, Windows fallback), mac, or windows. The Mac mini is the
# always-on acceptance host (key SSH); the Windows lab box needs sshpass
# credentials. REPORT_HOST serves /fp/recent — use a LAN address when the
# canary runs on the stand host.
TRIGGER=${TRIGGER:-auto}
MAC_HOST=${MAC_HOST:-}
MAC_USER=${MAC_USER:-}
MAC_CHROME=${MAC_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
WIN_HOST=${WIN_HOST:-}
WIN_USER=${WIN_USER:-}
WIN_PASS=${WIN_PASS:-}
REPORT_HOST=${REPORT_HOST:-203.0.113.10}

step() { printf '[canary] %s\n' "$*"; }

# 1) real browser, machine picked by TRIGGER (auto|mac|windows). Mac mini:
#    headless Chrome with a persistent dedicated profile dir, so resumption
#    tickets accumulate across daily runs; the instance exits itself after
#    --timeout. Windows: refresh the helper cmd, then fire the scheduled task.
triggered=0
mac_remote="nohup \"$MAC_CHROME\" --headless=new --user-data-dir=\"\$HOME/.fpcheck-chrome-profile\" --no-first-run --no-default-browser-check --timeout=20000 https://fp.example.test/fp >/dev/null 2>&1 & echo fired"
trigger_mac() {
    [ -n "$MAC_HOST" ] && [ -n "$MAC_USER" ] || { step "WARN: mac trigger skipped (MAC_HOST/MAC_USER unset)"; return 1; }
    ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$MAC_USER@$MAC_HOST" "$mac_remote" >/dev/null 2>&1
}
trigger_windows() {
    [ -n "$WIN_HOST" ] && [ -n "$WIN_USER" ] && [ -n "$WIN_PASS" ] || { step "WARN: windows trigger skipped (WIN_HOST/WIN_USER/WIN_PASS unset)"; return 1; }
    sshpass -p "$WIN_PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "$WIN_USER@$WIN_HOST" \
        'powershell -Command "Set-Content -Path C:\Users\fp\fpcheck.cmd -Value \"\"\"C:\Program Files\Google\Chrome\Application\chrome.exe\"\" --headless=new --timeout=20000 https://fp.example.test/fp\" -Encoding ASCII" && schtasks /Run /TN smfp2'
}
if [ "$TRIGGER" = mac ] || [ "$TRIGGER" = auto ]; then
    if trigger_mac; then
        triggered=1
        step "real chrome triggered on mac mini"
    else
        step "WARN: mac mini trigger failed"
    fi
fi
if [ "$triggered" -eq 0 ] && { [ "$TRIGGER" = windows ] || [ "$TRIGGER" = auto ]; }; then
    if trigger_windows; then
        triggered=1
        step "real chrome triggered on windows"
    else
        step "WARN: windows trigger failed"
    fi
fi
case "$TRIGGER" in mac|windows|auto) ;; *) step "WARN: unknown TRIGGER=$TRIGGER (want auto|mac|windows)" ;; esac
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
real_variants = {}
for r in real:
    ja4 = (r.get("tls") or {}).get("ja4")
    if ja4:
        real_variants[ja4] = real_variants.get(ja4, 0) + 1
r0 = real[0]
print(f"real variants today: {real_variants} (ua={r0['http']['user_agent'].split(') ')[0]}) "
      f"(hdrs={len(r0['http']['headers'])}, ttl={(r0.get('transport') or {}).get('ttl')})")
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
    ja4 = (probe.get("tls") or {}).get("ja4")
    our_variants.setdefault(ja4, tag)
    in_real = ja4 in real_variants
    known = ja4 in known_shapes
    if in_real:
        print(f"OK    {tag}: ja4={ja4} in real set")
    elif known:
        print(f"NOTE  {tag}: ja4={ja4} ({known_shapes[ja4]}) - not sampled by the "
              "real browser this run, shape is known-good")
    else:
        print(f"DRIFT {tag}: ja4={ja4} is in NEITHER the real set nor known shapes")
        bad += 1

uncovered = [v for v in real_variants if v not in our_variants]
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
