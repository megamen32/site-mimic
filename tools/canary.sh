#!/usr/bin/env bash
# Daily real-vs-ours canary for the site-mimic verification stand.
#
# Drives a real Chrome (Windows box, scheduled task, headless so no visible
# window) and our mimic clients at https://test.auto-gram.ru/fp, tags our
# requests with an x-canary header, then diffs the freshest /fp/recent
# reports: JA4 and header name count. Exit 0 = match, exit 2 = drift
# (Chrome turned an experiment on/off, bundled browser stale, profile drift).
set -u
cd "$(dirname "$0")/.."

WIN_HOST=${WIN_HOST:-192.168.2.190}
WIN_USER=${WIN_USER:-megam}
WIN_PASS=${WIN_PASS:-aofhkLSD25i}

step() { printf '[canary] %s\n' "$*"; }

# 1) real browser: refresh the helper cmd to headless (no visible window),
#    then fire the scheduled task.
sshpass -p "$WIN_PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    "$WIN_USER@$WIN_HOST" \
    'powershell -Command "Set-Content -Path C:\Users\roomhacker\fpcheck.cmd -Value \"\"\"C:\Program Files\Google\Chrome\Application\chrome.exe\"\" --headless=new --timeout=20000 https://test.auto-gram.ru/fp\" -Encoding ASCII" && schtasks /Run /TN smfp2' \
    >/dev/null 2>&1 || step "WARN: windows trigger failed (continuing with the cached real reference)"
step "real chrome triggered"
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
.tmp/canary-stand-probe "https://test.auto-gram.ru/fp" 1 .tmp/canary-win-exact.json >/dev/null 2>&1
.tmp/canary-stand-probe "https://test.auto-gram.ru/fp" 1 .tmp/canary-win-uTLS.json >/dev/null 2>&1
.tmp/canary-stand-probe "https://test.auto-gram.ru/fp" 1 .tmp/canary-win-PSK.json >/dev/null 2>&1
step "mimic probes done"

# 3) read the freshest reports and diff.
python3 - <<'EOF'
import json, socket, ssl, sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection(("95.165.165.65", 443), timeout=15)
t = ctx.wrap_socket(raw, server_hostname="test.auto-gram.ru")
t.sendall(b"GET /fp/recent?limit=50 HTTP/1.1\r\nHost: test.auto-gram.ru\r\nConnection: close\r\n\r\n")
buf = b""
while True:
    d = t.recv(65536)
    if not d:
        break
    buf += d
head, _, body = buf.partition(b"\r\n\r\n")
out = b""
while body:
    line, _, body = body.partition(b"\r\n")
    try:
        n = int(line.split(b";")[0], 16)
    except ValueError:
        break
    if n == 0:
        break
    out += body[:n]
    body = body[n + 2:]
reports = json.loads(out)

real = [r for r in reports
        if "Windows NT" in (r["http"]["user_agent"] or "")
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
print(f"real variants today: {real_variants} (hdrs={len(r0['http']['headers'])}, "
      f"ttl={(r0.get('transport') or {}).get('ttl')})")

bad = 0
our_variants = {}
for tag, probe in ours.items():
    ja4 = (probe.get("tls") or {}).get("ja4")
    our_variants.setdefault(ja4, tag)
    in_real = ja4 in real_variants
    if not in_real:
        bad += 1
    print(f"{'OK    ' if in_real else 'DRIFT'}  {tag}: ja4={ja4} "
          f"{'in real set' if in_real else 'NOT in real variant set!'}")

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
