#!/usr/bin/env bash
# The QUIC canary: the real browser's HTTP/3 fingerprint against ours.
#
# The TCP canary (tools/canary.sh) drives a real Chrome and our mimic
# clients against the verification stand and diffs JA4, JA3 and the header
# names. This one does the same for the QUIC path: a real Chrome and our own
# h3 client against the same kind of HTTP/3 stand (cmd/h3sniff), then a diff
# of what the two put on the wire — the QUIC ClientHello (its JA4, the
# extension set, the signature algorithms), the QUIC transport parameters and
# the HTTP/3 settings of the control stream.
#
# Everything runs on this machine. Two stands are started, one for the
# browser and one for us, so that the two reports cannot be confused.
#
# The verdict has two halves, and the difference matters:
#
#   ours vs the pinned reference  -> DRIFT means WE changed. That is a
#                                     failure: exit 2.
#   the browser vs the reference   -> NOTE means the browser moved on. That
#                                     is not a failure of this library, but it
#                                     means the pinned measurement is old and
#                                     has to be taken again.
#
# Exit 0 = ours still matches the reference, exit 2 = drift, exit 1 = the
# canary could not run.
set -u
cd "$(dirname "$0")/.."

CHROME=${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
PORT=${CANARY_PORT:-18443}
WORK=.tmp/canary-quic
PROFILE=${CANARY_PROFILE:-examples/profiles/windows-chrome152-h3.json}

step() { printf '[canary-quic] %s\n' "$*"; }
die() { step "FAIL: $*"; exit 1; }

# The reference: what a real Chrome sent on the wire, measured on the phone
# (2026-08-30, Chrome on the S21, a QUIC handshake to a Google server) and
# pinned by mimic/h3_wire_test.go.
#
# The JA4 is split: the b and c parts are the fingerprint itself (the cipher
# list and the extension list with the signature algorithms), and the a part
# carries the SNI token and the extension count — both of which depend on
# whether the target was a name or an address.
REF_JA4_BC='55b375c5d22e_653d80c3fe9d'
REF_EXTENSIONS='0x0000 0x000a 0x000d 0x0010 0x001b 0x002b 0x002d 0x0033 0x0039 0x44cd 0xfe0d'
REF_SIGALGS='0x0201 0x0401 0x0403 0x0501 0x0503 0x0601 0x0804 0x0805 0x0806'
REF_SETTINGS='1=65536 6=262144 7=100 51=1'
REF_GCO='4f5249474543435049573258'   # google_connection_options: ORIGECCPIW2X

command -v go >/dev/null || die "go is not on PATH"
[ -x "$CHROME" ] || die "no Chrome at $CHROME (set CHROME)"
[ -f "$PROFILE" ] || die "no profile at $PROFILE"

# The LAN address: Chrome refuses to speak QUIC to a loopback address.
ip_of() {
    if [ -n "${CANARY_IP:-}" ]; then echo "$CANARY_IP"; return; fi
    for dev in en0 en1 en2; do
        addr=$(ipconfig getifaddr "$dev" 2>/dev/null) && [ -n "$addr" ] && { echo "$addr"; return; }
    done
    hostname -I 2>/dev/null | awk '{print $1}'
}
IP=$(ip_of)
[ -n "$IP" ] || die "no LAN address found (set CANARY_IP)"
URL="https://$IP:$PORT/"

mkdir -p "$WORK"

# The certificate. Chrome checks the certificate even with
# --ignore-certificate-errors when it speaks QUIC, so the browser has to
# trust the CA that signed the stand's certificate. The CA is a test one,
# named as such, and it is added to the login keychain once.
if [ ! -f "$WORK/srv.pem" ] || [ ! -f "$WORK/srv.key" ]; then
    step "generating a certificate for $IP"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
        -subj "/CN=site-mimic canary CA" >/dev/null 2>&1 || die "openssl: the CA"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$WORK/srv.key" -out "$WORK/srv.csr" \
        -subj "/CN=$IP" >/dev/null 2>&1 || die "openssl: the request"
    printf 'subjectAltName=IP:%s\n' "$IP" > "$WORK/ext.cnf"
    openssl x509 -req -in "$WORK/srv.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
        -CAcreateserial -out "$WORK/srv.pem" -days 30 -extfile "$WORK/ext.cnf" \
        >/dev/null 2>&1 || die "openssl: the certificate"
fi

# Trust the CA, so the browser speaks QUIC to the stand. Chrome refuses to
# speak QUIC to a certificate it does not trust, and it refuses loopback
# addresses, so this is the only way to put a real browser on the wire.
if [ "$(uname -s)" = "Darwin" ]; then
    KEYCHAIN=~/Library/Keychains/login.keychain-db
    if ! security find-certificate -c "site-mimic canary CA" "$KEYCHAIN" >/dev/null 2>&1; then
        if [ "${CANARY_NO_KEYCHAIN:-0}" = "1" ]; then
            step "WARN: the canary CA is not trusted and CANARY_NO_KEYCHAIN=1;"
            step "      the browser will not speak QUIC, so the canary cannot run"
        else
            step "trusting the canary CA in the login keychain (test CA, once)"
            security add-trusted-cert -r trustRoot -k "$KEYCHAIN" "$WORK/ca.pem" \
                >/dev/null 2>&1 || die "could not trust the CA; run it by hand:"
        fi
    fi
fi

step "building the stand"
go build -o "$WORK/h3sniff" ./cmd/h3sniff || die "build cmd/h3sniff"

rm -f "$WORK/browser.jsonl" "$WORK/ours.jsonl"
"$WORK/h3sniff" -addr "$IP:$PORT" -cert "$WORK/srv.pem" -key "$WORK/srv.key" \
    -wait 90s -out "$WORK/browser.jsonl" >"$WORK/browser.log" 2>&1 &
BROWSER_STAND=$!
OURS_PORT=$((PORT + 1))
"$WORK/h3sniff" -addr "$IP:$OURS_PORT" -cert "$WORK/srv.pem" -key "$WORK/srv.key" \
    -wait 90s -out "$WORK/ours.jsonl" >"$WORK/ours-stand.log" 2>&1 &
OURS_STAND=$!
# The stands are not jobs of this shell: a killed background job makes bash
# print "Terminated" in the middle of the canary's own output.
disown $BROWSER_STAND $OURS_STAND 2>/dev/null || true
trap 'kill $BROWSER_STAND $OURS_STAND 2>/dev/null' EXIT
sleep 1
kill -0 $BROWSER_STAND 2>/dev/null || die "the stand did not start (see $WORK/browser.log)"

# 1) the real browser. --origin-to-force-quic-on makes Chrome speak QUIC on
# the first request instead of waiting for an Alt-Svc.
PROFILE_DIR=$(mktemp -d /tmp/canary-quic-chrome.XXXXXX)
step "driving Chrome against https://$IP:$PORT/"
"$CHROME" --user-data-dir="$PROFILE_DIR" --no-first-run --no-default-browser-check \
    --ignore-certificate-errors --origin-to-force-quic-on="$IP:$PORT" "$URL" \
    >/dev/null 2>&1 &
CHROME_PID=$!
sleep 12
kill $CHROME_PID 2>/dev/null

# 2) our own h3 client, against the same kind of stand.
step "driving our h3 client against https://$IP:$OURS_PORT/"
go run ./examples/http3 -url "https://$IP:$OURS_PORT/" -profile "$PROFILE" -insecure \
    >"$WORK/ours.log" 2>&1 || step "WARN: our client failed (see $WORK/ours.log)"
sleep 1

kill $BROWSER_STAND $OURS_STAND 2>/dev/null
wait $BROWSER_STAND 2>/dev/null
wait $OURS_STAND 2>/dev/null
[ -s "$WORK/ours.jsonl" ] || die "our client never reached the stand (see $WORK/ours.log)"

# 3) the diff.
python3 - "$WORK/browser.jsonl" "$WORK/ours.jsonl" "$REF_JA4_BC" "$REF_EXTENSIONS" \
    "$REF_SIGALGS" "$REF_SETTINGS" "$REF_GCO" "$IP" \
    mimic/testdata/chrome_quic_transport_parameters.bin <<'EOF'
import json
import sys

(browser_path, ours_path, ref_bc, ref_ext, ref_sig, ref_settings, ref_gco,
 target, ref_tp_path) = sys.argv[1:10]
ref_ext = set(ref_ext.split())
ref_sig = set(ref_sig.split())
ref_settings = dict(p.split("=") for p in ref_settings.split())

# An address on the wire means no SNI, and no server_name extension with
# it; the measurement was taken against a name.
BY_NAME = not target.replace(".", "").isdigit()
if not BY_NAME:
    ref_ext = ref_ext - {"0x0000"}


def load(path):
    reports = []
    for line in open(path):
        line = line.strip()
        if line:
            reports.append(json.loads(line))
    return reports


browser_reports = load(browser_path)
ours_reports = load(ours_path)
if not browser_reports:
    print("CANARY FAIL: the browser never reached the stand over QUIC")
    print("            (Chrome speaks QUIC only to an address it trusts and")
    print("             never to a loopback one)")
    sys.exit(2)
if not ours_reports:
    print("CANARY FAIL: our client never reached the stand")
    sys.exit(2)

browser = browser_reports[0]
ours = ours_reports[0]

bad = 0


def compare(label, ours_value, want, browser_value):
    global bad
    if ours_value != want:
        print(f"DRIFT {label}: ours={ours_value} want={want}")
        bad += 1
    elif browser_value != want:
        print(f"NOTE  {label}: the browser sends {browser_value}, the reference says "
              f"{want} - the browser moved on, the measurement is old")


def bc_of(report):
    parts = report.get("ja4", "").split("_")
    return "_".join(parts[1:]) if len(parts) >= 3 else report.get("ja4", "")


# The fingerprint itself: the cipher list and the extension list.
compare("JA4 b and c", bc_of(ours), ref_bc, bc_of(browser))

# The extension set, order-independent: the QUIC hello shuffles it.
ours_ext = set(ours.get("extension_ids", []))
browser_ext = set(browser.get("extension_ids", []))
compare("extensions", ours_ext, ref_ext, browser_ext)

ours_sig = set(ours.get("sig_algs", []))
browser_sig = set(browser.get("sig_algs", []))
compare("signature algorithms", ours_sig, ref_sig, browser_sig)

ours_settings = ours.get("settings", {})
browser_settings = browser.get("settings", {})
for key, want in ref_settings.items():
    compare(f"setting {key}", ours_settings.get(key), int(want), browser_settings.get(key))

ours_tp = ours.get("transport_parameters", {})
browser_tp = browser.get("transport_parameters", {})
compare("google_connection_options", ours_tp.get("12584"), ref_gco, browser_tp.get("12584"))


def tp_set(params):
    """The parameter ids, without the GREASE ones (a random id on both sides)."""
    return {key for key in params if len(key) <= 6}


def read_varint(data, pos):
    length = 1 << (data[pos] >> 6)
    value = int.from_bytes(data[pos:pos + length], "big") & ((1 << (length * 8 - 2)) - 1)
    return value, pos + length


def captured_tp_ids(path):
    """The parameter ids of the captured transport parameters."""
    data = open(path, "rb").read()
    out = set()
    pos = 0
    while pos < len(data):
        param_id, pos = read_varint(data, pos)
        length, pos = read_varint(data, pos)
        pos += length
        if len(str(param_id)) > 6:   # a GREASE id
            continue
        out.add(str(param_id))
    return out


compare("transport parameters", tp_set(ours_tp), captured_tp_ids(ref_tp_path),
        tp_set(browser_tp))

print(f"real browser: ja4={browser['ja4']} extensions={len(browser_ext)} "
      f"agent={browser.get('user_agent', '')[:56]}")
print(f"ours:         ja4={ours['ja4']} extensions={len(ours_ext)} "
      f"agent={ours.get('user_agent', '')[:56]}")
print(f"reference:    ja4=...{ref_bc} extensions={len(ref_ext)} "
      f"({'by name' if BY_NAME else 'by address'})")

sys.exit(2 if bad else 0)
EOF
rc=$?
if [ "$rc" -eq 0 ]; then
    step "RESULT: match — our QUIC fingerprint is the reference one"
else
    step "RESULT: DRIFT — our QUIC fingerprint changed (see above)"
fi
exit $rc
