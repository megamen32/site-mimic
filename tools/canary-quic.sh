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
PROFILE=${CANARY_PROFILE:-examples/profiles/mac-chrome156-h3.json}

step() { printf '[canary-quic] %s\n' "$*"; }
die() { step "FAIL: $*"; exit 1; }

# The reference: what a real Chrome sent on the wire, measured against this
# stand (2026-10-21, Google Chrome 156.0.8078.47 on macOS) and pinned by
# mimic/h3_wire_test.go.
#
# The JA4 is split: the b and c parts are the fingerprint itself (the cipher
# list and the extension list with the signature algorithms), and the a part
# carries the SNI token and the extension count — both of which depend on
# whether the target was a name or an address.
#
# The extension list is the one Chrome 156 sends: the Chrome 155 set plus
# the unregistered 0xCA34 and 0x12E0. Chrome 155 sent eleven extensions and
# fingerprinted as q13i0311h3_55b375c5d22e_178839b6cec1; Chrome 156 sends
# twelve and fingerprints as q13i0312h3_55b375c5d22e_eb028bd37c08.
# It lives in tools/chrome_reference.json — the same file the Chrome
# autopilot (tools/chrome_autopilot.sh) reads — so that there is one set
# of numbers to move when the browser moves on.
#
# The JA4 is split: the b and c parts are the fingerprint itself (the cipher
# list and the extension list with the signature algorithms), and the a part
# carries the SNI token and the extension count — both of which depend on
# whether the target was a name or an address.
REF_JSON=tools/chrome_reference.json
eval "$(python3 - "$REF_JSON" <<'PYEOF'
import json
import sys

ref = json.load(open(sys.argv[1]))["quic"]
print("REF_JA4_BC='%s'" % ref["b_and_c"])
print("REF_EXTENSIONS='%s'" % " ".join(ref["extension_ids"]))
print("REF_SIGALGS='%s'" % " ".join(ref["sig_algs"]))
print("REF_SETTINGS='%s'" % " ".join("%s=%d" % (k, v) for k, v in ref["settings"].items()))
print("REF_GCO='%s'" % ref["google_connection_options"])
print("REF_TP='%s'" % ref["transport_parameters_fixture"])
PYEOF
)"

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
# Both sides go by this name, so both hellos carry the server name and the
# comparison is between the same shape. A client that talks to an address has
# no session to offer on the next connection, and its hello would have a
# different extension set.
CANARY_HOST=${CANARY_HOST:-quic.test}
URL="https://$IP:$PORT/"

mkdir -p "$WORK"

# The certificate. Chrome checks the certificate even with
# --ignore-certificate-errors when it speaks QUIC, so the browser has to
# trust the CA that signed the stand's certificate. The CA is a test one,
# named as such, and it is added to the login keychain once.
#
# The server certificate names the address of this machine, and the address
# changes with the network the machine is on. A certificate that names the
# old address makes the browser refuse to speak QUIC — so it is reissued
# when the address changes. The CA stays: it is the one the keychain
# trusts.
if [ ! -f "$WORK/ca.pem" ] || [ ! -f "$WORK/ca.key" ]; then
    step "generating the CA"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
        -subj "/CN=site-mimic canary CA" >/dev/null 2>&1 || die "openssl: the CA"
fi
if [ ! -f "$WORK/srv.pem" ] || [ ! -f "$WORK/srv.key" ] || [ "$(cat "$WORK/srv.ip" 2>/dev/null)" != "$IP" ]; then
    step "generating a certificate for $IP"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$WORK/srv.key" -out "$WORK/srv.csr" \
        -subj "/CN=$IP" >/dev/null 2>&1 || die "openssl: the request"
    printf 'subjectAltName=IP:%s,DNS:%s\n' "$IP" "$CANARY_HOST" > "$WORK/ext.cnf"
    openssl x509 -req -in "$WORK/srv.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
        -CAcreateserial -out "$WORK/srv.pem" -days 30 -extfile "$WORK/ext.cnf" \
        >/dev/null 2>&1 || die "openssl: the certificate"
    printf '%s' "$IP" > "$WORK/srv.ip"
fi

# Trust the CA, so the browser speaks QUIC to the stand. Chrome refuses to
# speak QUIC to a certificate it does not trust, and it refuses loopback
# addresses, so this is the only way to put a real browser on the wire.
#
# The trust is checked by the fingerprint of the CA on disk, not by its
# name: a name in the keychain says nothing about which CA it is, and a
# reissued CA with the same name is not the one that is trusted.
if [ "$(uname -s)" = "Darwin" ]; then
    KEYCHAIN=~/Library/Keychains/login.keychain-db
    CA_FP=$(openssl x509 -in "$WORK/ca.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    KEYCHAIN_FP=$(security find-certificate -c "site-mimic canary CA" -p "$KEYCHAIN" 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    if [ "$CA_FP" != "$KEYCHAIN_FP" ]; then
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
# The browser's stand runs in the browser mode: the page it serves asks for a
# subresource twice, and every connection is closed after its response. The
# browser therefore opens three connections - the first one full, the next
# two with the ticket of the first - and the canary sees all three hellos.
"$WORK/h3sniff" -addr "$IP:$PORT" -cert "$WORK/srv.pem" -key "$WORK/srv.key" \
    -wait 90s -browser -out "$WORK/browser.jsonl" >"$WORK/browser.log" 2>&1 &
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
step "driving our h3 client against https://$CANARY_HOST:$OURS_PORT/"
go run ./examples/http3 -url "https://quic.test:$OURS_PORT/" -profile "$PROFILE" -insecure -resume \
    -resolve "quic.test=$IP" \
    >"$WORK/ours.log" 2>&1 || step "WARN: our client failed (see $WORK/ours.log)"
sleep 1

kill $BROWSER_STAND $OURS_STAND 2>/dev/null
wait $BROWSER_STAND 2>/dev/null
wait $OURS_STAND 2>/dev/null
[ -s "$WORK/ours.jsonl" ] || die "our client never reached the stand (see $WORK/ours.log)"

# 3) the diff.
python3 - "$WORK/browser.jsonl" "$WORK/ours.jsonl" "$REF_JA4_BC" "$REF_EXTENSIONS" \
    "$REF_SIGALGS" "$REF_SETTINGS" "$REF_GCO" "$IP" \
    "$REF_TP" <<'EOF'
import json
import sys

(browser_path, ours_path, ref_bc, ref_ext, ref_sig, ref_settings, ref_gco,
 target, ref_tp_path) = sys.argv[1:10]
ref_ext = set(ref_ext.split())
ref_sig = set(ref_sig.split())
ref_settings = dict(p.split("=") for p in ref_settings.split())

# An address on the wire means no SNI, and no server_name extension with
# it; the measurement was taken against a name. The browser goes by the
# address and our client by a name (a session is bound to a name, so a
# client that talks to an address has no session to offer), so the two sides
# are compared with the shape each of them sends.
ref_ext_by_name = set(ref_ext)
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


def is_resumed(report):
    """A hello that offered a ticket: it carries the pre_shared_key."""
    return "0x0029" in (report.get("extension_ids") or [])


def full_report(reports):
    """The report of the handshake that offered no ticket.

    The stand reports the newest hello it saw for a client address, so the
    first report of a client that resumes can carry the hello of its
    second connection. The reference is the shape of the full handshake, so
    the comparison has to take the report without the pre_shared_key.
    """
    for report in reports:
        if not is_resumed(report):
            return report
    return reports[0]


def resumed_report(reports):
    """The report of the handshake that offered a ticket, if there was one."""
    for report in reports:
        if is_resumed(report):
            return report
    return None


browser = full_report(browser_reports)
ours = full_report(ours_reports)

# The resumption: a browser that has a ticket for an origin offers it on the
# next connection, and the hello then carries the pre_shared_key. Both sides
# are checked, so a client that stops resuming shows up here.
def resumed_shape(reports):
    for report in reports[1:]:
        if "0x0029" in (report.get("extension_ids") or []):
            return True
    return False


def resumption_line(label, reports):
    if len(reports) < 2:
        print("%s: one connection only, nothing to resume on" % label)
        return
    print("%s: %d connections, a later one resumes: %s"
          % (label, len(reports), "yes" if resumed_shape(reports) else "no"))


resumption_line("the browser", browser_reports)
resumption_line("ours", ours_reports)

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
# The extension sets are compared per side: our client goes by a name and
# carries the server_name extension, the browser goes by the address and
# does not.
if ours_ext != ref_ext_by_name:
    print("DRIFT extensions: ours=%s want=%s" % (ours_ext, ref_ext_by_name))
    bad += 1
elif browser_ext != ref_ext:
    print("NOTE  extensions: the browser sends %s, the reference says %s - the browser moved on, the measurement is old"
          % (browser_ext, ref_ext))

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

# The resumed shape: the hello of a connection that offered a ticket. The
# browser goes by the address and we go by a name, so the first part of the
# JA4 differs; the rest — the cipher list and the extension list — has to
# be the same, or a server that counts resumptions sees two different
# clients.
browser_resumed = resumed_report(browser_reports)
ours_resumed = resumed_report(ours_reports)
if browser_resumed and ours_resumed:
    if bc_of(browser_resumed) != bc_of(ours_resumed):
        print("DRIFT the resumed hello: ours=%s the browser sends %s"
              % (bc_of(ours_resumed), bc_of(browser_resumed)))
        bad += 1
    else:
        print("the resumed hello: ours and the browser send the same shape (%s)"
              % bc_of(ours_resumed))
else:
    print("the resumed hello: %s" % (
        "the browser offered no ticket" if not browser_resumed
        else "we offered no ticket"))

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
