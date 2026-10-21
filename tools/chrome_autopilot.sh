#!/usr/bin/env bash
# The autopilot for a new Chrome release.
#
# Chrome ships every four weeks and each release changes the wire now and
# then: a new extension, a new google_connection_options token, a new
# shape. The autopilot turns that into something the project notices
# instead of something a person has to remember to look for:
#
#   1. it asks Chrome for Testing which stable is the newest;
#   2. it downloads it once, into .tools/;
#   3. it runs that browser against the local stands — the HTTP/3 one and a
#      plain TCP tap — and fingerprints what it puts on the wire;
#   4. it diffs the result with the pinned reference
#      (tools/chrome_reference.json, the same file the QUIC canary reads);
#   5. it prints what moved, and with --issue it opens an issue with the
#      diff, so the next step (patch the fork, move the reference) is
#      queued rather than remembered.
#
# The browser is the one from Chrome for Testing, not the system one: a
# stable release must not touch the browser a person uses, and the
# download is the same build the reference was taken from.
#
# Usage:
#   tools/chrome_autopilot.sh              # measure and report
#   tools/chrome_autopilot.sh --issue      # and open an issue when it moved
#   tools/chrome_autopilot.sh --version 157.0.0.0   # a specific build
#   tools/chrome_autopilot.sh --keep       # keep the downloaded browser
set -u
cd "$(dirname "$0")/.."

CFT_API=https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
REFERENCE=tools/chrome_reference.json
TOOLS_DIR=.tools/cft
ISSUE=0
KEEP=0
VERSION=""
PORT=${AUTOPILOT_PORT:-18730}

step() { printf '[autopilot] %s\n' "$*"; }
die() { step "FAIL: $*"; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--issue) ISSUE=1; shift ;;
	--keep) KEEP=1; shift ;;
	--version) VERSION="$2"; shift 2 ;;
	-h|--help) sed -n '2,25p' "$0"; exit 0 ;;
	*) die "unknown argument $1" ;;
	esac
done

command -v curl >/dev/null || die "no curl"
command -v python3 >/dev/null || die "no python3"
[ -f "$REFERENCE" ] || die "no reference at $REFERENCE"

# 1. which stable is the newest?
if [ -z "$VERSION" ]; then
	step "asking Chrome for Testing for the newest stable"
	VERSION=$(curl -s "$CFT_API" | python3 -c "
import json, sys
print(json.load(sys.stdin)['channels']['Stable']['version'])
") || die "could not read the Chrome for Testing index"
fi
step "stable: $VERSION"

# 2. the browser, once.
PLATFORM=mac-arm64
case "$(uname -s)-$(uname -m)" in
Darwin-arm64) PLATFORM=mac-arm64 ;;
Darwin-x86_64) PLATFORM=mac-x64 ;;
Linux-x86_64) PLATFORM=linux64 ;;
Linux-aarch64) PLATFORM=linux-arm64 ;;
esac
DIR=$TOOLS_DIR/$VERSION/$PLATFORM
BIN=""
for candidate in \
	"$DIR/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
	"$DIR/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
	"$DIR/chrome-linux64/chrome" \
	"$DIR/chrome-linux-arm64/chrome"; do
	[ -x "$candidate" ] && BIN="$candidate" && break
done

if [ -z "$BIN" ]; then
	# The download url is built from the build number: the index only
	# carries the stable one, and --version may ask for another.
	URL="https://storage.googleapis.com/chrome-for-testing-public/$VERSION/$PLATFORM/chrome-$PLATFORM.zip"
	step "downloading $URL"
	mkdir -p "$DIR"
	ZIP=$TOOLS_DIR/$VERSION/chrome-$PLATFORM.zip
	curl -sL "$URL" -o "$ZIP" || die "download failed"
	unzip -q -o "$ZIP" -d "$DIR" || die "unzip failed"
	for candidate in \
		"$DIR/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
		"$DIR/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
		"$DIR/chrome-linux64/chrome" \
		"$DIR/chrome-linux-arm64/chrome"; do
		[ -x "$candidate" ] && BIN="$candidate" && break
	done
	[ -n "$BIN" ] || die "the downloaded archive has no browser at the expected path"
fi
step "browser: $BIN"

# The LAN address: Chrome refuses to speak QUIC to a loopback address.
IP=${AUTOPILOT_IP:-}
if [ -z "$IP" ]; then
	for dev in en0 en1 en2; do
		addr=$(ipconfig getifaddr "$dev" 2>/dev/null) && [ -n "$addr" ] && { IP="$addr"; break; }
	done
fi
[ -n "$IP" ] || die "no LAN address (set AUTOPILOT_IP)"

WORK=.tmp/autopilot
mkdir -p "$WORK"

# 3a. the TCP side: a plain ClientHello tap. The handshake then fails — the
# tap never answers — but the hello is on the wire before that.
step "measuring the TCP hello"
go build -o "$WORK/hello-tap" ./cmd/hello-tap || die "build cmd/hello-tap"
rm -f "$WORK/tcp.jsonl"
"$WORK/hello-tap" -listen "0.0.0.0:$PORT" -out "$WORK/tcp.jsonl" >"$WORK/tap.log" 2>&1 &
TAP=$!
sleep 1
PROFILE_DIR=$(mktemp -d /tmp/autopilot-chrome.XXXXXX)
"$BIN" --user-data-dir="$PROFILE_DIR" --no-first-run --no-default-browser-check \
	--disable-quic --ignore-certificate-errors "https://$IP:$PORT/" >/dev/null 2>&1 &
CHROME=$!
sleep 12
kill $CHROME 2>/dev/null
pkill -f "autopilot-chrome\." 2>/dev/null
kill $TAP 2>/dev/null
wait $TAP 2>/dev/null

TCP_JA4=$(python3 - "$WORK/tcp.jsonl" <<'PYEOF'
import json, sys
seen = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    if r.get("ja4") and r["ja4"] not in seen:
        seen.append(r["ja4"])
print(seen[0] if seen else "")
PYEOF
)
step "TCP JA4: ${TCP_JA4:-none}"

# 3b. the QUIC side: the canary, with this browser as the browser.
step "measuring the QUIC hello"
CANARY_OUT=$WORK/canary.txt
CHROME="$BIN" CANARY_PORT=$((PORT + 10)) ./tools/canary-quic.sh >"$CANARY_OUT" 2>&1
QUIC_LINE=$(grep -E "^real browser:" "$CANARY_OUT" | head -1)
QUIC_JA4=$(echo "$QUIC_LINE" | sed -n 's/.*ja4=\([^ ]*\).*/\1/p')
NOTES=$(grep -cE "^(NOTE|DRIFT)" "$CANARY_OUT" || true)
step "QUIC JA4: ${QUIC_JA4:-none}"

# 4. the diff.
python3 - "$REFERENCE" "$TCP_JA4" "$QUIC_JA4" "$NOTES" <<'PYEOF' | tee .tmp/autopilot/diff.txt
import json, sys

ref = json.load(open(sys.argv[1]))
tcp, quic, notes = sys.argv[2], sys.argv[3], int(sys.argv[4])
moved = []

def fingerprint(ja4):
    """The b and c parts: the fingerprint itself.

    The a part carries the SNI token and the extension count, and both
    depend on whether the target was a name or an address — the autopilot
    measures by address, the reference was taken by name.
    """
    parts = ja4.split("_")
    return "_".join(parts[1:]) if len(parts) >= 3 else ja4


if tcp and fingerprint(tcp) != ref["tcp"]["b_and_c"]:
    moved.append(f"TCP JA4: {tcp} (the reference says {ref['tcp']['ja4']})")
if quic and fingerprint(quic) != ref["quic"]["b_and_c"]:
    moved.append(f"QUIC JA4: {quic} (the reference says {ref['quic']['ja4']})")
if notes:
    moved.append(f"{notes} difference(s) in the QUIC canary — see the output")

print(f"reference: Chrome {ref['chrome_version']} (measured {ref['measured']})")
print(f"measured:  TCP {tcp or 'none'}, QUIC {quic or 'none'}")
if moved:
    print("\nthe browser has moved on:")
    for m in moved:
        print("  -", m)
else:
    print("\nthe browser still speaks the pinned reference")
sys.exit(1 if moved else 0)
PYEOF
DIFF_STATUS=$?

# 5. the issue, when the browser moved on and the owner asked for it.
if [ "$DIFF_STATUS" -ne 0 ] && [ "$ISSUE" = "1" ]; then
	BODY="Chrome has moved on (the reference is $(python3 -c "import json;print(json.load(open('$REFERENCE'))['chrome_version'])")).\n\n\`\`\`\n$(cat .tmp/autopilot/diff.txt)\n\`\`\`\n\nThe browser: $BIN\nThe canary output:\n\n\`\`\`\n$(grep -E '^(NOTE|DRIFT|real browser|ours)' "$CANARY_OUT")\n\`\`\`"
	step "opening an issue"
	gh issue create --repo "${AUTOPILOT_REPO:-megamen32/site-mimic}" \
		--title "Chrome moved on: the wire reference is stale" --body "$BODY" || step "WARN: could not open the issue"
fi

if [ "$KEEP" != "1" ]; then
	rm -rf "$TOOLS_DIR/$VERSION"
fi
exit $DIFF_STATUS
