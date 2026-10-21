#!/usr/bin/env bash
# Capture the ClientHello of several apps on a rooted phone, in one pass.
#
# The phone is a shared resource, so the sweep has one hard rule: it always
# leaves the phone as it found it. The CA is a root of trust in the device's
# trust store, and the apps that read the store start failing on it — so the
# CA and its mounts go when the sweep ends, whatever happened in between.
# The rules in iptables and the on-device forwarder go with them: a leftover
# REDIRECT sends the app's traffic into a dead forwarder, and a leftover
# REJECT silently breaks QUIC for that uid.
#
# What it does per app:
#
#   1. routes the app's TCP through the capture chain (mitmdump over SOCKS5)
#      and blocks its QUIC, so a TCP ClientHello exists at all;
#   2. launches the app and lets it talk;
#   3. reads the capture with the library's own parser (cmd/hellofp), so the
#      numbers are the ones a server would compute;
#   4. tears the chain down before the next app.
#
# The QUIC part is a different capture: Chrome does not try QUIC for an
# origin it has never seen, so a local stand gets nothing. A tcpdump over
# udp port 443 does, and tools/ja4_from_pcap.py decrypts the Initial
# packets. Use --quic for that.
#
# Usage:
#   tools/phone/sweep.sh                       # the default app list
#   tools/phone/sweep.sh ru.oneme.app com.yandex.browser
#   tools/phone/sweep.sh --quic com.android.chrome
#   tools/phone/sweep.sh --seconds 45 --out .tmp/sweep
#
# Environment:
#   ADB          adb binary (default: adb)
#   DEVICE       adb device serial (default: the only one attached)
#   SOCKS5_HOST  capture host the phone can reach (default: this machine's
#                LAN address)
#   SOCKS5_PORT  capture host port (default: 31896)
#   CA_PEM       the mitmproxy CA in PEM (default: ~/.mitmproxy/...)
#   PYTHON       python with the `websocket` and `cryptography` packages
#                (default: python3)
set -u
cd "$(dirname "$0")/../.."

ADB=${ADB:-adb}
DEVICE=${DEVICE:-}
SOCKS5_PORT=${SOCKS5_PORT:-31896}
CA_PEM=${CA_PEM:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}
PYTHON=${PYTHON:-python3}
SECONDS_PER_APP=${SECONDS_PER_APP:-25}
# The URL the QUIC capture navigates to: a browser only speaks QUIC to an
# origin it already knows, and a home page is no origin at all.
QUIC_URL=${QUIC_URL:-https://www.google.com/}
OUT=""
QUIC=0
APPS=()

step() { printf '[sweep] %s\n' "$*"; }
die() { step "FAIL: $*"; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--quic) QUIC=1; shift ;;
	--seconds) SECONDS_PER_APP="$2"; shift 2 ;;
	--url) QUIC_URL="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	-h|--help) sed -n '2,30p' "$0"; exit 0 ;;
	*) APPS+=("$1"); shift ;;
	esac
done

# The default list: a browser, a browser fork and a native messenger — the
# three classes of client that matter.
if [ ${#APPS[@]} -eq 0 ]; then
	APPS=(com.android.chrome com.yandex.browser ru.oneme.app)
fi

[ -n "$OUT" ] || OUT=.tmp/sweep-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
WORK=$OUT/work
mkdir -p "$WORK"

command -v "$ADB" >/dev/null || die "no adb on PATH"
command -v mitmdump >/dev/null || die "no mitmdump on PATH"
[ -f "$CA_PEM" ] || die "no CA at $CA_PEM (mitmproxy --version writes it)"

if [ -z "$DEVICE" ]; then
	DEVICE=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')
	[ -n "$DEVICE" ] || die "no adb device attached"
fi
adb_() { "$ADB" -s "$DEVICE" "$@"; }

adb_ shell 'su -c id' >/dev/null 2>&1 || die "the device has no root (su failed)"

# The capture host: the phone has to reach it. A LAN address, not loopback.
if [ -z "${SOCKS5_HOST:-}" ]; then
	SOCKS5_HOST=$(for dev in en0 en1 en2; do
		addr=$(ipconfig getifaddr "$dev" 2>/dev/null) && [ -n "$addr" ] && { echo "$addr"; break; }
	done)
fi
[ -n "$SOCKS5_HOST" ] || die "no LAN address for the capture host (set SOCKS5_HOST)"
step "capture host: $SOCKS5_HOST:$SOCKS5_PORT, device: $DEVICE"

# The on-device half of the chain: the forwarder and the two scripts.
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' \
	-o "$WORK/tproxyfwd" ./cmd/tproxyfwd || die "build cmd/tproxyfwd"
adb_ push "$WORK/tproxyfwd" /data/local/tmp/tproxyfwd >/dev/null || die "push the forwarder"
adb_ push tools/phone/setup_capture.sh /data/local/tmp/setup_capture.sh >/dev/null
adb_ push tools/phone/ca_mount.sh /data/local/tmp/ca_mount.sh >/dev/null
adb_ shell "su -c 'chmod 700 /data/local/tmp/tproxyfwd'" >/dev/null

# The CA in Android's PEM naming: <subject_hash_old>.0
CA_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CA_PEM" 2>/dev/null | head -1 | awk '{print $NF}')
[ -n "$CA_HASH" ] || die "could not read the CA's hash"
push_ca() {
	cp "$CA_PEM" "$WORK/$CA_HASH.0"
	adb_ push "$WORK/$CA_HASH.0" "/data/local/tmp/$CA_HASH.0" >/dev/null
}

# The capture host: mitmdump in SOCKS5 mode. One out_jsonl for the whole
# sweep, split per app afterwards by the SNI.
CAPTURE=$OUT/capture.jsonl
rm -f "$CAPTURE"
mitmdump --mode socks5 --listen-host 0.0.0.0 --listen-port "$SOCKS5_PORT" \
	--set ssl_insecure=true --set connection_strategy=lazy \
	-s tools/phone/mitm_capture_addon.py --set out_jsonl="$CAPTURE" \
	>"$OUT/mitmdump.log" 2>&1 &
MITM_PID=$!
sleep 3
kill -0 $MITM_PID 2>/dev/null || die "mitmdump did not start (see $OUT/mitmdump.log)"

# The teardown runs whatever happens: the CA and its mounts go, the rules
# go, the forwarder dies. The phone is a shared resource.
cleanup() {
	step "tearing the chain down"
	for pkg in "${APPS[@]}"; do
		adb_ shell "su -c 'PKG=$pkg sh /data/local/tmp/setup_capture.sh stop'" >/dev/null 2>&1
	done
	kill $MITM_PID 2>/dev/null
	wait $MITM_PID 2>/dev/null
	# Whatever is left of the CA has to go too: a file on disk is a root
	# waiting to be mounted again.
	adb_ shell "su -c 'rm -f /data/local/tmp/*.0 /data/local/tmp/ca.pem'" >/dev/null 2>&1
	local mounted
	mounted=$(adb_ shell "su -c 'nsenter -t \$(pidof zygote64) -m -- ls /apex/com.android.conscrypt/cacerts 2>/dev/null | grep -c $CA_HASH'" 2>/dev/null | tr -d '\r')
	local rules
	rules=$(adb_ shell "su -c 'iptables -t nat -L OUTPUT -n 2>/dev/null | grep -c REDIRECT'" 2>/dev/null | tr -d '\r')
	local fwd
	fwd=$(adb_ shell "su -c 'pidof tproxyfwd || echo none'" 2>/dev/null | tr -d '\r')
	step "phone state: CA in the zygote view = ${mounted:-?}, REDIRECT rules = ${rules:-?}, forwarder = ${fwd:-?}"
}
trap cleanup EXIT INT TERM

# The launchers: an explicit activity wins, otherwise the package's own
# launcher. An app with no launcher (a service) is skipped with a note.
launch() {
	local pkg="$1" act="${2:-}"
	if [ -n "$act" ]; then
		# "am start -n" wants the full component: package/activity.
		case "$act" in
		*/*) ;;
		*) act="$pkg/$act" ;;
		esac
		adb_ shell am start -n "$act" >/dev/null 2>&1 && return 0
		# The activity may live in a split the package manager resolves but
		# "am start -n" cannot see: the launcher intent finds it anyway.
		adb_ shell am start -a android.intent.action.MAIN \
			-c android.intent.category.LAUNCHER "$pkg" >/dev/null 2>&1 && return 0
	fi
	# The package's own launcher.
	adb_ shell am start -a android.intent.action.MAIN \
		-c android.intent.category.LAUNCHER "$pkg" >/dev/null 2>&1 && return 0
	adb_ shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
}

for pkg in "${APPS[@]}"; do
	# A package may carry its activity: pkg#activity. The hash, not the
	# colon, because a URL has colons in it.
	act=""
	case "$pkg" in
	*#*) pkg="${pkg%%#*}"; act="${pkg#*#}" ;;
	esac
	step "=== $pkg ==="
	adb_ shell am force-stop "$pkg" >/dev/null 2>&1
	push_ca
	adb_ shell "su -c 'PKG=$pkg SOCKS5=$SOCKS5_HOST:$SOCKS5_PORT sh /data/local/tmp/setup_capture.sh start'" \
		>"$OUT/$pkg.setup.log" 2>&1
	if ! grep -q SETUP_DONE "$OUT/$pkg.setup.log"; then
		step "WARN: the chain did not start for $pkg (see $OUT/$pkg.setup.log)"
		continue
	fi
	launch "$pkg" "$act" || step "WARN: could not launch $pkg"
	sleep "$SECONDS_PER_APP"

	adb_ shell "su -c 'PKG=$pkg sh /data/local/tmp/setup_capture.sh stop'" >/dev/null 2>&1
	step "captured, chain stopped"

	if [ "$QUIC" = "1" ]; then
		# The QUIC capture: a pcap of the real thing, because the browser
		# only speaks QUIC to an origin it already knows.
		#
		# It runs with the chain stopped on purpose: the chain blocks the
		# app's QUIC (a REJECT on udp/443) so that a TCP ClientHello
		# exists at all, and a rejected packet never reaches the wire —
		# the capture would be empty.
		adb_ shell "su -c 'rm -f /sdcard/sweep-$pkg.pcap; tcpdump -i wlan0 -s 0 -w /sdcard/sweep-$pkg.pcap \"udp port 443\" >/data/local/tmp/tcpdump-$pkg.log 2>&1 &'" >/dev/null 2>&1
		sleep 2
		adb_ shell am force-stop "$pkg" >/dev/null 2>&1
		launch "$pkg" "$act" >/dev/null 2>&1
		sleep 3
		# The navigation that makes the client talk: without it a browser
		# sits on its home page and sends nothing.
		adb_ shell am start -a android.intent.action.VIEW -d "$QUIC_URL" >/dev/null 2>&1
		sleep "$SECONDS_PER_APP"
		adb_ shell "su -c 'pkill -x tcpdump'" >/dev/null 2>&1
		sleep 1
		adb_ pull "/sdcard/sweep-$pkg.pcap" "$OUT/$pkg.pcap" >/dev/null 2>&1
		adb_ shell rm -f "/sdcard/sweep-$pkg.pcap" >/dev/null 2>&1
		step "quic captured"
	fi
done

# The summary: one line per hello, with the library's own parser.
step "reading the capture"
if [ -s "$CAPTURE" ]; then
	go run ./cmd/hellofp "$CAPTURE" > "$OUT/hellofp.txt" 2>&1
	awk '/^SNI /{sni=$2} /^JA4 /{print sni, $2}' "$OUT/hellofp.txt" | sort -u > "$OUT/ja4.txt"
	cat "$OUT/ja4.txt"
fi
if [ "$QUIC" = "1" ]; then
	for pcap in "$OUT"/*.pcap; do
		[ -f "$pcap" ] || continue
		"$PYTHON" tools/ja4_from_pcap.py "$pcap" 2>/dev/null | sed "s|^|QUIC |"
	done | tee "$OUT/quic-ja4.txt"
fi

step "done: $OUT"
