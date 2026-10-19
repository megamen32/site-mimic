#!/system/bin/sh
# appcap: route a target app's (or browser's) TCP traffic through the capture
# chain and clean up after it.
#
#   app TCP -> iptables nat REDIRECT :30886 -> tproxyfwd -> SOCKS5 -> mitmdump
#   app UDP/443 -> REJECT   (forces QUIC/HTTP3 down to TCP; without this the
#                              app speaks QUIC and no TCP ClientHello exists)
#
# The QUIC block is the single most important step: a modern app talks
# HTTP/3 over UDP/443 by default, and then there is no ClientHello to
# capture at all. The capture of ru.oneme.app looked "empty" for exactly
# this reason before the REJECT rule was added.
#
# Usage (root):
#   adb shell "su -c 'sh /data/local/tmp/setup_capture.sh start'"
#   adb shell "su -c 'sh /data/local/tmp/setup_capture.sh stop'"
#
# Environment:
#   PKG         package to capture (default ru.oneme.app)
#   APP_UID     its uid; auto-detected from the package when possible
#   SOCKS5      SOCKS5 upstream of the on-device forwarder (host:port)
#   LISTEN_PORT local port of the forwarder (default 30886)
#
# Files that must exist on the device:
#   /data/local/tmp/tproxyfwd   (build with: GOOS=linux GOARCH=arm64 \
#                                go build -o tproxyfwd ./cmd/tproxyfwd)
#   /data/local/tmp/c8750f0d.0  (the mitmproxy CA, Android PEM naming)
set -u

ACTION="${1:-start}"
PKG="${PKG:-ru.oneme.app}"
LISTEN_PORT="${LISTEN_PORT:-30886}"
SOCKS5="${SOCKS5:-127.0.0.1:1080}"

# The uid is the reliable selector: it also covers traffic of a browser
# (com.android.chrome) and of helper processes of the app.
APP_UID="${APP_UID:-}"
if [ -z "$APP_UID" ]; then
  APP_UID=$(stat -c %u "/data/data/$PKG" 2>/dev/null)
fi
if [ -z "$APP_UID" ]; then
  # "stop" must still run: the forwarder has to die and the leftover rules
  # have to go even if the package was uninstalled meanwhile.
  if [ "$ACTION" = "start" ]; then
    echo "FATAL: no uid for $PKG (set APP_UID)"; exit 1
  fi
  echo "WARN: no uid for $PKG — only the forwarder is stopped"
else
  echo "PKG=$PKG APP_UID=$APP_UID SOCKS5=$SOCKS5"
fi

cleanup() {
  if [ -n "$APP_UID" ]; then
    iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner "$APP_UID" ! -d 127.0.0.0/8 -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null
    iptables -D OUTPUT -p udp -m owner --uid-owner "$APP_UID" --dport 443 -j REJECT 2>/dev/null
  fi
  pkill -x tproxyfwd 2>/dev/null
}

case "$ACTION" in
  stop)
    cleanup
    echo "== remaining rules for uid $APP_UID =="
    iptables -t nat -L OUTPUT -n -v | grep "owner --uid-owner $APP_UID" || echo "none"
    iptables -L OUTPUT -n -v | grep "owner --uid-owner $APP_UID" || echo "none"
    echo CLEANED
    ;;
  start)
    echo "== cleanup of a previous run =="
    cleanup
    sleep 1

    echo "== CA mount (zygote view) =="
    sh /data/local/tmp/ca_mount.sh "$PKG"

    echo "== restart the app so it inherits the CA view =="
    am force-stop "$PKG"
    sleep 1

    echo "== iptables =="
    iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner "$APP_UID" ! -d 127.0.0.0/8 -j REDIRECT --to-ports "$LISTEN_PORT"
    iptables -A OUTPUT -p udp -m owner --uid-owner "$APP_UID" --dport 443 -j REJECT

    echo "== forwarder =="
    chmod 700 /data/local/tmp/tproxyfwd
    TPROXYFWD_LISTEN=127.0.0.1:"$LISTEN_PORT" TPROXYFWD_SOCKS5="$SOCKS5" \
      setsid /data/local/tmp/tproxyfwd </dev/null >>/data/local/tmp/tproxyfwd.log 2>&1 &
    sleep 2
    netstat -tln | grep -q "$LISTEN_PORT" && echo LISTENER_OK || echo FATAL_NO_LISTENER
    iptables -t nat -L OUTPUT -n -v | tail -4
    echo SETUP_DONE
    ;;
  *)
    echo "usage: setup_capture.sh start|stop"; exit 2 ;;
esac
