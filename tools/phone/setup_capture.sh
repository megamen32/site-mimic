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
#   DNS_HIJACK  set to 1 to force DNS to 1.1.1.1 (routers that hijack DNS
#               break the capture; the app then resolves the wrong host)
#   ADB_KEEPALIVE  set to 1 to keep the adb port reachable (some stock
#               Android builds DROP inbound adb when the USB host sleeps)
#   ADB_PORT    the adb port for ADB_KEEPALIVE (default 5555)
#   PURGE_BINARIES  set to 1 to delete the forwarder binary and its log on
#               stop (the CA files are always removed)
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
DNS_HIJACK="${DNS_HIJACK:-0}"
ADB_KEEPALIVE="${ADB_KEEPALIVE:-0}"
ADB_PORT="${ADB_PORT:-5555}"
PURGE_BINARIES="${PURGE_BINARIES:-0}"

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
  if [ "$DNS_HIJACK" = "1" ]; then
    iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination 1.1.1.1 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1 2>/dev/null
  fi
  # The adb keepalive rule is an inbound ACCEPT — it must not survive the
  # capture: the phone is a shared device and the rule outlives the work.
  if [ "$ADB_KEEPALIVE" = "1" ]; then
    iptables -D INPUT -p tcp --dport "$ADB_PORT" -j ACCEPT 2>/dev/null
  fi
  # leftovers of a TPROXY-based leg (an older capture shape) — harmless but
  # they keep a fwmark route alive, so drop them too.
  iptables -t mangle -D OUTPUT -m owner --uid-owner "$APP_UID" -p tcp -j MARK --set-mark 31/0x7f 2>/dev/null
  iptables -t mangle -D PREROUTING -p tcp -m mark --mark 31/0x7f -j TPROXY --on-port "$LISTEN_PORT" --tproxy-mark 31/0x7f 2>/dev/null
  ip rule del fwmark 31/0x7f table 100 2>/dev/null
  ip route del local default dev lo table 100 2>/dev/null
  pkill -x tproxyfwd 2>/dev/null
}

# Unmount the CA bind-mount again.
#
# ca_mount.sh mounts /data/local/tmp/cacerts over the conscrypt APEX
# directory in the zygote namespace (and in the running app), and every
# `start` mounts it once more — the mounts stack up, so a single umount
# only peels off the top layer and the CA stays in the system trust store
# of every process forked after the capture.
#
# The system trust store is not a mount point of its own here, so
# unmounting until it fails stops exactly at our own layers.
unmount_ca() {
  for P in $(pidof zygote64; pidof zygote; pidof "$PKG"); do
    while nsenter -t "$P" -m -- umount /apex/com.android.conscrypt/cacerts 2>/dev/null; do :; done
  done
}

case "$ACTION" in
  stop)
    cleanup
    echo "== CA bind-mount =="
    unmount_ca
    echo "== CA files =="
    # The CA must not survive the capture: a leftover <hash>.0 in
    # /data/local/tmp is a mitm root waiting to be mounted again, and on a
    # shared phone that is a hole you do not want to leave open.
    rm -rf /data/local/tmp/cacerts 2>/dev/null
    rm -f /data/local/tmp/*.0 2>/dev/null
    echo "CA files left: $(ls /data/local/tmp/*.0 2>/dev/null | wc -l)"
    if [ "$PURGE_BINARIES" = "1" ]; then
      rm -f /data/local/tmp/tproxyfwd /data/local/tmp/tproxyfwd.log 2>/dev/null
      echo "forwarder binary removed"
    fi
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
    if [ "$DNS_HIJACK" = "1" ]; then
      # Some office routers hijack DNS for part of the zone. The app then
      # talks to the wrong host and the capture looks like an app bug.
      iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 1.1.1.1
      iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1
      echo "dns hijack: forced to 1.1.1.1"
    fi
    if [ "$ADB_KEEPALIVE" = "1" ]; then
      # Stock Android DROPs inbound adb from non-loopback; when the USB host
      # sleeps, adb dies mid-capture and the capture is lost.
      iptables -C INPUT -p tcp --dport "$ADB_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp --dport "$ADB_PORT" -j ACCEPT
      echo "adb keepalive: tcp/$ADB_PORT accepted"
    fi

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
