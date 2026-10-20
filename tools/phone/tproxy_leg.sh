#!/system/bin/sh
# Fallback capture leg for a phone that is NOT on USB: the phone opens a
# reverse SSH tunnel to the capture host, so the capture host's mitmdump is
# reachable at 127.0.0.1:<PORT> on the phone.
#
# Why this exists: the normal leg is `adb reverse tcp:<port> tcp:<port>`,
# which needs a working USB/adb link. When the phone is on its own network
# (or the USB host sleeps), the only way back to the capture host is a tunnel
# the phone dials itself — with Termux ssh this is a plain reverse forward.
#
# The script refuses to run while USB is attached: in that case adb reverse
# is the leg, and raising a second one on the same port just makes the
# capture path ambiguous.
#
# Environment:
#   SSH_HOST      capture host (default: 127.0.0.1 — set it to the real one)
#   SSH_PORT      SSH port on the capture host (default: 22)
#   SSH_USER      user on the capture host (default: root)
#   SSH_KEY       private key path (default: $PREFIX/home/.ssh/id_ed25519)
#   CAPTURE_PORT  port of the capture proxy on the capture host (default: 31896)
#   TERMUX_PREFIX Termux prefix (default: /data/data/com.termux/files/usr)
#   USB_PATH      sysfs node that reports USB state (default:
#                 /sys/class/power_supply/usb/online)
#
# Start it under Termux, detached:
#   nohup sh tproxy_leg.sh >/data/local/tmp/tproxy_leg.log 2>&1 &
set -u

SSH_HOST=${SSH_HOST:-127.0.0.1}
SSH_PORT=${SSH_PORT:-22}
SSH_USER=${SSH_USER:-root}
CAPTURE_PORT=${CAPTURE_PORT:-31896}
TERMUX_PREFIX=${TERMUX_PREFIX:-/data/data/com.termux/files/usr}
USB_PATH=${USB_PATH:-/sys/class/power_supply/usb/online}
SSH_KEY=${SSH_KEY:-$TERMUX_PREFIX/home/.ssh/id_ed25519}

if [ -r "$USB_PATH" ] && [ "$(cat "$USB_PATH" 2>/dev/null)" = "1" ]; then
  echo "USB attached — adb reverse is the leg; not raising the ssh leg"
  exit 0
fi

if [ ! -x "$TERMUX_PREFIX/bin/ssh" ]; then
  echo "no ssh under $TERMUX_PREFIX — install Termux and run: pkg install openssh"
  exit 1
fi

# Replace a previous leg on the same port; a stale forward silently eats the
# connections and the capture stays empty.
pkill -f "ssh.*127.0.0.1:$CAPTURE_PORT:127.0.0.1:$CAPTURE_PORT" 2>/dev/null
sleep 1

exec "$TERMUX_PREFIX/bin/ssh" -nNT \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=2 \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile="$TERMUX_PREFIX/home/.ssh/known_hosts" \
  -o LogLevel=ERROR \
  -i "$SSH_KEY" \
  -p "$SSH_PORT" \
  "$SSH_USER@$SSH_HOST" \
  -L "127.0.0.1:$CAPTURE_PORT:127.0.0.1:$CAPTURE_PORT"
