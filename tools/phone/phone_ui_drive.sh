#!/usr/bin/env bash
# Drive a rooted phone from the host: tap, tap-by-node, screenshots, dumps.
#
# A capture of a real client is only worth something if the client actually
# did something. Driving the UI by hand over `adb shell input` is the
# reliable way to reach a specific state (open a video, press a button) and
# keep the wire capture aligned with a known action.
#
# Usage:
#   phone_ui_drive.sh wsize                 # current resolution
#   phone_ui_drive.sh tap <x> <y>            # tap in device pixels
#   phone_ui_drive.sh tap% <pct> <pct>       # tap in percent of the screen
#   phone_ui_drive.sh tapid <substr> [...]   # tap the centre of a UI node
#   phone_ui_drive.sh act <text>             # log a timestamped action marker
#   phone_ui_drive.sh shot <name>            # screencap -> $OUT_DIR/<name>.png
#   phone_ui_drive.sh uidump                # uiautomator dump -> $OUT_DIR/ui.xml
#   phone_ui_drive.sh back                  # keyevent BACK
#   phone_ui_drive.sh key <keycode>         # keyevent <keycode>
#
# Environment:
#   ADB       adb binary (default: adb)
#   SERIAL    device serial (default: single attached device)
#   OUT_DIR   where shots/dumps/logs go (default: ./phone-capture)
#   LEASE_ID  lease id of the shared device, if your adb wrapper needs it
set -euo pipefail

ADB=${ADB:-adb}
SERIAL=${SERIAL:-}
OUT_DIR=${OUT_DIR:-phone-capture}
HERE=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$OUT_DIR"
ALOG="$OUT_DIR/phone_actions.log"

if [ -n "$SERIAL" ]; then
  ADB_ARGS=(-s "$SERIAL")
else
  ADB_ARGS=()
fi
adb_() { "$ADB" "${ADB_ARGS[@]}" "$@"; }

screen_size() {
  adb_ shell wm size | grep -oE '[0-9]+x[0-9]+' | tail -1 | tr -d '\r'
}

log() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$ALOG"; }

cmd=${1:-}
[ $# -gt 0 ] && shift || true

case "$cmd" in
wsize)
  W=$(screen_size); echo "${W%x*} x ${W#*x}"
  ;;
tap)
  adb_ shell input tap "$1" "$2"
  log "tap $1 $2"
  ;;
tap%)
  W=$(screen_size); WX=${W%x*}; WY=${W#*x}
  X=$((WX * $1 / 100)); Y=$((WY * $2 / 100))
  adb_ shell input tap "$X" "$Y"
  log "tap ${1}% ${2}% ($X,$Y)"
  ;;
tapid)
  adb_ shell uiautomator dump /data/local/tmp/ui.xml >/dev/null 2>&1
  adb_ pull /data/local/tmp/ui.xml "$OUT_DIR/ui.xml" >/dev/null 2>&1
  XY=$(python3 "$HERE/phone_ui_find.py" "$@" --file "$OUT_DIR/ui.xml")
  if [ "$XY" = "NOTFOUND" ]; then
    log "NOTFOUND: $*"
    exit 1
  fi
  adb_ shell input tap $XY
  log "tapid $* @ $XY"
  ;;
act)
  log "ACTION $*"
  ;;
shot)
  adb_ shell screencap -p /data/local/tmp/shot.png >/dev/null 2>&1
  adb_ pull /data/local/tmp/shot.png "$OUT_DIR/$1.png" >/dev/null 2>&1
  log "shot $1"
  echo "$OUT_DIR/$1.png"
  ;;
uidump)
  adb_ shell uiautomator dump /data/local/tmp/ui.xml >/dev/null 2>&1
  adb_ pull /data/local/tmp/ui.xml "$OUT_DIR/ui.xml" >/dev/null 2>&1
  wc -c < "$OUT_DIR/ui.xml"
  ;;
back)
  adb_ shell input keyevent 4
  log "back"
  ;;
key)
  adb_ shell input keyevent "$1"
  log "key $1"
  ;;
*)
  sed -n '2,20p' "$0"
  exit 2
  ;;
esac
