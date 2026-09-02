#!/usr/bin/env bash
# Windows-like TCP preset for the host kernel (sysctl).
#
# What Windows SYNs look like vs stock Linux (measured 2026-09-01, see
# docs/fingerprint-matrix.md):
#
#   Windows 11: win 64240, options [mss 1460, nop, wscale 8, nop, nop, sackOK]  (no timestamps)
#   Linux:      win 64240, options [mss 1460, sackOK, TS val…, nop, wscale 7]
#
# The two remaining tells are TCP timestamps (off in our Windows reference)
# and the window-scale factor (8 vs 7 — driven by the maximum receive
# buffer). Both are kernel sysctls; they are HOST-WIDE and affect every
# connection this machine makes.
#
# Usage:
#   sudo ./win-tcp-preset.sh apply    # stamp Windows-like values
#   sudo ./win-tcp-preset.sh revert   # restore Ubuntu defaults
#   sudo ./win-tcp-preset.sh status
set -u

PRESET_FILE=/etc/sysctl.d/60-win-tcp-mimic.conf

apply() {
  cat > "$PRESET_FILE" <<'EOF'
# site-mimic: Windows-like TCP presentation (see tools/win-tcp-preset.sh)
# no TCP timestamps in SYN (Windows 11 reference: no TS option)
net.ipv4.tcp_timestamps = 0
# smaller max receive buffer -> kernel advertises window scale 8 (Windows: 8;
# stock Ubuntu with 6 MB max advertises 7). Empirically 8 MiB max -> wscale 8.
net.ipv4.tcp_rmem = 4096 65536 8388608
net.ipv4.tcp_wmem = 4096 16384 4194304
EOF
  sysctl -p "$PRESET_FILE"
  echo "applied: $PRESET_FILE"
}

revert() {
  rm -f "$PRESET_FILE"
  sysctl -w net.ipv4.tcp_timestamps=1
  sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
  sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"
  echo "reverted to Ubuntu defaults"
}

status() {
  sysctl net.ipv4.tcp_timestamps net.ipv4.tcp_rmem net.ipv4.tcp_wmem
}

case "${1:-status}" in
  apply)  apply ;;
  revert) revert ;;
  status) status ;;
  *) echo "usage: $0 {apply|revert|status}" >&2; exit 2 ;;
esac
