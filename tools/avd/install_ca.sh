#!/usr/bin/env bash
# Install the mitmproxy CA into an Android emulator's USER trust store.
#
# The user store is /data/misc/user/0/cacerts-added/<subject_hash_old>.0.
# Two details make the difference between "the app trusts me" and "the app
# does not":
#
#   * the file needs the SELinux context
#     u:object_r:system_security_cacerts_file:s0 — without it the platform
#     refuses to load the certificate;
#   * the trust store is read at boot, so the emulator has to REBOOT after
#     the CA is placed. Skipping the reboot is the classic reason for
#     "I installed the CA and Chrome still refuses".
#
# Usage:
#   ADB=~/Android/Sdk/platform-tools/adb SERIAL=emulator-5554 sh install_ca.sh
#
# Environment:
#   ADB        adb binary (default: adb)
#   SERIAL     emulator serial (default: the only attached device)
#   CA         mitm CA PEM (default: $HOME/.mitmproxy/mitmproxy-ca-cert.pem)
#   REBOOT     set to 0 to skip the reboot (only useful if the CA is
#              already in the store and was loaded at the last boot)
set -euo pipefail

ADB=${ADB:-adb}
SERIAL=${SERIAL:-}
CA=${CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}
REBOOT=${REBOOT:-1}

if [ -n "$SERIAL" ]; then
  ADB_ARGS=(-s "$SERIAL")
else
  ADB_ARGS=()
fi
adb_() { "$ADB" "${ADB_ARGS[@]}" "$@"; }

[ -f "$CA" ] || { echo "FATAL: no CA at $CA (run mitmdump once to generate it)"; exit 1; }

HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CA" -noout)
echo "CA subject_hash_old: $HASH"

adb_ root >/dev/null 2>&1 || true
sleep 2

TARGET=/data/misc/user/0/cacerts-added/$HASH.0
if adb_ shell "ls $TARGET" >/dev/null 2>&1; then
  echo "CA already in the user store — nothing to do"
else
  adb_ push "$CA" /sdcard/mitmca.pem >/dev/null
  adb_ shell "mkdir -p /data/misc/user/0/cacerts-added && \
    cp /sdcard/mitmca.pem $TARGET && \
    chmod 644 $TARGET && \
    chcon u:object_r:system_security_cacerts_file:s0 $TARGET && \
    rm -f /sdcard/mitmca.pem && ls -la $TARGET"
  echo "CA placed in the user store"
fi

if [ "$REBOOT" = "1" ]; then
  echo "rebooting the emulator so the trust store is re-read..."
  adb_ reboot >/dev/null 2>&1
  booted=""
  for _ in $(seq 1 60); do
    booted=$(adb_ shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [ "$booted" = "1" ] && break
    sleep 3
  done
  echo "boot_completed=${booted:-timeout}"
  adb_ root >/dev/null 2>&1 || true
  sleep 1
fi

adb_ shell "ls -la /data/misc/user/0/cacerts-added/" || true
echo "CA_READY"
