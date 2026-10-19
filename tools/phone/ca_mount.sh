#!/system/bin/sh
# appcap: install the mitmproxy CA into the Android system trust store so
# that NEW app processes trust it.
#
# Android 14+ keeps the system CAs in the conscrypt APEX, and the platform
# trust store is not what the browser trusts (see README.md, "Chrome Root
# Store"). The bind-mount must be visible in the ZYGOTE mount namespace:
# per-pid mounts and `su -mm` mounts are NOT inherited by freshly forked
# apps, so a restart of the app loses the trust.
#
# Inputs (pushed to /data/local/tmp before the run):
#   <subject_hash_old>.0   — the mitmproxy CA in Android PEM naming
#                           (mitmproxy-ca-cert.pem -> <subject_hash_old>.0)
#
# Usage (root):
#   adb shell "su -c 'sh /data/local/tmp/ca_mount.sh <package>'"
#
# <package> is optional; the CA is mounted into the zygote view anyway, and
# the package is only used to patch an already running process.
PKG="${1:-}"

mkdir -p /data/local/tmp/cacerts
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null
cp /data/local/tmp/*.0 /data/local/tmp/cacerts/ 2>/dev/null
chown root:root /data/local/tmp/cacerts/*
chmod 644 /data/local/tmp/cacerts/*
chcon -R u:object_r:system_security_cacerts_file:s0 /data/local/tmp/cacerts

mount_into() {
  # toybox on Android 14+ needs the "--" separator before the mount args.
  nsenter -t "$1" -m -- mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null
}

# zygote namespaces: every app forked AFTER this inherits the CA view
for Z in $(pidof zygote64; pidof zygote); do mount_into "$Z"; done
# already-running target app: patch its live namespace too
if [ -n "$PKG" ]; then
  for P in $(pidof "$PKG"); do mount_into "$P"; done
fi

Z=$(pidof zygote64 | awk '{print $1}')
echo "CA files in zygote view: $(nsenter -t "$Z" -m -- ls /apex/com.android.conscrypt/cacerts | wc -l)"
echo CA_MOUNTED
