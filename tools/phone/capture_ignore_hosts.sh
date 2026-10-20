#!/system/bin/sh
# The hosts whose TLS must NOT be decrypted during a capture.
#
# Some hosts pin their certificate OUTSIDE the app bundle: an OIDC browser,
# Google Play services, an obfuscated transport. A system-CA mount or an APK
# patch cannot cover them, and decrypting them anyway is what produces the
# "TLS handshake failed" spam and the "we were MITM'd" telemetry.
#
# The fix is to TUNNEL them (pass the bytes through untouched) instead of
# intercepting them — mitmdump's --ignore-hosts does exactly that: the
# connection is proxied, the payload is not decrypted.
#
# Usage:
#   IGNORE_HOSTS=$(sh capture_ignore_hosts.sh)
#   mitmdump ... --ignore-hosts "$IGNORE_HOSTS"
#
# Override with the CAPTURE_IGNORE_HOSTS environment variable. The list is
# a regex in mitmproxy's syntax (alternation of escaped host names).
#
# Do NOT add the target's own API hosts here: a decrypted request to the
# host you are profiling is the whole point of the capture.
set -u

DEFAULT='(auth\.gid\.ru|sentry-prod\.gid\.team|api\.vigo\.tech|pic\.rtbcdn\.ru|firebaseremoteconfig\.googleapis\.com|firebase-settings\.crashlytics\.com|crashlyticsreports-pa\.googleapis\.com|firebaselogging-pa\.googleapis\.com)'

printf '%s' "${CAPTURE_IGNORE_HOSTS:-$DEFAULT}"
