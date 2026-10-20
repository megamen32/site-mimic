#!/usr/bin/env bash
# Build a CAPTURE build of an Android app: embed the mitmproxy CA in the app's
# own trust configuration, so the app trusts the capture without the PHONE's
# system trust store being touched.
#
# Why this beats a system CA:
#   * the device's platform trust store stays clean — an anti-fraud client
#     that enumerates the system CAs finds nothing to report;
#   * no zygote-namespace bind-mount is needed, so nothing is left behind
#     on a shared device;
#   * the capture CA lives and dies with the app bundle.
#
# What the patch does:
#   1. res/xml/network_security_config.xml — the base-config trust-anchors
#      gain <certificates src="@raw/capcapture"/>, with the CA embedded as
#      res/raw/capcapture.pem.
#   2. (optional) EXTRA_PEMS — PEM files bundled in res/raw whose client
#      pins through its own SSLSocketFactory, bypassing the network security
#      config. The capture CA is APPENDED to them (not substituted), so the
#      original anchors survive and the app still works with the capture off.
#   3. Nothing else is touched: no smali edits. The result is re-signed
#      with a local debug key.
#
# Consequences of re-signing (know them before you ship the build):
#   * the signature no longer matches the store's — store auto-update stops
#     working, so version bumps must come through this pipeline;
#   * app-link verification usually breaks, so start the app by explicit
#     component instead of a plain VIEW intent.
#
# Usage:
#   build_patched_apk.sh <store.apk> [out.apk]
#
# Environment:
#   CAPTURE_CA   CA to embed (default: $HOME/.mitmproxy/mitmproxy-ca-cert.pem)
#   EXTRA_PEMS   space-separated res/raw paths whose bundled PEMs should
#                also carry the CA (e.g. "global_sign.pem remote_config.pem")
#   TOOLS_DIR    where apktool.jar / uber-apk-signer.jar are cached
#                (default: $HOME/.cache/site-mimic)
#   KEEP_WORK    set to 1 to keep the decoded tree for debugging
set -euo pipefail

IN=${1:?usage: build_patched_apk.sh <store.apk> [out.apk]}
OUT=${2:-$(dirname "$IN")/patched-capture.apk}
CA=${CAPTURE_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}
TOOLS_DIR=${TOOLS_DIR:-$HOME/.cache/site-mimic}
EXTRA_PEMS=${EXTRA_PEMS:-}

APKTOOL_VER=2.11.1
SIGNER_VER=1.3.0

mkdir -p "$TOOLS_DIR"
[ -f "$TOOLS_DIR/apktool.jar" ] || curl -sSL -m 180 -o "$TOOLS_DIR/apktool.jar" \
  "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar"
[ -f "$TOOLS_DIR/uber-apk-signer.jar" ] || curl -sSL -m 120 -o "$TOOLS_DIR/uber-apk-signer.jar" \
  "https://github.com/patrickfav/uber-apk-signer/releases/download/v${SIGNER_VER}/uber-apk-signer-${SIGNER_VER}.jar"

[ -f "$CA" ] || { echo "FATAL: capture CA not found: $CA"; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/apk-capture-patch.XXXXXX")
cleanup() {
  st=$?
  if [ "$st" -ne 0 ] && [ -f "$WORK/build.log" ]; then
    cp "$WORK/build.log" "${TOOLS_DIR}/last-build-failed.log" || true
  fi
  [ "${KEEP_WORK:-0}" = "1" ] || rm -rf "$WORK"
  exit "$st"
}
trap cleanup EXIT

echo "=== decode ==="
java -jar "$TOOLS_DIR/apktool.jar" d -f --no-src -o "$WORK/app" "$IN" >/dev/null

PKG=$(grep -oE 'package="[^"]+"' "$WORK/app/AndroidManifest.xml" | head -1 | cut -d'"' -f2 || true)
echo "package: ${PKG:-unknown}"

CFG=$WORK/app/res/xml/network_security_config.xml
[ -f "$CFG" ] || { echo "FATAL: no network_security_config.xml in APK"; exit 1; }

echo "=== patch: embed capture CA in trust-anchors ==="
mkdir -p "$WORK/app/res/raw"
cp "$CA" "$WORK/app/res/raw/capcapture.pem"

# apktool can drop custom attribute DECLARATIONS on decode; aapt2 then fails
# with "attribute <name> not found". Start with an empty declaration file and
# let the rebuild loop below fill it in.
ATTRS_FILE="$WORK/app/res/values/zz-capture-patch-attrs.xml"
cat > "$ATTRS_FILE" <<'XMLEOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
</resources>
XMLEOF

if ! grep -q 'capcapture' "$CFG"; then
  python3 - "$CFG" <<'PY'
import re
import sys

path = sys.argv[1]
xml = open(path).read()
anchor = '<certificates src="@raw/capcapture" />'

if "<base-config>" in xml and "trust-anchors" in xml:
    xml = xml.replace("<trust-anchors>", "<trust-anchors>\n            " + anchor, 1)
elif "<base-config" in xml:
    xml = re.sub(
        r"<base-config([^>]*)/>",
        r"<base-config\1>\n        <trust-anchors>\n            "
        r'<certificates src="system" />\n            ' + anchor
        + "\n        </trust-anchors>\n    </base-config>",
        xml, count=1)
    if anchor not in xml:
        xml = re.sub(
            r"(<base-config[^>/]*>)",
            r"\1\n        <trust-anchors>\n            "
            r'<certificates src="system" />\n            ' + anchor
            + "\n        </trust-anchors>",
            xml, count=1)
else:
    xml = xml.replace(
        "<network-security-config>",
        "<network-security-config>\n    <base-config>\n        <trust-anchors>\n            "
        '<certificates src="system" />\n            ' + anchor
        + "\n        </trust-anchors>\n    </base-config>",
        1)

open(path, "w").write(xml)
print("config patched")
PY
fi
grep -c capcapture "$CFG"

if [ -n "$EXTRA_PEMS" ]; then
  echo "=== patch: append capture CA to extra bundled PEMs ==="
  matched=0
  for pem in $EXTRA_PEMS; do
    target="$WORK/app/res/raw/$pem"
    if [ -f "$target" ]; then
      if ! grep -q 'capcapture' "$target"; then
        printf '\n' >> "$target"
        cat "$CA" >> "$target"
      fi
      matched=$((matched + 1))
    else
      echo "WARN: $pem not found in res/raw — skipped"
    fi
  done
  echo "PEM patch applied to $matched file(s)"
fi

echo "=== rebuild ==="
build_ok=0
for attempt in 1 2 3 4 5 6; do
  if java -jar "$TOOLS_DIR/apktool.jar" b --use-aapt2 -o "$WORK/unsigned.apk" "$WORK/app" >"$WORK/build.log" 2>&1; then
    build_ok=1
    break
  fi
  # "attribute <name> (aka <pkg>:<name>) not found" — re-declare it broadly and
  # retry. android:* attributes are NOT redeclared: those are a human problem.
  MISSING=$(grep -oE 'attribute [A-Za-z0-9_]+ \(aka [A-Za-z0-9_.]+:[A-Za-z0-9_]+\)' "$WORK/build.log" | head -1)
  NAME=$(echo "$MISSING" | awk '{print $2}')
  AKA=$(echo "$MISSING" | grep -oE 'aka [A-Za-z0-9_.]+:' | cut -d' ' -f2)
  if [ -z "$NAME" ] || [ -z "$AKA" ] || [ "$AKA" = "android:" ]; then
    echo "FATAL: unfixable aapt2 error (attempt $attempt):"
    tail -8 "$WORK/build.log"
    exit 1
  fi
  echo "aapt2 missing app attr '$NAME' — re-declaring and retrying"
  grep -q "\"$NAME\"" "$ATTRS_FILE" || sed -i "s#</resources>#    <attr name=\"$NAME\" format=\"reference|float|integer|dimension|boolean|color|string\" />\n</resources>#" "$ATTRS_FILE"
done
[ "$build_ok" = 1 ] || { echo "FATAL: build still failing after attr fixes"; tail -8 "$WORK/build.log"; exit 1; }

echo "=== align + sign (v1+v2+v3, local debug key) ==="
rm -rf "$WORK/signed"
mkdir -p "$WORK/signed"
java -jar "$TOOLS_DIR/uber-apk-signer.jar" -a "$WORK/unsigned.apk" --out "$WORK/signed" --allowResign >/dev/null 2>&1
mv "$WORK"/signed/*-aligned-*signed.apk "$OUT" 2>/dev/null || mv "$WORK"/signed/*.apk "$OUT"
ls -la "$OUT" | awk '{print $5, $9}'
echo "OK: $OUT"
echo "reminder: a re-signed app does not auto-update from the store any more."
