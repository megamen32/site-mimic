#!/usr/bin/env bash
# Self-healing guard for the fpd routing in /etc/haproxy/haproxy.cfg.
#
# The stand's haproxy config is regenerated periodically by an automated
# deploy, which wipes hand-added blocks. This guard re-adds the fpd SNI route
# (the stand hostname -> 127.0.0.1:8478, send-proxy-v2) whenever it goes
# missing, validates the config and reloads haproxy. Run from the
# ha-fpd-guard.timer (every 10 minutes); safe to run manually.
#
# STAND_HOST: hostname routed to fpd (default: the public site-mimic stand).
# CFG:        haproxy config to guard (default: the system one).
#
# The block is installed once and then left alone: on a host that already
# has it, the hostname is not re-written. Move the stand to another name by
# editing the existing ACL line by hand.
set -u
CFG=${CFG:-/etc/haproxy/haproxy.cfg}
STAND_HOST=${STAND_HOST:-test.auto-gram.ru}

case "$STAND_HOST" in
  '' | *[!A-Za-z0-9._-]*)
    echo "guard: invalid STAND_HOST: $STAND_HOST"
    exit 1
    ;;
esac

grep -q be_fpd_test "$CFG" && exit 0

python3 - "$CFG" "$STAND_HOST" <<'EOF'
import sys
p, host = sys.argv[1], sys.argv[2]
s = open(p).read()
acl_anchor = "    default_backend be_local_https"
acl_add = f"""    acl sni_test_fpd req.ssl_sni -i {host}
    use_backend be_fpd_test if sni_test_fpd
    default_backend be_local_https"""
backend_anchor = """backend be_local_https
    server nginx_https 127.0.0.1:8444 check"""
backend_add = backend_anchor + f"""

# fpd: live fingerprint display for {host} (site-mimic stand)
backend be_fpd_test
    server fpd 127.0.0.1:8478 send-proxy-v2"""
assert acl_anchor in s and backend_anchor in s, "anchors missing from haproxy.cfg"
s = s.replace(acl_anchor, acl_add, 1).replace(backend_anchor, backend_add, 1)
open(p, "w").write(s)
EOF
haproxy -c -f "$CFG" >/dev/null || { echo "guard: generated config invalid, restoring backup"; cp "$CFG.bak-fpd2" "$CFG" 2>/dev/null || true; exit 1; }
systemctl reload haproxy
echo "$(date -Is) guard: fpd routing restored for $STAND_HOST, haproxy reloaded"
