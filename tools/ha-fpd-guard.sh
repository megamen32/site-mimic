#!/usr/bin/env bash
# Self-healing guard for the fpd routing in /etc/haproxy/haproxy.cfg.
#
# The stand's haproxy config is regenerated periodically by the deploy flow,
# which wipes hand-added blocks. This guard re-adds the fpd SNI route
# (test.auto-gram.ru -> 127.0.0.1:8478, send-proxy-v2) whenever it goes
# missing, validates the config and reloads haproxy. Run from the
# ha-fpd-guard.timer (every 10 minutes); safe to run manually.
set -u
CFG=/etc/haproxy/haproxy.cfg

grep -q be_fpd_test "$CFG" && exit 0

python3 - "$CFG" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
acl_anchor = "    default_backend be_local_https"
acl_add = """    acl sni_test_fpd req.ssl_sni -i test.auto-gram.ru
    use_backend be_fpd_test if sni_test_fpd
    default_backend be_local_https"""
backend_anchor = """backend be_local_https
    server nginx_https 127.0.0.1:8444 check"""
backend_add = backend_anchor + """

# fpd: live fingerprint display for test.auto-gram.ru (site-mimic stand)
backend be_fpd_test
    server fpd 127.0.0.1:8478 send-proxy-v2"""
assert acl_anchor in s and backend_anchor in s, "anchors missing from haproxy.cfg"
s = s.replace(acl_anchor, acl_add, 1).replace(backend_anchor, backend_add, 1)
open(p, "w").write(s)
EOF
haproxy -c -f "$CFG" >/dev/null || { echo "guard: generated config invalid, restoring backup"; cp "$CFG.bak-fpd2" "$CFG" 2>/dev/null || true; exit 1; }
systemctl reload haproxy
echo "$(date -Is) guard: fpd routing restored, haproxy reloaded"
