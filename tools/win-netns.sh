#!/usr/bin/env bash
# Isolated netns with a Windows-like TCP personality for site-mimic probes.
#
#   tools/win-netns.sh up     create netns "mimic-win" (macvlan, own LAN IP,
#                             no TCP timestamps, wscale 8, TTL 128 — the
#                             Windows SYN option SET without touching the
#                             host sysctls)
#   tools/win-netns.sh down   remove it
#
# Run probes inside:
#   ip netns exec mimic-win ./examples/.../stand-probe https://test.auto-gram.ru/fp
#
# NOTE: the SYN option SET matches Windows (mss/wscale/sack, no TS) but the
# option ORDER stays the Linux kernel order (mss,sack,wscale vs Windows'
# mss,wscale,sack). Per-connection order control needs raw-SYN — roadmap.
set -euo pipefail
IFACE=${IFACE:-enp28s0f2np2}
NS=${NS:-mimic-win}
NS_IP=${NS_IP:-192.168.2.150/24}
GW=${GW:-192.168.2.1}

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }; }

case "${1:-up}" in
up)
    need_root
    ip netns add "$NS"
    ip link add "$NS-eth" link "$IFACE" type macvlan mode bridge
    ip link set "$NS-eth" netns "$NS"
    ip -n "$NS" link set "$NS-eth" up
    ip -n "$NS" addr add "$NS_IP" dev "$NS-eth"
    ip -n "$NS" route add default via "$GW"
    # Windows-like TCP personality inside the namespace
    ip netns exec "$NS" sysctl -qw net.ipv4.tcp_timestamps=0
    ip netns exec "$NS" sysctl -qw "net.ipv4.tcp_rmem=4096 65536 8388608"
    ip netns exec "$NS" sysctl -qw net.ipv4.ip_default_ttl=128
    # netns DNS: /etc/resolv.conf points at systemd-resolved on the host lo,
    # pin the stand host instead (harmless for the host itself)
    grep -q "test.auto-gram.ru" /etc/hosts || \
        echo "95.165.165.65 test.auto-gram.ru" >> /etc/hosts
    echo "ready: ip netns exec $NS <probe command>"
    ;;
down)
    need_root
    ip netns del "$NS" 2>/dev/null || true
    ;;
rawsyn)
    # Rebuild the SYN option ORDER to Windows (mss,wscale,sack) on the fly:
    # NFQUEUE grabs outgoing SYNs, tools/rawsyn rewrites them, everything
    # else passes through (--queue-bypass keeps traffic alive if it dies).
    need_root
    ip netns exec "$NS" iptables -A OUTPUT -p tcp --dport 443 --syn \
        -j NFQUEUE --queue-num 100 --queue-bypass
    echo "rawsyn armed; starting rewriter (Ctrl-C to stop, then: $0 rawsyn-off)"
    ( cd "$(dirname "$0")/rawsyn" && go build -o /tmp/rawsyn . )
    ip netns exec "$NS" /tmp/rawsyn -queue 100
    ;;
rawsyn-off)
    need_root
    ip netns exec "$NS" iptables -D OUTPUT -p tcp --dport 443 --syn \
        -j NFQUEUE --queue-num 100 --queue-bypass 2>/dev/null || true
    echo "rawsyn disarmed"
    ;;
status)
    ip netns list | grep "$NS" || echo "no $NS"
    ip netns exec "$NS" sysctl net.ipv4.tcp_timestamps net.ipv4.ip_default_ttl 2>/dev/null || true
    ;;
*)
    echo "usage: $0 {up|down|rawsyn|rawsyn-off|status}"; exit 1
    ;;
esac
