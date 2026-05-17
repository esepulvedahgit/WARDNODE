#!/usr/bin/env bash
# wardnode-set-ipv6.sh — Activa o desactiva IPv6 en UFW (configuración global)
# Uso: sudo /opt/wardnode/wardnode-set-ipv6.sh yes|no
set -euo pipefail

VAL="${1:-}"
if [[ "$VAL" != "yes" && "$VAL" != "no" ]]; then
    echo "Uso: $0 yes|no" >&2
    exit 1
fi

if [ ! -f /etc/default/ufw ]; then
    echo "No se encontró /etc/default/ufw" >&2
    exit 1
fi

sed -i "s/^IPV6=.*/IPV6=${VAL}/" /etc/default/ufw
/usr/sbin/ufw reload
echo "IPv6 ${VAL} — UFW recargado."
