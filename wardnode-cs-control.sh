#!/usr/bin/env bash
# wardnode-cs-control.sh — Controla servicios CrowdSec (crowdsec + bouncer)
# Uso: sudo /opt/wardnode/wardnode-cs-control.sh <action> <target>
# action : start | stop | enable | disable | restart
# target : crowdsec | bouncer
set -euo pipefail

ACTION="${1:-}"
TARGET="${2:-}"

case "$ACTION" in
  start|stop|enable|disable|restart) ;;
  *) echo "Acción inválida: '$ACTION'" >&2; exit 1 ;;
esac

case "$TARGET" in
  crowdsec) SVC="crowdsec" ;;
  bouncer)  SVC="crowdsec-firewall-bouncer" ;;
  *) echo "Servicio inválido: '$TARGET'" >&2; exit 1 ;;
esac

systemctl "$ACTION" "$SVC"
echo "${ACTION} ${SVC}: OK"
