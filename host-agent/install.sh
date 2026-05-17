#!/usr/bin/env bash
# WardNode WF — Instalación del agente en el host
# Uso: sudo bash install.sh
# Ejecutar UNA SOLA VEZ. Después el servicio arranca automáticamente con el host.
set -euo pipefail

AGENT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wardnode-wf-agent.py"
AGENT_DEST="/opt/wardnode/wardnode-wf-agent.py"
IPV6_SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wardnode-set-ipv6.sh"
IPV6_SCRIPT_DEST="/opt/wardnode/wardnode-set-ipv6.sh"
SERVICE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wardnode-wf.service"
SOCKET_DIR="/run/wardnode"
TMPFILES_CONF="/etc/tmpfiles.d/wardnode.conf"
SERVICE_NAME="wardnode-wf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Ejecuta como root: sudo bash install.sh"
[ -f "$AGENT_SRC" ]   || err "No se encontró wardnode-wf-agent.py junto a este script"

# Limpiar restos de versiones anteriores
rm -f /etc/sudoers.d/wardnode-wf
userdel wardnode-wf 2>/dev/null || true
groupdel wardnode-wf 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════"
echo "  WardNode WF — Instalación del agente"
echo "═══════════════════════════════════════════════"
echo ""

# 1. UFW
if ! command -v ufw &>/dev/null; then
    warn "UFW no instalado — instalando..."
    apt-get update -qq && apt-get install -y -qq ufw
    ok "UFW instalado"
else
    ok "UFW encontrado"
fi

# 2. Directorio del socket
mkdir -p "$SOCKET_DIR"
chown root:root "$SOCKET_DIR"
chmod 755 "$SOCKET_DIR"
ok "Directorio $SOCKET_DIR configurado"

# 3. tmpfiles.d para que /run/wardnode persista entre reinicios
echo "d $SOCKET_DIR 0755 root root -" > "$TMPFILES_CONF"
ok "tmpfiles.d configurado ($TMPFILES_CONF)"

# 4. Copiar agente
mkdir -p /opt/wardnode
cp "$AGENT_SRC" "$AGENT_DEST"
chown root:root "$AGENT_DEST"
chmod 755 "$AGENT_DEST"
ok "Agente instalado en $AGENT_DEST"

# 5b. Script helper IPv6
cp "$IPV6_SCRIPT_SRC" "$IPV6_SCRIPT_DEST"
chown root:root "$IPV6_SCRIPT_DEST"
chmod 755 "$IPV6_SCRIPT_DEST"
ok "Script IPv6 instalado en $IPV6_SCRIPT_DEST"

# 5. Servicio systemd
cp "$SERVICE_SRC" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Esperar hasta 5s para que el socket aparezca
for i in $(seq 1 10); do
    [ -S "${SOCKET_DIR}/${SERVICE_NAME}.sock" ] && break
    sleep 0.5
done

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Servicio $SERVICE_NAME activo"
else
    warn "El servicio no arrancó — revisa: journalctl -u $SERVICE_NAME -n 30"
fi

if [ -S "${SOCKET_DIR}/${SERVICE_NAME}.sock" ]; then
    ok "Socket disponible: ${SOCKET_DIR}/${SERVICE_NAME}.sock"
else
    warn "Socket no encontrado todavía — puede tardar unos segundos"
fi

echo ""
echo "═══════════════════════════════════════════════"
ok "Instalación completada"
echo ""
echo "  Estado del servicio:"
systemctl status "$SERVICE_NAME" --no-pager -l | head -20
echo ""
echo "  Próximos pasos:"
echo "  1. Activa el módulo 'WardNode WF' desde el panel"
echo "═══════════════════════════════════════════════"
echo ""
