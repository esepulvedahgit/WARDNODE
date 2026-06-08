#!/usr/bin/env bash
# WardNode — Instalación del agente WF en el host
# Uso: sudo bash install.sh   — Idempotente.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$SCRIPT_DIR/wardnode-wf-agent.py"
AGENT_DEST="/opt/wardnode/wardnode-wf-agent.py"
IPV6_SCRIPT_SRC="$SCRIPT_DIR/wardnode-set-ipv6.sh"
IPV6_SCRIPT_DEST="/opt/wardnode/wardnode-set-ipv6.sh"
SERVICE_SRC="$SCRIPT_DIR/wardnode-wf.service"
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
echo "  WardNode — Instalación del agente"
echo "═══════════════════════════════════════════════"
echo ""

# ── 1. UFW + iptables-persistent ─────────────────
if ! command -v netfilter-persistent &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent
    ok "iptables-persistent instalado"
else
    ok "iptables-persistent ya instalado"
fi

if ! command -v ufw &>/dev/null; then
    warn "UFW no instalado — instalando..."
    apt-get update -qq && apt-get install -y -qq ufw
    ok "UFW instalado"
else
    ok "UFW encontrado"
fi
ufw logging medium >/dev/null 2>&1 || warn "No se pudo activar logging UFW medium todavía"
touch /var/log/ufw.log 2>/dev/null || true
chmod 640 /var/log/ufw.log 2>/dev/null || true

# Garantizar que rsyslog enruta los eventos UFW al archivo de log
if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
    apt-get install -y -qq rsyslog && systemctl enable --now rsyslog
    ok "rsyslog instalado y activo"
fi
if [ ! -f /etc/rsyslog.d/20-ufw.conf ]; then
    printf ':msg,contains,"[UFW " /var/log/ufw.log\n& ~\n' > /etc/rsyslog.d/20-ufw.conf
    systemctl restart rsyslog 2>/dev/null || true
    ok "rsyslog configurado para logs UFW"
fi

# ── 2. Grupo dedicado wardnode (GID fijo 1500) ───
if ! getent group wardnode &>/dev/null; then
    groupadd --system --gid 1500 wardnode
    ok "Grupo 'wardnode' (GID 1500) creado"
else
    ok "Grupo 'wardnode' ya existe"
fi

# ── 3. Directorio del socket ──────────────────────
mkdir -p "$SOCKET_DIR"
chown root:wardnode "$SOCKET_DIR"
chmod 750 "$SOCKET_DIR"
ok "Directorio $SOCKET_DIR configurado (root:wardnode 750)"

# ── 4. tmpfiles.d para persistir /run/wardnode ───
echo "d $SOCKET_DIR 0750 root wardnode -" > "$TMPFILES_CONF"
ok "tmpfiles.d configurado ($TMPFILES_CONF)"

# ── 5. Copiar agente WF y scripts helper ─────────
mkdir -p /opt/wardnode
cp "$AGENT_SRC" "$AGENT_DEST"
chown root:root "$AGENT_DEST"
chmod 755 "$AGENT_DEST"
ok "Agente WF instalado en $AGENT_DEST"

cp "$IPV6_SCRIPT_SRC" "$IPV6_SCRIPT_DEST"
chown root:root "$IPV6_SCRIPT_DEST"
chmod 755 "$IPV6_SCRIPT_DEST"
ok "Script IPv6 instalado en $IPV6_SCRIPT_DEST"

# ── 6. Servicio systemd del agente WF ────────────
echo ""
echo "  → Iniciando agente WF…"

cp "$SERVICE_SRC" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

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
echo "  Estado del agente WF:"
systemctl status "$SERVICE_NAME" --no-pager -l | head -8
echo ""
echo "  Próximos pasos:"
echo "  1. Activa el módulo 'WardNode WF' desde el panel"
echo "  2. Configura el dominio de consola para asegurar el puerto 5000 automáticamente"
echo "═══════════════════════════════════════════════"
echo ""
