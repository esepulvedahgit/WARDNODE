#!/usr/bin/env bash
# WardNode — Instalación del agente WF y CrowdSec en el host
# También instala CrowdSec (desactivado) listo para el módulo CS.
# Uso: sudo bash install.sh   — Idempotente.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$SCRIPT_DIR/wardnode-wf-agent.py"
AGENT_DEST="/opt/wardnode/wardnode-wf-agent.py"
IPV6_SCRIPT_SRC="$SCRIPT_DIR/wardnode-set-ipv6.sh"
IPV6_SCRIPT_DEST="/opt/wardnode/wardnode-set-ipv6.sh"
CS_CONTROL_SRC="$SCRIPT_DIR/wardnode-cs-control.sh"
CS_CONTROL_DEST="/opt/wardnode/wardnode-cs-control.sh"
SERVICE_SRC="$SCRIPT_DIR/wardnode-wf.service"
SOCKET_DIR="/run/wardnode"
TMPFILES_CONF="/etc/tmpfiles.d/wardnode.conf"
SERVICE_NAME="wardnode-wf"
ACQUIS_FILE="/etc/crowdsec/acquis.yaml"
CS_CONFIG="/etc/crowdsec/config.yaml"

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

# ── 1. UFW ────────────────────────────────────────
if ! command -v ufw &>/dev/null; then
    warn "UFW no instalado — instalando..."
    apt-get update -qq && apt-get install -y -qq ufw
    ok "UFW instalado"
else
    ok "UFW encontrado"
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

# ── 6. Instalar CrowdSec (módulo CS) ──────────────
echo ""
echo "  → Preparando CrowdSec (módulo CS)…"

if command -v cscli &>/dev/null; then
    ok "CrowdSec ya instalado: $(cscli version 2>/dev/null | head -1 || echo 'versión desconocida')"
else
    warn "Instalando CrowdSec + firewall bouncer..."

    # Eliminar fuentes y keyrings previos (evita conflicto si ya hubo instalación previa)
    rm -f /etc/apt/sources.list.d/crowdsec*.list \
          /etc/apt/sources.list.d/crowdsec*.sources \
          /etc/apt/sources.list.d/*crowdsec*.list \
          /etc/apt/sources.list.d/*crowdsec*.sources \
          /etc/apt/keyrings/crowdsec*.gpg \
          /etc/apt/keyrings/*crowdsec*.gpg \
          /usr/share/keyrings/crowdsec*.gpg \
          /usr/share/keyrings/*crowdsec*.gpg 2>/dev/null || true

    apt-get install -y -qq curl gnupg ca-certificates

    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/crowdsec-archive-keyring.gpg
    chmod 644 /usr/share/keyrings/crowdsec-archive-keyring.gpg

    . /etc/os-release
    echo "deb [signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] \
https://packagecloud.io/crowdsec/crowdsec/${ID} ${VERSION_CODENAME} main" \
        > /etc/apt/sources.list.d/crowdsec.list

    apt-get update -qq
    apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables
    ok "CrowdSec + bouncer instalados"
fi

# ── 7. Colección SSH (brute-force protection) ────
if ! cscli collections list 2>/dev/null | grep -q "crowdsecurity/sshd"; then
    warn "Instalando colección crowdsecurity/sshd..."
    cscli collections install crowdsecurity/sshd
    ok "Colección SSH instalada"
else
    ok "Colección crowdsecurity/sshd ya instalada"
fi

# ── 8. Adquisición de logs SSH ───────────────────
if [ -f "$ACQUIS_FILE" ] && grep -q "auth.log" "$ACQUIS_FILE" 2>/dev/null; then
    ok "Adquisición de /var/log/auth.log ya configurada"
else
    warn "Configurando adquisición de /var/log/auth.log..."
    cat >> "$ACQUIS_FILE" << 'ACQUIS_EOF'

---
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog
ACQUIS_EOF
    ok "Adquisición configurada en $ACQUIS_FILE"
fi

# ── 9. Prometheus CrowdSec en 127.0.0.1 ──────────
if [ -f "$CS_CONFIG" ]; then
    if grep -q "listen_addr:" "$CS_CONFIG"; then
        sed -i 's/listen_addr:.*/listen_addr: 127.0.0.1/' "$CS_CONFIG"
    elif grep -q "^prometheus:" "$CS_CONFIG"; then
        sed -i '/^prometheus:/a\  listen_addr: 127.0.0.1' "$CS_CONFIG"
    else
        cat >> "$CS_CONFIG" << 'CS_PROM_EOF'

prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
CS_PROM_EOF
    fi
    ok "CrowdSec prometheus en 127.0.0.1:6060"
else
    warn "No se encontró $CS_CONFIG — omitiendo configuración de métricas"
fi

# ── 10. Script de control CS ─────────────────────
if [ -f "$CS_CONTROL_SRC" ]; then
    cp "$CS_CONTROL_SRC" "$CS_CONTROL_DEST"
    chown root:root "$CS_CONTROL_DEST"
    chmod 755 "$CS_CONTROL_DEST"
    ok "Script de control CS instalado en $CS_CONTROL_DEST"
else
    warn "wardnode-cs-control.sh no encontrado — reinstala para habilitar el módulo CS"
fi

# ── 11. Dejar CrowdSec DESACTIVADO ───────────────
# El módulo CS lo activa cuando el usuario lo habilita desde el panel.
systemctl disable crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
systemctl stop crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
ok "CrowdSec desactivado — se activa al habilitar el módulo WardNode CS"

# ── 12. Servicio systemd del agente WF ───────────
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
echo "  2. Para habilitar CrowdSec activa el módulo 'WardNode CS'"
echo "═══════════════════════════════════════════════"
echo ""
