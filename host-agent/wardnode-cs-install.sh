#!/usr/bin/env bash
# WardNode CS — Instalación de CrowdSec en el host
# Uso: sudo bash wardnode-cs-install.sh
# Requiere: wardnode-wf ya instalado (usuario wardnode-wf debe existir)
set -euo pipefail

SUDOERS_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sudoers-wardnode-cs"
CONTROL_SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wardnode-cs-control.sh"
SUDOERS_DEST="/etc/sudoers.d/wardnode-cs"
CONTROL_SCRIPT_DEST="/opt/wardnode/wardnode-cs-control.sh"
ACQUIS_FILE="/etc/crowdsec/acquis.yaml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Ejecuta como root: sudo bash wardnode-cs-install.sh"
[ -f "$SUDOERS_SRC" ]         || err "No se encontró sudoers-wardnode-cs junto a este script"
[ -f "$CONTROL_SCRIPT_SRC" ] || err "No se encontró wardnode-cs-control.sh junto a este script"

# Verificar que wardnode-wf existe (prerequisito)
id "wardnode-wf" &>/dev/null || err "Usuario 'wardnode-wf' no encontrado — instala WardNode WF primero"

echo ""
echo "═══════════════════════════════════════════════"
echo "  WardNode CS — Instalación de CrowdSec"
echo "═══════════════════════════════════════════════"
echo ""

# 1. Añadir repositorio de CrowdSec e instalar
if command -v cscli &>/dev/null; then
    ok "CrowdSec ya instalado: $(cscli version 2>/dev/null | head -1 || echo 'versión desconocida')"
else
    warn "CrowdSec no encontrado — instalando desde repositorio oficial..."
    apt-get install -y -qq curl gnupg
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt-get install -y crowdsec
    ok "CrowdSec instalado"
fi

# 2. Instalar bouncer
if dpkg -l crowdsec-firewall-bouncer-iptables &>/dev/null 2>&1; then
    ok "crowdsec-firewall-bouncer-iptables ya instalado"
else
    warn "Instalando crowdsec-firewall-bouncer-iptables..."
    apt-get install -y crowdsec-firewall-bouncer-iptables
    ok "Bouncer instalado"
fi

# 3. Instalar colección SSH (protección brute-force)
if cscli collections list 2>/dev/null | grep -q "crowdsecurity/sshd"; then
    ok "Colección crowdsecurity/sshd ya instalada"
else
    warn "Instalando colección crowdsecurity/sshd..."
    cscli collections install crowdsecurity/sshd
    ok "Colección SSH instalada"
fi

# 4. Configurar adquisición de logs SSH
if [ -f "$ACQUIS_FILE" ] && grep -q "auth.log" "$ACQUIS_FILE" 2>/dev/null; then
    ok "Adquisición de /var/log/auth.log ya configurada"
else
    warn "Añadiendo adquisición de /var/log/auth.log..."
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

# 5. Instalar sudoers para wardnode-wf → cscli + control script
cp "$SUDOERS_SRC" "$SUDOERS_DEST"
chmod 440 "$SUDOERS_DEST"
if visudo -c -f "$SUDOERS_DEST" &>/dev/null; then
    ok "Sudoers instalado ($SUDOERS_DEST)"
else
    rm -f "$SUDOERS_DEST"
    err "Error de sintaxis en sudoers — abortando"
fi

# 5b. Script de control de servicios (propiedad root para no ser modificable por wardnode-wf)
cp "$CONTROL_SCRIPT_SRC" "$CONTROL_SCRIPT_DEST"
chown root:root "$CONTROL_SCRIPT_DEST"
chmod 755 "$CONTROL_SCRIPT_DEST"
ok "Script de control instalado en $CONTROL_SCRIPT_DEST"

# 6. Habilitar y arrancar servicios
systemctl daemon-reload
systemctl enable crowdsec
systemctl restart crowdsec

# Esperar hasta 5s para que crowdsec arranque
for i in $(seq 1 10); do
    systemctl is-active --quiet crowdsec && break
    sleep 0.5
done

if systemctl is-active --quiet crowdsec; then
    ok "crowdsec.service activo"
else
    warn "crowdsec no arrancó — revisa: journalctl -u crowdsec -n 30"
fi

systemctl enable crowdsec-firewall-bouncer
systemctl restart crowdsec-firewall-bouncer

for i in $(seq 1 10); do
    systemctl is-active --quiet crowdsec-firewall-bouncer && break
    sleep 0.5
done

if systemctl is-active --quiet crowdsec-firewall-bouncer; then
    ok "crowdsec-firewall-bouncer.service activo"
else
    warn "bouncer no arrancó — revisa: journalctl -u crowdsec-firewall-bouncer -n 30"
fi

echo ""
echo "═══════════════════════════════════════════════"
ok "Instalación completada"
echo ""
echo "  Estado CrowdSec:"
systemctl status crowdsec --no-pager -l | head -8
echo ""
echo "  Estado Bouncer:"
systemctl status crowdsec-firewall-bouncer --no-pager -l | head -8
echo ""
echo "  Próximos pasos:"
echo "  1. Activa el módulo 'WardNode CS' desde el panel"
echo "  2. Verifica las decisiones activas en el panel"
echo "═══════════════════════════════════════════════"
echo ""
