#!/usr/bin/env bash
# WardNode — Deploy de un click para VPS Ubuntu/Debian
#
# Uso rápido (sin clonar el repo):
#   curl -fsSL https://raw.githubusercontent.com/esepulvedahgit/WARDNODE/main/quick-deploy.sh | sudo bash
#
# Uso local (si ya tienes el repo):
#   sudo bash quick-deploy.sh
#
# Qué hace este script:
#   1. Instala Docker + Compose v2 si no están presentes.
#   2. Clona el repositorio en /opt/wardnode (o actualiza si ya existe).
#   3. Pide el dominio y detecta la IP pública de la VPS.
#   4. Genera automáticamente todos los secretos seguros en .env.prod.
#   5. Construye las imágenes Docker propias (console, proxy, crowdsec-bouncer).
#   6. Levanta el stack de producción con deploy-vps.sh.
#
# Contenedores que quedan activos:
#   console · docker-proxy · proxy (WAF) · db (PostgreSQL) · redis
#   alloy · loki · prometheus · nginx-exporter
#
# Módulos adicionales (se activan desde el panel /modules/):
#   OBS (Grafana) · DDoS (CrowdSec) · WF/CS host-agent (via SSH desde la UI)

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

info()   { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()     { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()    { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
step()   { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${RESET}"; }
hr()     { echo -e "${CYAN}──────────────────────────────────────────────────────────${RESET}"; }

# ── Constantes ────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/esepulvedahgit/WARDNODE.git"
BRANCH="main"
CLONE_DIR="/opt/wardnode"

# ── 0. Verificar root ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  if command -v sudo &>/dev/null && [[ -f "$0" ]]; then
    echo "  → Elevando privilegios con sudo..."
    exec sudo -E bash "$0" "$@"
  fi
  err "Este script debe ejecutarse como root."
  err ""
  err "  Opciones:"
  err "    sudo bash quick-deploy.sh"
  err "    curl -fsSL <url> | sudo bash"
  exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║           WardNode — Deploy de un click                      ║${RESET}"
echo -e "${BOLD}${GREEN}║   Nginx + ModSecurity + OWASP CRS  ·  Consola Flask          ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
info "Este script configurará WardNode en esta VPS."
info "Tiempo estimado: 5–15 minutos (según velocidad de red)."
echo ""

# ── 1. Verificar / instalar Docker ────────────────────────────────────────────
step "1/6 · Verificando Docker"

ensure_docker() {
  local docker_ok=true
  local compose_ok=true

  command -v docker &>/dev/null       || docker_ok=false
  docker compose version &>/dev/null  || compose_ok=false

  if $docker_ok && $compose_ok; then
    ok "Docker $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) con Compose v2 detectado."
    return 0
  fi

  if ! $docker_ok; then
    warn "Docker no encontrado. Instalando automáticamente..."
    echo ""
    if ! curl -fsSL https://get.docker.com | sh; then
      err ""
      err "La instalación automática de Docker falló."
      err "Instálalo manualmente y vuelve a ejecutar este script:"
      err ""
      err "  Guía oficial: https://docs.docker.com/engine/install/"
      exit 1
    fi
    systemctl enable --now docker 2>/dev/null || true
    echo ""
  fi

  # Verificar Compose v2 después de instalar Docker
  if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 no disponible tras la instalación."
    err "Verifica: docker compose version"
    err "Guía: https://docs.docker.com/compose/install/"
    exit 1
  fi

  ok "Docker instalado: $(docker --version)"
  ok "Compose:          $(docker compose version --short 2>/dev/null || docker compose version)"
}

ensure_docker

# ── 2. Clonar / actualizar repositorio ───────────────────────────────────────
step "2/6 · Preparando código fuente"

PROJECT_DIR=""

# Detectar si el script ya corre dentro de un checkout del repo
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"
if [[ -f "${SCRIPT_DIR}/docker-compose.vps.yml" && -f "${SCRIPT_DIR}/.env.prod.example" ]]; then
  PROJECT_DIR="$SCRIPT_DIR"
  ok "Repositorio detectado en ${PROJECT_DIR} — usando directorio local."
elif [[ -d "${CLONE_DIR}/.git" ]]; then
  info "Repositorio existente en ${CLONE_DIR} — actualizando..."
  if git -C "$CLONE_DIR" pull --ff-only origin "$BRANCH" 2>/dev/null; then
    ok "Código actualizado."
  else
    warn "git pull no pudo avanzar (posibles cambios locales). Continuando con la versión actual."
  fi
  PROJECT_DIR="$CLONE_DIR"
else
  info "Clonando repositorio en ${CLONE_DIR}..."
  mkdir -p "$(dirname "$CLONE_DIR")"
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$CLONE_DIR"
  PROJECT_DIR="$CLONE_DIR"
  ok "Repositorio clonado en ${PROJECT_DIR}."
fi

cd "$PROJECT_DIR"

# ── 3. Datos interactivos del operador ────────────────────────────────────────
step "3/6 · Configurando entorno"

# Si stdin viene de una tubería (curl | bash), redirigirlo al terminal
# para que read pueda capturar la entrada del operador.
[[ -t 0 ]] || exec < /dev/tty

# Detectar IP pública
detect_public_ip() {
  local ip=""
  for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
    ip="$(curl -fsSL --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]')" || continue
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  # Fallback: primera IP no-loopback del sistema
  hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
}

# ── Pedir dominio ──────────────────────────────────────────────────────────
echo ""
info "Escribe el dominio que apuntará a esta VPS (ej: panel.miempresa.com)."
info "Si aún no tienes DNS configurado puedes usar un valor provisional; lo"
info "puedes cambiar editando TRUSTED_HOSTS y PUBLIC_BASE_URL en .env.prod."
echo ""

DOMAIN=""
while true; do
  read -rp "  → Dominio: " DOMAIN
  DOMAIN="${DOMAIN// /}"
  # Validación básica de dominio (host.tld o sub.host.tld)
  if [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
    break
  fi
  warn "  Dominio inválido. Formato esperado: sub.dominio.com"
done

# ── Detectar IP pública ────────────────────────────────────────────────────
echo ""
info "Detectando IP pública de esta VPS..."
DETECTED_IP="$(detect_public_ip)"
echo ""
echo -e "  IP detectada: ${BOLD}${DETECTED_IP}${RESET}"
read -rp "  → ¿Es correcta? [Enter para confirmar / escribe otra IP]: " USER_IP
PUBLIC_IP="${USER_IP:-$DETECTED_IP}"
PUBLIC_IP="${PUBLIC_IP// /}"

if ! [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  warn "Formato de IP no estándar: '${PUBLIC_IP}'. Continuando de todas formas."
fi

echo ""
ok "Dominio : ${BOLD}${DOMAIN}${RESET}"
ok "IP VPS  : ${BOLD}${PUBLIC_IP}${RESET}"

# ── 4. Generar .env.prod ──────────────────────────────────────────────────────
step "4/6 · Generando variables de entorno seguras"

# ── Generadores de secretos ────────────────────────────────────────────────
rand_hex() {
  # $1 = número de bytes → produce $((2*$1)) chars hex
  openssl rand -hex "$1"
}

gen_fernet() {
  # Clave Fernet = 32 bytes aleatorios en base64-urlsafe con padding (44 chars)
  if command -v python3 &>/dev/null; then
    python3 -c "
try:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
except ImportError:
    import os, base64
    print(base64.urlsafe_b64encode(os.urandom(32)).decode())
" 2>/dev/null && return 0
  fi
  # Fallback sin Python: openssl base64 → convertir a URL-safe
  # 32 bytes → 44 chars base64 (incluye == de padding al final)
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
}

# Reemplaza (o añade) una variable en .env.prod.
# Usa | como delimitador de sed → seguro para valores con / : @ . - _ =
set_env() {
  local key="$1"
  local val="$2"
  if grep -q "^${key}=" .env.prod 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" .env.prod
  else
    echo "${key}=${val}" >> .env.prod
  fi
}

ENV_FILE=".env.prod"

# ── ¿Ya existe .env.prod? ─────────────────────────────────────────────────
ENV_EXISTED=false
if [[ -f "$ENV_FILE" ]]; then
  echo ""
  warn "El archivo ${ENV_FILE} ya existe."
  read -rp "  → ¿Regenerar todos los secretos? Los existentes se perderán. [s/N]: " REGEN
  if [[ "${REGEN,,}" =~ ^(s|si|y|yes)$ ]]; then
    ENV_EXISTED=false
  else
    ENV_EXISTED=true
    # Solo actualizar las variables que dependen del dominio/IP ingresados ahora
    info "Conservando secretos existentes. Actualizando dominio, IP y rutas..."
    set_env "PUBLIC_BASE_URL"      "https://${DOMAIN}"
    set_env "TRUSTED_HOSTS"        "${DOMAIN},${PUBLIC_IP},${PUBLIC_IP}:5000"
    set_env "WARDNODE_PROJECT_DIR" "${PROJECT_DIR}"
    ok "Variables de dominio actualizadas en ${ENV_FILE}."
  fi
fi

# ── Generar desde cero ────────────────────────────────────────────────────
if [[ "$ENV_EXISTED" == "false" ]]; then
  echo ""
  info "Generando secretos seguros..."

  SK="$(rand_hex 32)"
  WNK="$(gen_fernet)"
  PG_PASS="$(rand_hex 24)"
  REDIS_PASS="$(rand_hex 24)"
  GRAFANA_ADMIN_PASS="$(rand_hex 16)"
  GRAFANA_DB_PASS="$(rand_hex 16)"

  cp .env.prod.example "$ENV_FILE"

  set_env "SECRET_KEY"              "$SK"
  set_env "WARDNODE_SECRET_KEY"     "$WNK"
  set_env "POSTGRES_PASSWORD"       "$PG_PASS"
  set_env "DATABASE_URL"            "postgresql+psycopg://app:${PG_PASS}@127.0.0.1:5432/app"
  set_env "REDIS_PASSWORD"          "$REDIS_PASS"
  set_env "GRAFANA_ADMIN_PASSWORD"  "$GRAFANA_ADMIN_PASS"
  set_env "GRAFANA_DB_PASSWORD"     "$GRAFANA_DB_PASS"
  set_env "PUBLIC_BASE_URL"         "https://${DOMAIN}"
  set_env "TRUSTED_HOSTS"           "${DOMAIN},${PUBLIC_IP},${PUBLIC_IP}:5000"
  # Desactivar cookie segura inicialmente: el acceso es por HTTP (IP:5000)
  # hasta que el dominio tenga TLS. Ver PASO 4 al final del deploy.
  set_env "SESSION_COOKIE_SECURE"   "false"
  set_env "WARDNODE_PROJECT_DIR"    "${PROJECT_DIR}"

  chmod 600 "$ENV_FILE"
  ok "Secretos generados y guardados en ${ENV_FILE} (modo 600)."

  # Mostrar credenciales críticas para que el operador las guarde
  echo ""
  hr
  echo -e "${BOLD}${YELLOW}  ⚠  COPIA ESTOS VALORES EN UN LUGAR SEGURO ANTES DE CONTINUAR${RESET}"
  echo -e "${YELLOW}  No se vuelven a mostrar. Si los pierdes tendrás que regenerarlos.${RESET}"
  hr
  echo -e "${BOLD}  WARDNODE_SECRET_KEY  =  ${WNK}${RESET}"
  echo -e "${BOLD}  POSTGRES_PASSWORD    =  ${PG_PASS}${RESET}"
  echo -e "${BOLD}  REDIS_PASSWORD       =  ${REDIS_PASS}${RESET}"
  echo -e "${BOLD}  GRAFANA_ADMIN_PASS   =  ${GRAFANA_ADMIN_PASS}${RESET}"
  hr
  echo ""
  echo -e "${YELLOW}  WARDNODE_SECRET_KEY cifra todos los secretos en BD (SMTP, MaxMind,${RESET}"
  echo -e "${YELLOW}  claves LLM, TOTP). Los backups nunca la incluyen. Sin ella, los${RESET}"
  echo -e "${YELLOW}  secretos cifrados son IRRECUPERABLES. Guárdala fuera del servidor.${RESET}"
  echo ""
  read -rp "  → Presiona Enter cuando hayas guardado estas credenciales..." _

fi

# ── 5. Construir imágenes Docker propias ──────────────────────────────────────
step "5/6 · Construyendo imágenes Docker"
echo ""
info "Construyendo: wardnode-console, wardnode-proxy, wardnode-crowdsec-bouncer."
info "El proxy compila ngx_http_geoip2_module desde fuente — puede tardar ~5 min."
echo ""

docker compose -f docker-compose.prod.yml build

ok "Imágenes construidas correctamente."

# ── 6. Desplegar stack de producción ─────────────────────────────────────────
step "6/6 · Desplegando stack de producción"
echo ""
info "Precargando imágenes de terceros (Grafana, Loki, CrowdSec...)."
info "Luego levantando el stack base..."
echo ""

bash "${PROJECT_DIR}/deploy-vps.sh"

# ── Mensaje final ─────────────────────────────────────────────────────────────
echo ""
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║                 ✅  WardNode desplegado                           ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}Contenedores activos:${RESET}"
echo "  console · docker-proxy · proxy (WAF) · db (PostgreSQL) · redis"
echo "  alloy · loki · prometheus · nginx-exporter"
echo ""
echo -e "${BOLD}Módulos activables desde el panel (no requieren acción ahora):${RESET}"
echo "  OBS (Grafana)   → perfil 'obs'  — activar desde /modules/"
echo "  DDoS (CrowdSec) → perfil 'ddos' — activar desde /modules/"
echo "  WF / CS (UFW)   → instalar desde /modules/ vía SSH con llave del admin"
echo ""
hr
echo ""
echo -e "${BOLD}${GREEN}PASO 1 — Crear el primer administrador${RESET}"
echo ""
echo -e "  Abre en tu navegador:"
echo -e "  ${CYAN}http://${PUBLIC_IP}:5000/auth/setup${RESET}"
echo ""
echo -e "${BOLD}${GREEN}PASO 2 — Apuntar el DNS${RESET}"
echo ""
echo "  En tu proveedor DNS crea un registro A:"
echo -e "  ${BOLD}${DOMAIN}${RESET}  →  ${BOLD}${PUBLIC_IP}${RESET}"
echo ""
echo -e "${BOLD}${GREEN}PASO 3 — Emitir certificado TLS (Let's Encrypt)${RESET}"
echo ""
echo "  Cuando el DNS resuelva (puede tardar hasta 24h), ejecuta desde ${PROJECT_DIR}:"
echo ""
echo -e "  ${CYAN}docker compose -f docker-compose.vps.yml --profile certbot run --rm certbot \\"
echo "    certonly --webroot -w /var/www/certbot \\"
echo "    -d ${DOMAIN} --email tu@email.com \\"
echo "    --agree-tos --no-eff-email${RESET}"
echo ""
echo -e "${BOLD}${YELLOW}PASO 4 — Activar cookie segura (una vez el dominio cargue por HTTPS)${RESET}"
echo ""
echo -e "  Edita ${BOLD}${PROJECT_DIR}/.env.prod${RESET} y cambia:"
echo -e "    SESSION_COOKIE_SECURE=${RED}false${RESET}  →  SESSION_COOKIE_SECURE=${GREEN}true${RESET}"
echo ""
echo "  Luego reinicia la consola:"
echo -e "  ${CYAN}docker compose -f docker-compose.vps.yml restart console${RESET}"
echo ""
hr
echo ""
echo -e "${BOLD}Archivos importantes:${RESET}"
echo "  ${PROJECT_DIR}/.env.prod      ← secretos y configuración (chmod 600)"
echo "  ${PROJECT_DIR}/deploy-vps.sh  ← volver a desplegar tras actualizaciones"
echo ""
echo -e "${YELLOW}⚠  WARDNODE_SECRET_KEY debe guardarse fuera del servidor.${RESET}"
echo "   Sin ella los secretos cifrados en BD son irrecuperables."
echo "   Los backups NUNCA la incluyen."
echo ""
