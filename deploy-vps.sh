#!/usr/bin/env bash
# WardNode — despliegue en el VPS (uso manual o CD).
#
#   [1/3] Carga las imágenes propias desde los tarballs (si están presentes).
#          En pipelines CD/registry sin tarballs, este paso se omite limpiamente.
#   [2/3] Precarga las imágenes de terceros de OBS + DDoS sin arrancar nada.
#          El panel no puede descargarlas (pasa por docker-socket-proxy, que bloquea
#          los pulls por diseño). Las imágenes en disco permiten activar los módulos
#          desde el panel sin violar la filosofía on-demand de los profiles.
#   [3/3] Levanta el stack base (console, proxy, db, docker-proxy, alloy, loki,
#          prometheus, nginx-exporter). Solo Grafana se activa más tarde desde el
#          panel (módulo OBS). Alloy+Loki+Prometheus arrancan siempre para
#          minimizar la fuga de logs desde el primer arranque del sistema.
#
# Idempotente — re-ejecutarlo no re-descarga capas ya presentes ni reinicia
# contenedores que no hayan cambiado.
#
# Variables de entorno (override para CD / entornos no estándar):
#   COMPOSE_FILE  ruta al docker-compose de producción  (default: docker-compose.vps.yml)
#   ENV_FILE      ruta al archivo de variables de entorno (default: .env.prod)
#
# Uso:
#   bash deploy-vps.sh
#   COMPOSE_FILE=docker-compose.custom.yml ENV_FILE=.env.staging bash deploy-vps.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.vps.yml}"
ENV_FILE="${ENV_FILE:-.env.prod}"

# Tarballs de imágenes propias generados por scripts/build-prod.sh.
TARBALLS=(
  wardnode-console.tar.gz
  wardnode-proxy.tar.gz
  wardnode-crowdsec-bouncer.tar.gz
)

# Servicios de terceros a precargar, por nombre de servicio (no por tag de imagen).
# Usando nombres de servicio, el comando es estable aunque se actualicen las versiones
# en docker-compose.vps.yml. crowdsec-bouncer se excluye: es imagen propia (tarball).
THIRD_PARTY_SERVICES=(
  alloy
  loki
  grafana
  prometheus
  nginx-exporter
  crowdsec
)

# Función wrapper: siempre pasa --env-file y -f para que la interpolación
# de variables del compose (p.ej. GRAFANA_ADMIN_PASSWORD) funcione desde el host.
dc() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

# ── Validaciones previas ───────────────────────────────────────────────────────
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "ERROR: no se encontró el archivo compose '$COMPOSE_FILE' en $SCRIPT_DIR" >&2
  echo "       Asegúrate de ejecutar el script desde el directorio del proyecto." >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: no se encontró '$ENV_FILE'" >&2
  echo "       Copia .env.prod.example a .env.prod y edita los valores." >&2
  exit 1
fi

# ── [1/3] Cargar imágenes propias ─────────────────────────────────────────────
echo "==> [1/3] Cargando imágenes propias desde tarballs (si están presentes)..."
loaded=0
for tb in "${TARBALLS[@]}"; do
  if [ -f "$tb" ]; then
    echo "    docker load -i $tb"
    docker load -i "$tb"
    loaded=$((loaded + 1))
  fi
done
if [ "$loaded" -eq 0 ]; then
  echo "    (no se encontraron tarballs; se asumen imágenes ya presentes o vía registry/CD)"
fi

# ── [2/3] Precargar imágenes de terceros ──────────────────────────────────────
echo ""
echo "==> [2/3] Precargando imágenes de terceros (OBS + DDoS) sin arrancar nada..."
dc --profile obs --profile ddos pull "${THIRD_PARTY_SERVICES[@]}"

# ── [3/3] Levantar el stack base ──────────────────────────────────────────────
echo ""
echo "==> [3/3] Levantando el stack base..."
dc up -d

echo ""
echo "=========================================================================="
echo "Listo."
echo "  Consola: http://<ip-del-vps>:5000"
echo "  Primera visita → /auth/setup para crear el administrador inicial."
echo ""
echo "  Alloy + Loki + Prometheus ya están corriendo (capturan logs desde ahora)."
echo "  Módulo OBS (Grafana): activar desde el panel cuando sea necesario."
echo "  Módulo DDoS (CrowdSec): activar desde el panel cuando sea necesario."
echo "  Las imágenes ya están en disco para activar módulos sin descargas."
echo "=========================================================================="
