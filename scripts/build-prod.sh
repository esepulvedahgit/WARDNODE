#!/usr/bin/env bash
set -e

DIST=dist

mkdir -p "$DIST"

echo "==> Construyendo imágenes de producción..."
docker compose -f docker-compose.prod.yml build --pull

echo "==> Exportando wardnode-console:prod ..."
docker save wardnode-console:prod | gzip > "$DIST/wardnode-console.tar.gz"

echo "==> Exportando wardnode-proxy:prod ..."
docker save wardnode-proxy:prod | gzip > "$DIST/wardnode-proxy.tar.gz"

echo "==> Exportando wardnode-crowdsec-bouncer:prod ..."
docker save wardnode-crowdsec-bouncer:prod | gzip > "$DIST/wardnode-crowdsec-bouncer.tar.gz"

echo ""
echo "==> Listo. Archivos generados en $DIST/:"
ls -lh "$DIST"/*.tar.gz

echo ""
echo "Transferir al VPS con:"
echo "  scp $DIST/wardnode-console.tar.gz $DIST/wardnode-proxy.tar.gz \\"
echo "      $DIST/wardnode-crowdsec-bouncer.tar.gz \\"
echo "      docker-compose.vps.yml .env.prod.example deploy-vps.sh \\"
echo "      usuario@VPS:~/wardnode/"
echo "  # El módulo DDoS necesita además el directorio crowdsec/ (acquis.yaml):"
echo "  scp -r crowdsec usuario@VPS:~/wardnode/"
echo ""
echo "En el VPS:"
echo "  cp .env.prod.example .env.prod   # editar con secretos reales"
echo "  bash deploy-vps.sh               # [1/3] load imágenes propias"
echo "                                   # [2/3] precarga imágenes de terceros (OBS + DDoS)"
echo "                                   # [3/3] docker compose up -d (stack base)"
