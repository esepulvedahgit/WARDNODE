#!/usr/bin/env bash
set -e

DIST=dist

mkdir -p "$DIST"

echo "==> Construyendo imágenes de producción..."
docker compose -f docker-compose.prod.yml build

echo "==> Exportando wardnode-console:prod ..."
docker save wardnode-console:prod | gzip > "$DIST/wardnode-console.tar.gz"

echo "==> Exportando wardnode-proxy:prod ..."
docker save wardnode-proxy:prod | gzip > "$DIST/wardnode-proxy.tar.gz"

echo ""
echo "==> Listo. Archivos generados en $DIST/:"
ls -lh "$DIST"/*.tar.gz

echo ""
echo "Transferir al VPS con:"
echo "  scp $DIST/wardnode-console.tar.gz $DIST/wardnode-proxy.tar.gz \\"
echo "      docker-compose.vps.yml .env.prod.example \\"
echo "      usuario@VPS:~/wardnode/"
