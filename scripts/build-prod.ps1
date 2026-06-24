$ErrorActionPreference = "Stop"

$Dist = "dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

Write-Host "==> Construyendo imagenes de produccion..." -ForegroundColor Cyan
docker compose -f docker-compose.prod.yml build
if ($LASTEXITCODE -ne 0) { Write-Error "docker build fallo"; exit 1 }

Write-Host "==> Exportando wardnode-console:prod ..." -ForegroundColor Cyan
docker save wardnode-console:prod -o "$Dist\wardnode-console.tar"
if ($LASTEXITCODE -ne 0) { Write-Error "docker save console fallo"; exit 1 }

Write-Host "==> Exportando wardnode-proxy:prod ..." -ForegroundColor Cyan
docker save wardnode-proxy:prod -o "$Dist\wardnode-proxy.tar"
if ($LASTEXITCODE -ne 0) { Write-Error "docker save proxy fallo"; exit 1 }

Write-Host "==> Exportando wardnode-crowdsec-bouncer:prod ..." -ForegroundColor Cyan
docker save wardnode-crowdsec-bouncer:prod -o "$Dist\wardnode-crowdsec-bouncer.tar"
if ($LASTEXITCODE -ne 0) { Write-Error "docker save bouncer fallo"; exit 1 }

Write-Host ""
Write-Host "==> Listo. Archivos generados en $Dist\:" -ForegroundColor Green
Get-ChildItem "$Dist\wardnode-*.tar" |
    Select-Object Name, @{N="Tamanio"; E={ "{0:N1} MB" -f ($_.Length / 1MB) }} |
    Format-Table -AutoSize

Write-Host "Transferir al VPS con:" -ForegroundColor Yellow
Write-Host "  scp $Dist\wardnode-console.tar $Dist\wardnode-proxy.tar $Dist\wardnode-crowdsec-bouncer.tar docker-compose.vps.yml .env.prod.example deploy-vps.sh usuario@VPS:~/wardnode/"
Write-Host "  # El modulo DDoS necesita ademas el directorio crowdsec/ (acquis.yaml):"
Write-Host "  scp -r crowdsec usuario@VPS:~/wardnode/"
Write-Host ""
Write-Host "En el VPS:" -ForegroundColor Yellow
Write-Host "  cp .env.prod.example .env.prod   # editar secretos reales:"
Write-Host "                                   #   SECRET_KEY, WARDNODE_SECRET_KEY"
Write-Host "                                   #   POSTGRES_PASSWORD, DATABASE_URL"
Write-Host "                                   #   GRAFANA_ADMIN_PASSWORD"
Write-Host "                                   #   GRAFANA_DB_USER=grafana_ro"
Write-Host "                                   #   GRAFANA_DB_PASSWORD=<secreto>"
Write-Host "  bash deploy-vps.sh               # valida variables, [1/3] load imagenes,"
Write-Host "                                   # [2/3] precarga imagenes de terceros,"
Write-Host "                                   # [3/3] docker compose up -d"
Write-Host "                                   # El console crea el rol grafana_ro en arranque."
Write-Host "  # Grafana se activa desde el panel de modulos (OBS)."
