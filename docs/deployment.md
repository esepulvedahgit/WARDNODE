# WardNode — Guía de despliegue

## Prerrequisitos

- Docker Engine 24+ con Docker Compose v2
- Ubuntu 22.04 / 24.04 (o cualquier distro Linux con Docker)
- Puertos disponibles: `80`, `443`, `5000`
- (Opcional) Acceso root por SSH para instalar el host-agent (módulos WF/CS)

---

## Desarrollo local

```bash
cp .env.example .env          # editar SECRET_KEY y WARDNODE_SECRET_KEY
docker compose up -d
# Flask arranca en http://localhost:5000
# La primera visita redirige a /auth/setup para crear el admin inicial
```

La base de datos (PostgreSQL) y el proxy (Nginx + ModSecurity) se levantan automáticamente. Los archivos generados de Nginx se escriben en `generated/nginx/` y el proxy los lee.

---

## VPS / Producción

### 1. Preparar variables de entorno

```bash
cp .env.example .env
```

Editar `.env` con valores reales:

| Variable | Descripción | Cómo generarla |
|---|---|---|
| `SECRET_KEY` | Clave de sesiones Flask | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `WARDNODE_SECRET_KEY` | Clave de cifrado Fernet para secretos almacenados | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `DATABASE_URL` | URI de PostgreSQL | `postgresql+psycopg://app:password@db:5432/app` |
| `SESSION_COOKIE_SECURE` | Activar cookies seguras | `true` (requiere HTTPS) |
| `GRAFANA_ADMIN_PASSWORD` | Contraseña admin de Grafana | Elegir valor seguro |
| `WARDNODE_PROJECT_DIR` | Ruta absoluta al proyecto en el host | Ej: `/opt/wardnode` |

### 2. Desplegar

```bash
cp .env.prod.example .env.prod   # editar con secretos reales
bash deploy-vps.sh
```

`deploy-vps.sh` realiza tres pasos en orden:

| Paso | Qué hace |
|------|----------|
| **[1/3] load** | Carga las imágenes propias desde los tarballs (`wardnode-console`, `wardnode-proxy`, `wardnode-crowdsec-bouncer`). Si no hay tarballs (CD / registry), este paso se omite. |
| **[2/3] pull** | Precarga las imágenes de terceros de OBS y DDoS **sin arrancar ningún contenedor**. El panel no puede descargarlas directamente (pasa por `docker-socket-proxy`, que bloquea los pulls por diseño — mínima superficie de API). Las imágenes en disco permiten activar los módulos desde el panel sin violar la filosofía on-demand. |
| **[3/3] up -d** | Levanta el stack base (`console`, `proxy`, `db`, `docker-proxy`, `alloy`, `loki`, `prometheus`, `nginx-exporter`). El contenedor `console` ejecuta `flask db-setup` y `flask ensure-geoip` automáticamente. Alloy+Loki+Prometheus arrancan siempre para capturar logs desde el primer minuto. |

El script es idempotente — re-ejecutarlo no re-descarga capas ya presentes ni reinicia contenedores sin cambios.

### 3. Crear admin inicial

Visitar `http://<ip>:5000` → redirige a `/auth/setup`.

---

## Módulos opcionales

### WardNode WF (firewall UFW)

El módulo WF gestiona UFW en el host a través de un daemon Unix socket. Instalación:

**Opción A — desde el panel** (recomendada):
Módulos → WardNode WF → "Instalar agente" → introducir IP y clave SSH del host.

**Opción B — manual en el host**:
```bash
sudo bash host-agent/install.sh
```

El script instala el agente como servicio systemd (`wardnode-wf.service`) y crea el grupo `wardnode`.

### WardNode CS (CrowdSec IDS/IPS)

Requiere WF activo. CrowdSec se instala junto al host-agent. Activar desde el panel: Módulos → WardNode CS.

### WardNode OBS (observabilidad)

Stack: Grafana Alloy → Loki + Prometheus → Grafana. Grafana disponible en `/obs/` a través del proxy.

**Separación recolección / visualización:**

| Componente | Cuándo arranca | Función |
|---|---|---|
| Alloy + Loki + Prometheus | **Siempre** (stack base, sin profile) | Recolección y almacenamiento de logs y métricas. Capturan desde el primer arranque para minimizar pérdida de logs. |
| Grafana | Módulo OBS activado (`--profile obs`) | Visualización. Se activa desde el panel cuando se necesite. |

**Cifras oficiales de eventos WAF:** siempre desde PostgreSQL (`attack_event`), no desde Loki. El dashboard «WAF Analytics» y `/proxy/` son la fuente de verdad — los conteos coinciden exactamente. Loki sirve para explorar logs crudos en vivo.

Configurar `WARDNODE_PROJECT_DIR` en `.env` apuntando al directorio raíz del proyecto en el host (necesario para que el panel pueda levantar Grafana desde la UI).

Requisito: ejecutar `bash deploy-vps.sh` (paso 2) antes de activar el módulo OBS — precarga
la imagen de Grafana que el panel no puede descargar directamente.

Activar desde el panel: **Módulos → WardNode OBS → Activar** (arranca solo Grafana).

Equivalente manual (sin usar el panel):
```bash
# Dev — Alloy/Loki/Prometheus ya arrancaron con el stack base; solo añadir Grafana:
docker compose --profile obs up -d grafana

# VPS (la imagen de Grafana debe estar en disco primero; deploy-vps.sh ya la precarga)
docker compose --env-file .env.prod -f docker-compose.vps.yml --profile obs up -d grafana
```

### WardNode DDoS (CrowdSec brute-force SSH)

Protege el SSH del host detectando y bloqueando ataques de fuerza bruta.
Usa dos contenedores: `wardnode-crowdsec` (daemon, imagen pública pinada por digest)
y `wardnode-crowdsec-bouncer` (firewall nftables, **imagen propia**).

**Preparación antes de activar en producción:**

1. Construir la imagen del bouncer en desarrollo:
   ```bash
   bash scripts/build-prod.sh   # genera dist/wardnode-crowdsec-bouncer.tar.gz entre otros
   ```

2. Transferir al VPS (además de console y proxy):
   ```bash
   scp dist/wardnode-crowdsec-bouncer.tar.gz usuario@VPS:~/wardnode/
   ```

3. Cargar la imagen del bouncer en el VPS:
   ```bash
   docker load -i wardnode-crowdsec-bouncer.tar.gz
   ```

4. Ejecutar `bash deploy-vps.sh` (paso 2) — precarga el daemon CrowdSec de terceros
   (el bouncer ya quedó cargado del tarball en el paso 1 del script).

5. Activar desde el panel: **Módulos → WardNode DDoS → Activar**.

Equivalente manual (si no se usa el panel):
```bash
# Las imágenes deben estar en disco primero; deploy-vps.sh ya las precarga.
docker compose --env-file .env.prod -f docker-compose.vps.yml --profile ddos up -d \
  crowdsec crowdsec-bouncer
```

> **Sin archivos de config en el host:** el `entrypoint` del daemon genera **dos** archivos
> dentro del contenedor en cada arranque, sin depender de nada del host:
> - `config.yaml.local` → fuerza `api.server.listen_uri: 127.0.0.1:9080`.
> - `acquis.d/ssh.yaml` → define las fuentes de adquisición SSH (`/var/log/auth.log` +
>   journald `sshd`). Un `rm -rf` previo repara automáticamente cualquier estado corrupto
>   que pudieran haber dejado arranques fallidos anteriores.
>
> Además, `LOCAL_API_URL: http://127.0.0.1:9080` fija dónde se conecta el agente interno y
> `API_URL: http://127.0.0.1:9080` en el bouncer fija a dónde se conecta el bouncer.
>
> **Nota:** `LOCAL_API_URL` solo controla dónde se *conecta* el agente, no dónde el servidor
> *escucha*. Para cambiar de puerto, edita los tres valores en `docker-compose.vps.yml`.

---

## MaxMind GeoIP

El bloqueo por país requiere la base de datos GeoLite2-Country (gratuita):

1. Crear cuenta en maxmind.com
2. En el panel: Ajustes → MaxMind → introducir Account ID y License Key
3. La descarga ocurre automáticamente al iniciar. También manual:
   ```bash
   docker exec wardnode-console flask ensure-geoip
   ```

---

## TLS / HTTPS

### Certificado Let's Encrypt

En el panel: Sitio → TLS → activar Let's Encrypt → "Provisionar certificado".
Requiere que el dominio apunte al VPS y los puertos 80/443 estén abiertos.

### Certificado personalizado

Copiar los archivos a `certs/` y especificar las rutas en: Sitio → TLS → Certificado personalizado.

---

## Comandos útiles

```bash
# Ver logs del console
docker logs wardnode-console -f

# Regenerar configs Nginx manualmente
docker exec wardnode-console flask render-configs

# Aplicar migraciones de DB
docker exec wardnode-console flask db upgrade

# Reiniciar solo el proxy (para aplicar configs nuevas en dev)
docker compose restart proxy
```

---

## Notas de seguridad

- Cambiar `SECRET_KEY` y `WARDNODE_SECRET_KEY` antes del primer arranque en producción. Si `WARDNODE_SECRET_KEY` cambia después de almacenar secretos, éstos quedarán ilegibles.
- **Puerto 5000 (riesgo aceptado):** la consola escucha en `0.0.0.0:5000` por diseño, para permitir el primer inicio y la creación del admin (`/auth/setup`) antes de que exista un dominio. Al generar el dominio, el puerto se bloquea automáticamente en el firewall. Verificar tras el setup inicial: `sudo ufw status | grep 5000` debe mostrar el puerto denegado para origen público.
- **Bouncer key del módulo DDoS:** la config renderizada del bouncer (que contiene la key en claro) se escribe en `/dev/shm` (tmpfs, solo RAM) — nunca persiste en disco. Límite conocido y aceptado: la key sigue visible en el env del contenedor (`docker inspect`), legible solo por root del host; es inherente al diseño de inyección por entorno.
- Usar `SESSION_COOKIE_SECURE=true` siempre que haya HTTPS.
- El socket Unix del host-agent (`/run/wardnode/wardnode-wf.sock`) debe pertenecer al grupo `wardnode` (GID 1500). El script `install.sh` lo configura automáticamente.
- El contenedor console monta `/var/run/docker.sock` para gestionar otros contenedores. Asegurarse de que solo el usuario del host con privilegios tenga acceso a este socket.
