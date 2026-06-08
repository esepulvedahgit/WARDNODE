# WardNode

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Gunicorn](https://img.shields.io/badge/Gunicorn-22-499848?style=flat-square&logo=gunicorn&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-OWASP--CRS-009639?style=flat-square&logo=nginx&logoColor=white)
![ModSecurity](https://img.shields.io/badge/ModSecurity-v3-CC0000?style=flat-square)
![Grafana](https://img.shields.io/badge/Grafana-11.5-F46800?style=flat-square&logo=grafana&logoColor=white)
![Loki](https://img.shields.io/badge/Loki-3-F46800?style=flat-square&logo=grafana&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-latest-E6522C?style=flat-square&logo=prometheus&logoColor=white)
![pytest](https://img.shields.io/badge/pytest-8.0-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![Version](https://img.shields.io/badge/versión-1.0.0-brightgreen?style=flat-square)

**WardNode** es una consola de administración Flask para un stack de proxy inverso Nginx + ModSecurity + OWASP CRS. Separa el **plano de gestión** (consola Flask, puerto 5000) del **plano de tráfico** (proxy Nginx, puertos 80/443): la consola escribe configuración Nginx a disco y el proxy la lee, sin manejar tráfico de usuario directamente.

Módulos opcionales extienden la consola con gestión del firewall UFW del host y un stack de observabilidad completo (Grafana + Loki + Prometheus).

---

## 🚀 Tecnologías

### Backend
| Tecnología | Versión | Rol |
|---|---|---|
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | 3.12+ | Runtime |
| ![Flask](https://img.shields.io/badge/-Flask-000000?style=flat-square&logo=flask&logoColor=white) | 3.0 | Framework web |
| ![SQLAlchemy](https://img.shields.io/badge/-SQLAlchemy-D71F00?style=flat-square) | 3.1 (Flask-SQLAlchemy) | ORM |
| ![Alembic](https://img.shields.io/badge/-Alembic-6BA539?style=flat-square) | 4.0 (Flask-Migrate) | Migraciones |
| ![Gunicorn](https://img.shields.io/badge/-Gunicorn-499848?style=flat-square&logo=gunicorn&logoColor=white) | 22 | Servidor WSGI (producción) |

### Frontend
| Tecnología | Rol |
|---|---|
| ![Jinja2](https://img.shields.io/badge/-Jinja2-B41717?style=flat-square) | Plantillas HTML |
| ![HTMX](https://img.shields.io/badge/-HTMX-3D72D7?style=flat-square) | Actualizaciones parciales de página |
| ![Alpine.js](https://img.shields.io/badge/-Alpine.js-8BC0D0?style=flat-square&logo=alpinedotjs&logoColor=white) | Estado local en UI |
| ![Bootstrap](https://img.shields.io/badge/-Bootstrap-7952B3?style=flat-square&logo=bootstrap&logoColor=white) | Estilos y componentes |

### Proxy / WAF
| Tecnología | Versión | Rol |
|---|---|---|
| ![Nginx](https://img.shields.io/badge/-Nginx-009639?style=flat-square&logo=nginx&logoColor=white) | OWASP CRS base | Proxy inverso + WAF |
| ![ModSecurity](https://img.shields.io/badge/-ModSecurity-CC0000?style=flat-square) | v3 | Motor WAF |
| ![OWASP CRS](https://img.shields.io/badge/-OWASP%20CRS-000000?style=flat-square&logo=owasp&logoColor=white) | nginx | Ruleset de seguridad |
| `ngx_http_geoip2_module` | — | Bloqueo geográfico por país |
| ![Certbot](https://img.shields.io/badge/-Certbot-003A70?style=flat-square) | latest | TLS / Let's Encrypt |

### Datos
| Tecnología | Versión | Rol |
|---|---|---|
| ![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white) | 16-alpine | Base de datos (producción) |
| SQLite | — | Base de datos (desarrollo local) |
| psycopg | 3.1 | Driver PostgreSQL |

### Observabilidad (perfil `obs`)
| Tecnología | Versión | Rol |
|---|---|---|
| ![Grafana](https://img.shields.io/badge/-Grafana-F46800?style=flat-square&logo=grafana&logoColor=white) | 11.5 | Dashboards |
| ![Loki](https://img.shields.io/badge/-Loki-F46800?style=flat-square&logo=grafana&logoColor=white) | 3 | Almacenamiento de logs |
| Grafana Alloy | latest | Recolector (logs + métricas) |
| ![Prometheus](https://img.shields.io/badge/-Prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white) | latest | Almacenamiento de métricas |

### Seguridad adicional
![pyotp](https://img.shields.io/badge/-pyotp%20TOTP-4A4A4A?style=flat-square)
![cryptography](https://img.shields.io/badge/-cryptography%20Fernet-4A4A4A?style=flat-square)
![MaxMind](https://img.shields.io/badge/-MaxMind%20GeoLite2-003399?style=flat-square)
![paramiko](https://img.shields.io/badge/-paramiko%20SSH-4A4A4A?style=flat-square)
![Flask‑Limiter](https://img.shields.io/badge/-Flask--Limiter%203.8-4A4A4A?style=flat-square)

---

## 🏗️ Arquitectura

WardNode separa completamente el plano de gestión del plano de tráfico:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Docker Compose                          │
│                                                                 │
│  ┌──────────────────┐   generated/nginx/   ┌─────────────────┐ │
│  │  Flask Console   │  ──────────────────► │  Proxy (Nginx   │ │
│  │  :5000 (gestión) │   *.conf (montado    │  + ModSecurity  │ │
│  │                  │   como read-only)    │  + OWASP CRS)   │ │
│  │  - Genera config │                      │  :80 / :443     │ │
│  │  - Recarga proxy │◄── Docker SDK ──────►│                 │ │
│  └────────┬─────────┘                      └────────┬────────┘ │
│           │                                         │          │
│           ▼                                         ▼          │
│  ┌──────────────────┐              stdout  ┌─────────────────┐ │
│  │  PostgreSQL :5432│              logs    │  ModSec JSON    │ │
│  │  (sitios, eventos│              ───────►│  audit → ingest │ │
│  │   audit, config) │                      │  → AttackEvent  │ │
│  └──────────────────┘                      └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

Perfil OBS (opcional):
  Alloy ──► Loki (logs) + Prometheus (métricas) ──► Grafana :3000
```

### Pipeline de generación de configuración

```
UI / Route change
      │
      ▼
_apply_nginx()  ──►  render_nginx_configs()  ──►  generated/nginx/
                                                    ├── 00-geoip.conf
                                                    ├── 00-zones.conf
                                                    ├── 00-default.conf   (catch-all)
                                                    └── site-{domain}.conf
      │
      ▼
reload_nginx()  (docker exec nginx -s reload)
```

### Módulos host (Unix socket)

```
Flask container ─── Unix socket ─── wardnode-wf-agent.py (root:wardnode)
socket_client.py                    systemd: wardnode-wf.service
  └── validación 1                  └── validación 2 + subprocess ufw/iptables
```

---

## 📁 Estructura del proyecto

```
wardnode/
├── app/                          # Aplicación Flask
│   ├── __init__.py               # Factory, extensiones, CLI commands, ingest thread
│   ├── models.py                 # Site, AttackEvent, AuditLog, AppConfig, ...
│   ├── config.py                 # Configuración por entorno
│   ├── auth/                     # Blueprint: login, TOTP, usuarios, reset contraseña
│   ├── proxy/                    # Blueprint: WAF, sitios, reglas, GeoIP, headers
│   │   ├── routes.py             # Rutas de gestión
│   │   ├── services.py           # render_nginx_configs(), _build_challenge_html()
│   │   ├── ingest.py             # Hilo daemon: Docker logs → AttackEvent
│   │   ├── custom_rules.py       # Validación SecRule/SecAction
│   │   ├── security_headers.py   # Validación de cabeceras HTTP
│   │   ├── nginx_extra.py        # Validación directivas Nginx extra
│   │   ├── geoip.py              # Integración MaxMind GeoLite2
│   │   └── geoip_blocklist.py    # Regenera 00-geoip.conf + recarga
│   ├── modules/                  # Blueprint: WF / CS / OBS
│   │   ├── routes.py             # Toggle módulos, inyección obs.conf
│   │   └── socket_client.py      # Cliente Unix socket → wf-agent
│   ├── audit/                    # Blueprint: dashboard audit log
│   │   └── helpers.py            # log_audit() — escritura segura con SAVEPOINT
│   └── security.py               # Decoradores y utilidades de seguridad
│
├── proxy/                        # Imagen Docker del proxy
│   ├── Dockerfile                # Multi-stage: compila ngx_http_geoip2_module
│   ├── conf.d/generated.conf     # Include generated/*.conf
│   └── modsecurity/              # modsecurity-override.conf (JSON audit logs)
│
├── observability/
│   ├── alloy/config.alloy        # Pipeline Alloy: ModSec + Nginx + UFW → Loki; métricas → Prometheus
│   ├── grafana/provisioning/
│   │   ├── datasources/          # loki.yaml, prometheus.yaml, postgres.yaml
│   │   └── dashboards/           # 01-security-overview, 02-modsecurity-waf,
│   │                             # 03-waf-analytics, 04-nginx-logs,
│   │                             # 05-host-resources, 06-firewall-ufw
│   ├── loki.yaml
│   └── prometheus.yml
│
├── host-agent/
│   ├── wardnode-wf-agent.py      # Daemon privilegiado UFW/iptables via Unix socket
│   ├── install.sh                # Instala UFW, rsyslog, configura logging medium, crea systemd service
│   └── wardnode-wf.service       # Unit de systemd
│
├── generated/nginx/              # Configs generadas (git-ignored, montadas en proxy)
├── tests/                        # 8 módulos, ~80 tests (pytest)
├── docs/                         # architecture.md, deployment.md, security-baseline.md, adr/
├── docker-compose.yml            # Stack de desarrollo
├── docker-compose.vps.yml        # Stack de producción (VPS)
├── Dockerfile                    # Imagen de la consola Flask
├── .env.example                  # Variables de entorno de referencia
├── CHANGELOG.md
└── SECURITY.md
```

---

## ✨ Funcionalidades

### Gestión de sitios protegidos
- Registro de dominios con URL de upstream configurable.
- Generación automática de configuración Nginx por sitio (`site-{domain}.conf`) tras cada cambio.
- Recarga del proxy sin downtime vía `docker exec nginx -s reload`.

### OWASP CRS por categoría
Activación/desactivación de familias de reglas por sitio usando `SecRuleRemoveByTag`. Cubre: SQLi, XSS, LFI, RFI, RCE, PHP, Java, Node.js, protocolo HTTP, method enforcement, multipart, DoS, reputación IP, session fixation y niveles de paranoia 1–4.

### Reglas ModSecurity personalizadas
Editor con validación estricta antes de guardar:
- Solo `SecRule` y `SecAction`.
- IDs en rango reservado `1000000–1999999`, sin duplicados.
- Sin `include`, `exec:`, `lua:`, ni `ctl:ruleEngine=Off`.

### Cabeceras de seguridad
Gestión por sitio de `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` y `Content-Security-Policy`, con validación de nombre y valor.

### Políticas de tráfico
`limit_req` y `limit_conn` por sitio: requests/segundo, burst, nodelay, conexiones máximas y clave de aplicación. Genera zonas globales en `00-zones.conf`.

### Nginx extra por dominio
Directivas adicionales en contexto `server` y `location /` con validación y `nginx -t` en seco cuando el binario está disponible.

### GeoIP y blocklist de países
Bloqueo a nivel Nginx por código ISO de país usando MaxMind GeoLite2-Country (`flask ensure-geoip` descarga la base de datos automáticamente si hay credenciales configuradas).

### Bot Protection
Challenge matemático server-side con token HMAC-SHA256 (cookie `wn_bot=ward_cleared_v1`, `HttpOnly + Secure`). Los clientes desconocidos son redirigidos a `/_wn_challenge/` antes de alcanzar el upstream.

### TLS / Let's Encrypt
Aprovisionamiento de certificados desde la UI usando Docker SDK. Soporte para certificados personalizados o Let's Encrypt por sitio.

### Catch-all WAF (`default_server`)
Bloque `default_server` generado automáticamente (`00-default.conf`) con ModSecurity activo: captura todo el tráfico directo a la IP que no coincide con ningún virtual host registrado.

### TOTP 2FA
Autenticación de dos factores basada en TOTP (RFC 6238) por usuario. Secreta almacenada cifrada con Fernet. Flujo de enrollment con QR code en la UI.

### Audit Log
Registro de todas las acciones del operador (cambios de config, inicios de sesión, errores). Dashboard con KPI cards, timeline y exportación CSV. Escritura segura con `SAVEPOINT` de SQLAlchemy.

### Roles
| Rol | Capacidades |
|---|---|
| `admin` | Gestión de usuarios + todas las acciones del proxy |
| `operator` | Todas las acciones del proxy, sin gestión de usuarios |
| `reader` | Solo lectura de paneles y detalles |

### Recuperación de contraseña
Tokens hasheados, de un solo uso, con expiración configurable (`PASSWORD_RESET_TOKEN_MINUTES`). Integración SMTP configurable.

---

## 🧩 Módulos opcionales

### WardNode WF — Firewall UFW
Administra UFW del host sin exponer SSH. Comunica con un daemon `wardnode-wf-agent.py` (systemd, `root:wardnode`) a través de un socket Unix bind-montado. Validación doble: Flask valida antes de enviar; el agente revalida antes de ejecutar `ufw`/`iptables`.

Funciones: allow/deny puertos e IPs, rate limiting de puertos (`limit_port`), protección del puerto de la consola, detección de puertos Docker expuestos, inicialización del firewall con política `deny incoming`.

#### Logging de eventos UFW

`install.sh` configura el nivel de logging en `medium` (registra conexiones aceptadas y bloqueadas con rate-limiting) y garantiza el enrutamiento de logs mediante rsyslog:

```
UFW → kernel → /var/log/kern.log          ← Alloy lee aquí (fuente primaria)
                       │
                       ▼ rsyslog (/etc/rsyslog.d/20-ufw.conf)
               /var/log/ufw.log            ← archivo separado (referencia/debug)
```

`install.sh` instala rsyslog si no está activo y crea `/etc/rsyslog.d/20-ufw.conf` para filtrar y separar las líneas `[UFW ]` a `/var/log/ufw.log`. Alloy lee desde `kern.log` y filtra por `[UFW ` antes de enviar a Loki.

> En hosts ya inicializados con `logging low`, aplicar manualmente: `sudo ufw logging medium`

### WardNode OBS — Observabilidad
Stack Grafana activado con `--profile obs`. 6 dashboards provisionados automáticamente:

| Dashboard | Datasource | Descripción |
|---|---|---|
| Security Overview | Loki | Resumen de eventos WAF en tiempo real |
| ModSecurity WAF | Loki | Análisis de logs ModSecurity por patrón |
| WAF Analytics | **PostgreSQL** | KPIs, criticidad, top IPs/reglas desde `attack_event` |
| Nginx Logs | Loki | Accesos y errores del proxy |
| Host Resources | Prometheus | CPU, memoria, disco, red |
| Firewall UFW | Loki | Eventos `[UFW BLOCK]`/`[UFW ALLOW]`, top IPs y puertos |

Grafana se sirve en `/obs/` con autenticación por proxy a la sesión Flask.

---

## ⚙️ Despliegue

### Desarrollo local

```bash
# Requisitos: Python 3.12+
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env       # editar DATABASE_URL, SECRET_KEY, WARDNODE_SECRET_KEY

flask db upgrade           # aplica migraciones (SQLite por defecto)
flask init-db              # seed de categorías OWASP CRS
flask run                  # http://localhost:5000
```

Ir a `http://localhost:5000/auth/setup` para crear el primer admin.

### Docker — stack completo (dev)

```bash
cp .env.example .env
docker compose up --build

# Con stack de observabilidad:
docker compose --profile obs up --build
```

- Consola: `http://localhost:5000`
- Proxy WAF: `http://localhost` / `https://localhost`
- Grafana (perfil obs): `http://localhost:3000`

### Producción / VPS

```bash
# 1. Clonar y preparar variables de entorno
cp .env.prod.example .env

# 2. Construir e iniciar el stack
docker compose -f docker-compose.vps.yml up -d --build

# 3. (Opcional) Activar observabilidad
docker compose -f docker-compose.vps.yml --profile obs up -d

# 4. Instalar el agente de host (requiere root en el VPS)
sudo bash host-agent/install.sh
```

Los comandos CLI de producción se ejecutan automáticamente en el entrypoint del contenedor:

| Comando | Descripción |
|---|---|
| `flask db-setup` | `create_all` + stamp en DB nueva; `db upgrade` en existente |
| `flask ensure-geoip` | Descarga GeoLite2-Country si hay credenciales MaxMind configuradas |
| `flask render-configs` | Regenera todos los `.conf` de Nginx manualmente |

#### Let's Encrypt (producción)

```bash
docker compose -f docker-compose.vps.yml --profile certbot run --rm certbot \
  certonly --webroot -w /var/www/certbot \
  -d app.ejemplo.com --email admin@ejemplo.com \
  --agree-tos --no-eff-email
```

---

## 🔧 Variables de entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `SECRET_KEY` | `change-me` | Clave de sesión Flask — **cambiar en producción** |
| `WARDNODE_SECRET_KEY` | `""` | Clave Fernet para cifrar secretos (TOTP, SMTP, MaxMind) |
| `DATABASE_URL` | `sqlite:///app.db` | Docker usa `postgresql+psycopg://...` |
| `PROXY_CONFIG_DIR` | `generated/nginx` | Directorio donde Flask escribe los `.conf` |
| `GEOIP_DB_PATH` | `/app/data/geoip/GeoLite2-Country.mmdb` | Ruta a la base de datos GeoIP |
| `NGINX_CONTAINER_NAME` | `wardnode-proxy` | Nombre del contenedor para Docker SDK |
| `WARDNODE_PROXY_CONTAINER` | `wardnode-proxy` | Contenedor del que se leen logs ModSecurity |
| `WF_SOCKET_PATH` | `/app/sockets/wardnode-wf.sock` | Socket Unix del agente WF |
| `SESSION_COOKIE_SECURE` | `false` | Poner `true` detrás de HTTPS en producción |
| `RATELIMIT_STORAGE_URI` | `memory://` | Usar `redis://` en entornos multi-proceso |
| `GRAFANA_ADMIN_PASSWORD` | `wardnode` | Contraseña del admin de Grafana |
| `WARDNODE_PROJECT_DIR` | `""` | Ruta absoluta al proyecto en el host (necesaria para módulo OBS en VPS) |

Ver `.env.example` para la lista completa.

---

## 🧪 Tests

```bash
source .venv/bin/activate

pytest                     # todos los tests (~80)
pytest tests/test_proxy.py # módulo individual
pytest -k "test_name"      # test específico
pytest --cov=app           # con cobertura
```

Los tests usan SQLite en memoria, CSRF y rate limiting desactivados. Fixtures: `app`, `client`, `user_factory`, `login_as`.

---

## 🔒 Seguridad

- **CSRF** global vía Flask-WTF; header `X-CSRFToken` inyectado en todas las mutaciones HTMX.
- **Rate limiting** en login (5/hora), setup y reset de contraseña.
- **RBAC** con decorador `@roles_required` en todas las rutas mutantes.
- **Validación de entrada** en reglas ModSec, directivas Nginx extra y cabeceras HTTP.
- **Secretos cifrados** en base de datos con Fernet (`WARDNODE_SECRET_KEY`).
- **TOTP 2FA** opcional por usuario.
- **Socket Unix** con doble capa de validación para comandos privilegiados del host.

Ver [`SECURITY.md`](SECURITY.md) para la línea base de seguridad completa.

---

## 📚 Documentación

| Documento | Descripción |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Arquitectura detallada del sistema |
| [`docs/deployment.md`](docs/deployment.md) | Guía de despliegue paso a paso |
| [`docs/security-baseline.md`](docs/security-baseline.md) | Controles de seguridad implementados |
| [`docs/frontend-guidelines.md`](docs/frontend-guidelines.md) | Guía de desarrollo frontend (HTMX + Alpine.js) |
| [`docs/testing-strategy.md`](docs/testing-strategy.md) | Estrategia de tests |
| [`docs/adr/`](docs/adr/) | Registros de decisiones de arquitectura (ADR) |
| [`CHANGELOG.md`](CHANGELOG.md) | Historial de cambios por versión |
| [`SECURITY.md`](SECURITY.md) | Política de seguridad y reporte de vulnerabilidades |
