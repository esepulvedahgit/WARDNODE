# WardNode

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Gunicorn](https://img.shields.io/badge/Gunicorn-22-499848?style=flat-square&logo=gunicorn&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-OWASP--CRS-009639?style=flat-square&logo=nginx&logoColor=white)
![ModSecurity](https://img.shields.io/badge/ModSecurity-v3-CC0000?style=flat-square)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-11.5-F46800?style=flat-square&logo=grafana&logoColor=white)
![Loki](https://img.shields.io/badge/Loki-3-F46800?style=flat-square&logo=grafana&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-latest-E6522C?style=flat-square&logo=prometheus&logoColor=white)
![pytest](https://img.shields.io/badge/pytest-8.0-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![Version](https://img.shields.io/badge/versión-1.0.0-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**WardNode** es una consola de administración Flask para un stack de proxy inverso Nginx + ModSecurity + OWASP CRS. Separa el **plano de gestión** (consola Flask, puerto 5000) del **plano de tráfico** (proxy Nginx, puertos 80/443): la consola escribe configuración Nginx a disco y el proxy la lee, sin manejar tráfico de usuario directamente.

Cuatro módulos opcionales extienden la consola con capacidades de gestión del host: **WardNode WF** (firewall UFW), **WardNode OBS** (observabilidad Grafana/Loki/Prometheus), **WardNode SOC** (correlación de incidentes, análisis LLM y scoring ML) y **WardNode CrowdSec** (IDS/IPS). Cada pantalla de la consola incluye una página de **ayuda embebida** accesible desde el botón "Documentación".

---

## ⚡ Deploy de un click

Despliega WardNode en cualquier VPS Ubuntu 22.04/24.04 o Debian con **un solo comando** (requiere `root` o `sudo`):

```bash
curl -fsSL https://raw.githubusercontent.com/esepulvedahgit/WARDNODE/main/quick-deploy.sh | sudo bash
```

El script instala Docker si no está presente, clona el repositorio en `/opt/wardnode`, genera todos los secretos seguros de forma automática y levanta el stack completo de producción. Al terminar te indica la URL para crear el primer administrador.

> Ver la sección [**Producción / VPS — Deploy de un click**](#producción--vps--deploy-de-un-click) para el detalle completo de los pasos post-instalación (DNS, TLS, cookie segura).

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
| ![Redis](https://img.shields.io/badge/-Redis-DC382D?style=flat-square&logo=redis&logoColor=white) | 7-alpine | Storage compartido Flask-Limiter (producción multi-worker) |

### Observabilidad (perfil `obs`)
| Tecnología | Versión | Rol |
|---|---|---|
| ![Grafana](https://img.shields.io/badge/-Grafana-F46800?style=flat-square&logo=grafana&logoColor=white) | 11.5 | Dashboards |
| ![Loki](https://img.shields.io/badge/-Loki-F46800?style=flat-square&logo=grafana&logoColor=white) | 3 | Almacenamiento de logs |
| Grafana Alloy | latest | Recolector (logs + métricas) |
| ![Prometheus](https://img.shields.io/badge/-Prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white) | latest | Almacenamiento de métricas |

### Seguridad y análisis
![pyotp](https://img.shields.io/badge/-pyotp%20TOTP-4A4A4A?style=flat-square)
![cryptography](https://img.shields.io/badge/-cryptography%20Fernet-4A4A4A?style=flat-square)
![MaxMind](https://img.shields.io/badge/-MaxMind%20GeoLite2-003399?style=flat-square)
![paramiko](https://img.shields.io/badge/-paramiko%20SSH-4A4A4A?style=flat-square)
![Flask‑Limiter](https://img.shields.io/badge/-Flask--Limiter%203.8-4A4A4A?style=flat-square)
![scikit-learn](https://img.shields.io/badge/-scikit--learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![httpx](https://img.shields.io/badge/-httpx-4A4A4A?style=flat-square)
![pyzipper](https://img.shields.io/badge/-pyzipper%20AES--256-4A4A4A?style=flat-square)

---

## 🏗️ Arquitectura

WardNode separa completamente el plano de gestión del plano de tráfico:

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Docker Compose                              │
│                                                                      │
│  ┌──────────────────┐   generated/nginx/   ┌──────────────────────┐ │
│  │  Flask Console   │  ──────────────────► │  Proxy (Nginx        │ │
│  │  :5000 (gestión) │   *.conf (montado    │  + ModSecurity       │ │
│  │                  │   como read-only)    │  + OWASP CRS)        │ │
│  │  - Genera config │                      │  :80 / :443          │ │
│  │  - Recarga proxy │◄── Docker SDK ──────►│                      │ │
│  └────────┬─────────┘                      └──────────┬───────────┘ │
│           │                                           │             │
│           ▼                                           ▼             │
│  ┌──────────────────┐              stdout    ┌─────────────────┐    │
│  │  PostgreSQL :5432│              logs      │  ModSec JSON    │    │
│  │  (sitios, eventos│              ─────────►│  audit → ingest │    │
│  │   audit, config) │                        │  → AttackEvent  │    │
│  └──────────────────┘                        └─────────────────┘    │
│                                                                      │
│  ┌──────────────────┐                                               │
│  │  Redis :6379     │  ← storage Flask-Limiter (multi-worker)      │
│  └──────────────────┘                                               │
└──────────────────────────────────────────────────────────────────────┘

Perfil OBS (opcional):
  Alloy ──► Loki (logs) + Prometheus (métricas) ──► Grafana :3000
```

### Workers en segundo plano

La consola arranca seis hilos daemon en startup. En producción con Gunicorn multi-worker, un advisory lock de PostgreSQL garantiza que solo un proceso ejecuta cada ciclo:

| Hilo | Advisory lock | Función |
|---|---|---|
| `modsec-ingest` | — | Lee JSON de stdout del proxy → `AttackEvent` |
| `rawlog-worker` | 815004 | Persiste log crudo en `modsec_raw_log` |
| `syslog-forwarder` | 815005 | Reenvía WAF events + audit log a SIEM (RFC5424) |
| `soc-worker` | 815001 | Correlación de incidentes + ML (cada N min.) |
| `backup-scheduler` | 815002 | Backup cifrado diario a hora configurable |
| `crowdsec-ingest` | — | Lee alertas CrowdSec → `DdosBanEvent` |

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

### Módulo WF — comunicación con el host

```
Flask container ─── Unix socket ─── wardnode-wf-agent.py (root:wardnode)
socket_client.py                    systemd: wardnode-wf.service
  └── validación 1                  └── validación 2 + subprocess ufw/iptables
```

---

## 📁 Estructura del proyecto

```
wardnode/
├── app/                            # Aplicación Flask
│   ├── __init__.py                 # Factory, extensiones, CLI commands, threads
│   ├── models.py                   # Site, AttackEvent, AuditLog, AppConfig, ...
│   ├── config.py                   # Configuración por entorno
│   ├── email.py                    # send_email() — wrapper SMTP con adjuntos
│   ├── encryption.py               # encrypt_secret() / decrypt_secret() (Fernet)
│   ├── extensions.py               # Instancias db, login_manager, limiter, csrf
│   ├── security.py                 # Decoradores @roles_required, utilidades
│   │
│   ├── auth/                       # Blueprint /auth — login, TOTP, usuarios, reset
│   ├── proxy/                      # Blueprint /proxy — WAF, sitios, reglas, GeoIP
│   │   ├── routes.py               # Rutas de gestión + 4 rutas /docs
│   │   ├── services.py             # render_nginx_configs(), bot challenge HTML
│   │   ├── ingest.py               # Thread: Docker logs → AttackEvent
│   │   ├── rawlog_worker.py        # Thread: log crudo → modsec_raw_log
│   │   ├── syslog_forwarder.py     # RFC5424: build_rfc5424, SyslogSender
│   │   ├── syslog_worker.py        # Thread: cursor incremental → SIEM
│   │   ├── custom_rules.py         # Validación SecRule/SecAction
│   │   ├── security_headers.py     # Validación cabeceras HTTP
│   │   ├── nginx_extra.py          # Validación directivas Nginx extra
│   │   ├── geoip.py                # Integración MaxMind GeoLite2
│   │   └── geoip_blocklist.py      # Regenera 00-geoip.conf + recarga
│   │
│   ├── modules/                    # Blueprint /modules — WF / OBS / SOC / CrowdSec / Sys
│   │   ├── routes.py               # Toggle módulos, inyección obs.conf, rutas /docs
│   │   └── socket_client.py        # Cliente Unix socket → wf-agent
│   │
│   ├── soc/                        # Blueprint /soc — Security Operations Center
│   │   ├── worker.py               # Thread: ciclo detección + ML (advisory lock 815001)
│   │   ├── detect.py               # Heurística SQL sobre AttackEvent → SocIncident
│   │   ├── enrich.py               # AbuseIPDB (TTL 24h) + MITRE ATT&CK mapping
│   │   ├── mitre_cti.py            # Sincronización enterprise-attack.json → MitreAttackTechnique
│   │   ├── alerts.py               # Email + Telegram con cooldown por IP
│   │   ├── ml.py                   # IsolationForest (scikit-learn) sobre agregados 14d
│   │   ├── soar.py                 # Bloqueo automático de IPs vía CrowdSec/UFW
│   │   ├── daily_report.py         # Reporte estadístico diario por correo
│   │   ├── schema.py               # Normalización y validación de salida LLM
│   │   └── llm/                    # Multi-proveedor httpx (OpenRouter, Anthropic, OpenAI…)
│   │
│   ├── backup/                     # Blueprint /backup — backups AES-256
│   │   ├── service.py              # Creación/restauración de zip AES-256 (pyzipper)
│   │   ├── worker.py               # Thread: scheduler diario (advisory lock 815002)
│   │   ├── collectors.py           # pg_dump, TLS certs, estado WF via Docker SDK
│   │   └── routes.py               # Rutas UI + CLI + /backup/docs
│   │
│   ├── ddos/                       # Lógica CrowdSec (no es blueprint; rutas en modules/)
│   │   ├── control.py              # ban/unban vía Docker SDK (wardnode-crowdsec)
│   │   ├── ingest.py               # Thread: cscli alerts → DdosBanEvent
│   │   └── safety.py               # is_ban_safe() — 5 capas de protección antes de banear
│   │
│   ├── audit/                      # Blueprint /audit — dashboard de auditoría
│   │   ├── helpers.py              # log_audit() — escritura segura con SAVEPOINT
│   │   └── routes.py               # KPI cards, timeline, CSV export, /audit/docs
│   │
│   └── main/                       # Blueprint / — root redirect, /status JSON
│
├── proxy/                          # Imagen Docker del proxy
│   ├── Dockerfile                  # Añade ngx_http_geoip2_module sobre OWASP CRS base
│   ├── conf.d/generated.conf       # include generated/*.conf
│   └── modsecurity/                # modsecurity-override.conf (JSON audit logs vía YAJL)
│
├── observability/
│   ├── alloy/config.alloy          # Pipeline: ModSec + Nginx + UFW → Loki; métricas → Prometheus
│   ├── grafana/provisioning/
│   │   ├── datasources/            # loki.yaml, prometheus.yaml, postgres.yaml
│   │   └── dashboards/             # 01-security-overview, 03-waf-analytics,
│   │                               # 04-nginx-logs, 06-firewall-ufw, 07-nginx-metrics
│   ├── loki.yaml
│   └── prometheus.yml
│
├── host-agent/
│   ├── wardnode-wf-agent.py        # Daemon privilegiado UFW/iptables vía Unix socket
│   ├── install.sh                  # Instala UFW, rsyslog, CrowdSec; crea servicio systemd
│   └── wardnode-wf.service         # Unit de systemd
│
├── generated/nginx/                # Configs generadas (git-ignored, montadas en proxy)
├── tests/                          # 13 módulos, 492 tests (pytest)
├── docs/                           # architecture.md, deployment.md, security-baseline.md
│                                   # frontend-guidelines.md, testing-strategy.md, adr/
├── docker-compose.yml              # Stack de desarrollo
├── docker-compose.prod.yml         # Build de imágenes propias (console, proxy, bouncer)
├── docker-compose.vps.yml          # Stack de producción (VPS, incluye Redis)
├── quick-deploy.sh                 # Deploy de un click: instala Docker, clona, genera secretos, levanta
├── deploy-vps.sh                   # Deploy avanzado: valida env, precarga imágenes, up -d
├── Dockerfile                      # Imagen de la consola Flask
├── .env.example                    # Variables de entorno para desarrollo
├── .env.prod.example               # Variables de entorno para producción (plantilla)
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

### Log crudo ModSecurity en vivo
Pestaña **Log** (`/proxy/logs`): polling en tiempo real desde `modsec_raw_log`, buscador por frase, detalle expandible y archivado cifrado AES-256 opcional. Distinto de los Eventos WAF: muestra cada alerta individual sin deduplicar.

### SOC — Centro de Operaciones de Seguridad
Pipeline automático sobre `AttackEvent`:
1. **Detección heurística** (volumen, diversidad, fan-out de paths, block ratio) → `SocIncident` con severidad 0–100.
2. **Enriquecimiento**: reputación AbuseIPDB (cache 24h) + mapping CRS → MITRE ATT&CK.
3. **Análisis LLM** opt-in (OpenRouter, Anthropic, OpenAI, DeepSeek, Gemini) — nunca se envían cuerpos de petición, solo metadatos agregados.
4. **Alertas** email y Telegram con cooldown por IP.
5. **Scoring ML**: IsolationForest (scikit-learn) entrenado sobre los últimos 14 días de datos; eleva el score heurístico si detecta anomalías.
6. **SOAR**: bloqueo automático de IPs vía CrowdSec/UFW cuando la severidad supera el umbral.
7. **Reporte diario** por correo con estadísticas de incidentes.

### Backups cifrados
- Zip AES-256 (pyzipper) con: volcado PostgreSQL (`pg_dump -Fc`), certificados TLS, estado UFW, manifest con checksums SHA-256.
- **Nunca incluye** `WARDNODE_SECRET_KEY` ni `.env` — deben guardarse por separado.
- Scheduler diario configurable con retención automática y notificación por email.
- Restauración por UI (re-autenticación admin + TOTP + confirmación `RESTAURAR`) o CLI.

### Syslog RFC5424 — reenvío a SIEM
Thread daemon que reenvía eventos WAF (`modsec_raw_log`) y entradas de auditoría (`audit_log`) a un servidor syslog externo vía UDP o TCP (RFC6587 octet-counting). Semántica at-least-once con cursores incrementales.

### TOTP 2FA
Autenticación de dos factores basada en TOTP (RFC 6238) por usuario. Secreto almacenado cifrado con Fernet. Flujo de enrollment con QR code en la UI.

### Audit Log
Registro de todas las acciones del operador (cambios de config, inicios de sesión, errores). Dashboard con KPI cards, timeline y exportación CSV. Escritura segura con `SAVEPOINT` de SQLAlchemy.

### Roles
| Rol | Capacidades |
|---|---|
| `admin` | Gestión de usuarios + todas las acciones del proxy y módulos |
| `operator` | Todas las acciones del proxy y módulos WF/OBS; sin gestión de usuarios, ajustes ni backups |
| `reader` | Solo lectura de paneles, eventos, logs y SOC (vista); sin modificar configuración |

### Recuperación de contraseña
Tokens hasheados, de un solo uso, con expiración configurable (`PASSWORD_RESET_TOKEN_MINUTES`). Integración SMTP configurable.

---

## 🧩 Módulos opcionales

Los cuatro módulos se activan desde la consola (`/modules/`) y **requieren WardNode WF** como base (excepto OBS que también lo requiere por su dependencia de UFW para la red de contenedores).

### WardNode WF — Firewall UFW
Administra UFW del host sin exponer SSH. Comunica con un daemon `wardnode-wf-agent.py` (systemd, `root:wardnode`) a través de un socket Unix bind-montado. Validación doble: Flask valida antes de enviar; el agente revalida antes de ejecutar `ufw`/`iptables`.

Funciones: allow/deny puertos e IPs, rate limiting de puertos (`limit_port`), protección del puerto de la consola, detección de puertos Docker expuestos, inicialización del firewall con política `deny incoming`.

#### Logging de eventos UFW

`install.sh` configura el nivel de logging en `medium` (registra conexiones aceptadas y bloqueadas) y garantiza el enrutamiento de logs mediante rsyslog:

```
UFW → kernel → /var/log/kern.log          ← Alloy lee aquí (fuente primaria)
                       │
                       ▼ rsyslog (/etc/rsyslog.d/20-ufw.conf)
               /var/log/ufw.log            ← archivo separado (referencia/debug)
```

### WardNode OBS — Observabilidad
Stack Grafana activado con `--profile obs`. Colección (Alloy + Loki + Prometheus + nginx-exporter) siempre activa; Grafana solo con el perfil. 5 dashboards provisionados automáticamente:

| Dashboard | Datasource | Descripción |
|---|---|---|
| Security Overview (`01`) | PostgreSQL + Loki | Resumen de eventos WAF y tendencia de tráfico HTTP |
| WAF Analytics (`03`) | **PostgreSQL** | KPIs, criticidad, top IPs/reglas desde `attack_event` |
| Nginx Logs (`04`) | Loki | Accesos y errores del proxy |
| Firewall UFW (`06`) | Loki | Eventos `[UFW BLOCK]`/`[UFW ALLOW]`, top IPs y puertos |
| Nginx Metrics (`07`) | Loki | Agregados de códigos de respuesta HTTP |

> **Fuente autoritativa de eventos WAF:** siempre la tabla `attack_event` en PostgreSQL (1 fila = 1 transacción deduplicada). Los conteos de Loki son orientativos (retención 30 días, líneas crudas sin deduplicar).

> **Log crudo ModSecurity:** disponible en la consola en la pestaña **Log** (`/proxy/logs`).

Grafana se sirve en `/obs/` con autenticación por proxy a la sesión Flask.

### WardNode SOC — Centro de Operaciones
Correlación automática de `AttackEvent` en `SocIncident`. El pipeline (detección → enriquecimiento → LLM → alertas → ML → SOAR) corre en el worker daemon `soc-worker`. Gated por `module_soc_enabled` + rol admin.

Configuración desde `/soc/config`: proveedores LLM y claves API (cifradas), opt-in de envío de datos, umbrales de alerta, habilitación del scoring ML, sincronización MITRE ATT&CK.

### WardNode CrowdSec — IDS/IPS
Integra CrowdSec para detección y bloqueo de amenazas (SSH brute-force, escaneos, etc.). Comunica con el contenedor `wardnode-crowdsec` vía **Docker SDK** (no el socket WF). El bouncer actúa sobre UFW.

Funciones: visualización de decisiones activas, ban/unban manual, safe-IPs (no banear IPs del propio sistema), ingest automático de alertas CrowdSec → `DdosBanEvent`.

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

### Producción / VPS — Deploy de un click

La forma más rápida: **un solo comando** en la VPS limpia (Ubuntu 22.04/24.04 o Debian).

**Método recomendado** — el script se descarga primero y luego se ejecuta; esto evita problemas con `curl | bash` cuando `/dev/tty` no está disponible en la sesión SSH:

```bash
curl -fsSL https://raw.githubusercontent.com/esepulvedahgit/WARDNODE/main/quick-deploy.sh -o /tmp/wardnode-deploy.sh
sudo bash /tmp/wardnode-deploy.sh
```

**Alternativa: one-liner con variables de entorno** (útil para automatización o si el método anterior cuelga en paso 3):

```bash
WARDNODE_DOMAIN=panel.tudominio.com WARDNODE_IP=1.2.3.4 \
  curl -fsSL https://raw.githubusercontent.com/esepulvedahgit/WARDNODE/main/quick-deploy.sh | sudo -E bash
```

O si ya tienes el repo descargado:

```bash
sudo bash quick-deploy.sh
```

**Qué hace el script automáticamente:**
1. Instala Docker + Compose v2 si no están presentes (vía `get.docker.com`).
2. Clona el repositorio en `/opt/wardnode` (o actualiza si ya existe).
3. Pide el dominio que usarás y detecta la IP pública de la VPS.
4. Genera todos los secretos seguros (`SECRET_KEY`, `WARDNODE_SECRET_KEY`, contraseñas de BD, Redis y Grafana) en `.env.prod`.
5. Agrega la IP de la VPS a `TRUSTED_HOSTS` para que puedas entrar a la consola por `http://IP:5000/auth/setup` antes de configurar el DNS.
6. Construye las imágenes Docker propias desde el código fuente.
7. Levanta el stack completo de producción.

**Una vez desplegado**, sigue estos pasos desde la URL que muestra el script:

| Paso | Acción |
|------|--------|
| 1 | `http://<IP>:5000/auth/setup` → crear el primer administrador |
| 2 | Apuntar el DNS de tu dominio a `<IP>` en tu proveedor |
| 3 | Emitir el certificado TLS (ver sección **Let's Encrypt** abajo) |
| 4 | Cuando el dominio cargue por HTTPS, editar `.env.prod` → `SESSION_COOKIE_SECURE=true` y `docker compose -f docker-compose.vps.yml restart console` |

Los módulos **WF (UFW)** y **CrowdSec** se instalan desde el panel `/modules/` vía SSH con la llave del admin — no requieren acción en este punto.

> **`WARDNODE_SECRET_KEY`** cifra todos los secretos almacenados en BD (SMTP, MaxMind, claves LLM, TOTP). Los backups **nunca** la incluyen. Guárdala fuera del servidor; sin ella los secretos cifrados son irrecuperables.

---

### Producción / VPS — Deploy manual (método avanzado)

Si prefieres controlar cada paso:

```bash
# 1. Clonar y preparar variables de entorno
git clone https://github.com/esepulvedahgit/WARDNODE.git /opt/wardnode
cd /opt/wardnode
cp .env.prod.example .env.prod     # Editar secretos, dominio y contraseñas

# 2. Construir las imágenes propias
docker compose -f docker-compose.prod.yml build

# 3. Desplegar el stack base (precarga imágenes de terceros y levanta contenedores)
bash deploy-vps.sh
```

`deploy-vps.sh` verifica que todas las variables obligatorias estén definidas antes de arrancar, crea el symlink `.env → .env.prod` para comandos manuales, y levanta: **console, docker-proxy, proxy, db, redis, alloy, loki, prometheus, nginx-exporter**.

Los módulos OBS (Grafana, perfil `obs`) y DDoS (CrowdSec, perfil `ddos`) se activan desde el panel de módulos, no en este paso.

> **Nota sobre `TRUSTED_HOSTS`**: para acceder a la consola por `http://IP:5000/auth/setup` antes de que el DNS resuelva, agrega la IP de la VPS a esta variable: `TRUSTED_HOSTS=tu-dominio.com,IP,IP:5000`. Flask 3.1+ rechaza peticiones cuyo header `Host` no esté en esta lista.

Los comandos CLI se ejecutan automáticamente en el entrypoint del contenedor en producción (`flask db-setup`, `flask ensure-geoip`, `flask grafana-provision-ro`). También disponibles manualmente:

| Comando | Descripción |
|---|---|
| `flask db-setup` | `create_all` + stamp en DB nueva; `db upgrade` en existente |
| `flask init-db` | Seed de categorías OWASP CRS |
| `flask ensure-geoip` | Descarga GeoLite2-Country si hay credenciales MaxMind |
| `flask render-configs` | Regenera todos los `.conf` de Nginx manualmente |
| `flask reap-reset-tokens` | Elimina tokens de reset de contraseña expirados |
| `flask reset-encrypted-secrets` | Borra todos los secretos cifrados (solo emergencia) |
| `flask grafana-provision-ro` | Crea usuario de solo lectura en Grafana para PostgreSQL |
| `flask backup-create` | Genera un backup cifrado AES-256 ahora |
| `flask backup-restore <zip>` | Restaura desde un zip (interactivo; `--yes` para omitir confirmación) |
| `flask backup-prune [--keep N]` | Elimina backups más antiguos, retiene N (default: config) |

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
| `WARDNODE_SECRET_KEY` | `""` | Clave Fernet para cifrar secretos (TOTP, SMTP, MaxMind, APIs SOC) |
| `DATABASE_URL` | `sqlite:///app.db` | Docker usa `postgresql+psycopg://...` |
| `PROXY_CONFIG_DIR` | `generated/nginx` | Directorio donde Flask escribe los `.conf` |
| `GEOIP_DB_PATH` | `/app/data/geoip/GeoLite2-Country.mmdb` | Ruta a la base de datos GeoIP |
| `NGINX_CONTAINER_NAME` | `wardnode-proxy` | Contenedor proxy para Docker SDK (TLS) |
| `WARDNODE_PROXY_CONTAINER` | `wardnode-proxy` | Contenedor del que se leen logs ModSecurity |
| `WARDNODE_DB_CONTAINER` | `wardnode-db` | Contenedor para `pg_dump`/`pg_restore` (backups) |
| `WARDNODE_CROWDSEC_CONTAINER` | `wardnode-crowdsec` | Contenedor CrowdSec para `cscli` vía Docker SDK |
| `WARDNODE_BACKUP_DIR` | `/app/data/backups` | Directorio de almacenamiento de backups cifrados |
| `WF_SOCKET_PATH` | `/app/sockets/wardnode-wf.sock` | Socket Unix del agente WF |
| `SESSION_COOKIE_SECURE` | `false` | Poner `true` detrás de HTTPS en producción |
| `RATELIMIT_STORAGE_URI` | `memory://` | Se construye como `redis://` si `REDIS_PASSWORD` está definida |
| `REDIS_PASSWORD` | `""` | Contraseña Redis; activa storage compartido de rate-limit en producción |
| `REDIS_HOST` | `127.0.0.1:6379` | Host:puerto de Redis |
| `RATELIMIT_DEFAULT` | `200/day;50/hour` | Límite global por defecto |
| `LOGIN_RATELIMIT` | `5/hour` | Límite específico para el endpoint de login |
| `PASSWORD_RESET_TOKEN_MINUTES` | `30` | Expiración de tokens de reset de contraseña |
| `PASSWORD_RESET_SHOW_TOKEN` | `false` | Solo desarrollo — nunca activar en producción |
| `PUBLIC_BASE_URL` | `""` | URL base pública para enlaces en emails de reset y alertas |
| `GRAFANA_ADMIN_PASSWORD` | `wardnode` | Contraseña del admin de Grafana |
| `GRAFANA_DB_USER` | `grafana_ro` | Usuario de solo lectura de Grafana en PostgreSQL |
| `GRAFANA_DB_PASSWORD` | `""` | Contraseña del usuario de solo lectura de Grafana |
| `WARDNODE_PROJECT_DIR` | `""` | Ruta absoluta al proyecto en el host (necesaria para módulo OBS en VPS) |

Ver `.env.example` y `.env.prod.example` para la lista completa con comentarios.

---

## 🧪 Tests

```bash
source .venv/bin/activate

pytest                     # todos los tests (492)
pytest tests/test_proxy.py # módulo individual
pytest -k "test_name"      # test específico
pytest --cov=app           # con cobertura
```

Los tests usan SQLite en memoria, CSRF y rate limiting desactivados. Fixtures: `app`, `client`, `user_factory`, `login_as`. Trece módulos de test cubren: proxy/WAF, autenticación, backups, módulos WF/OBS, seguridad, SOC, syslog, log crudo y páginas de documentación embebida.

---

## 🔒 Seguridad

- **CSRF** global vía Flask-WTF; header `X-CSRFToken` inyectado en todas las mutaciones HTMX.
- **Rate limiting** en login (configurable, default 5/hora), setup y reset de contraseña.
- **RBAC** con decorador `@roles_required` en todas las rutas mutantes.
- **Validación de entrada** en reglas ModSec, directivas Nginx extra y cabeceras HTTP.
- **Secretos cifrados** en base de datos con Fernet (`WARDNODE_SECRET_KEY`).
- **TOTP 2FA** opcional por usuario.
- **Socket Unix** con doble capa de validación para comandos privilegiados del host.
- **CrowdSec safe-IPs**: cinco capas de protección antes de ejecutar un ban.
- **Backups**: zip AES-256, checksums SHA-256, anti zip-bomb, validación de cabecera Alembic en restore.

Ver [`SECURITY.md`](SECURITY.md) para la línea base de seguridad completa.

---

## 📚 Documentación

La consola incluye **ayuda embebida** en cada área del sidebar: el botón **"Documentación"** abre una página in-app con TOC navegable, advertencias y referencia rápida — sin salir de la consola.

Documentación de referencia en el repositorio:

| Documento | Descripción |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Arquitectura detallada del sistema |
| [`docs/deployment.md`](docs/deployment.md) | Guía de despliegue paso a paso |
| [`docs/security-baseline.md`](docs/security-baseline.md) | Controles de seguridad implementados |
| [`docs/frontend-guidelines.md`](docs/frontend-guidelines.md) | Guía de desarrollo frontend (HTMX + Alpine.js) |
| [`docs/testing-strategy.md`](docs/testing-strategy.md) | Estrategia de tests |
| [`docs/adr/`](docs/adr/) | Registros de decisiones de arquitectura (ADR 0001–0004) |
| [`CHANGELOG.md`](CHANGELOG.md) | Historial de cambios por versión |
| [`SECURITY.md`](SECURITY.md) | Política de seguridad y reporte de vulnerabilidades |
