# Changelog

Todos los cambios notables del proyecto WardNode se documentan en este archivo.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/).

---

## [1.0.0] — 2026-05-19

### Añadido
- **Consola de gestión Flask** — panel de administración para el stack Nginx + ModSecurity + OWASP CRS
- **Proxy WAF** — imagen Docker personalizada `owasp/modsecurity-crs:nginx` con módulo `ngx_http_geoip2_module`
- **Gestión de sitios** — creación, edición y eliminación de sitios protegidos con upstream configurable
- **Reglas OWASP CRS** — activación/desactivación por categoría con acordeón colapsable (agrupado por familia, badge enabled/total)
- **Reglas ModSecurity personalizadas** — editor con validación: solo SecRule/SecAction, IDs 1.000.000–1.999.999, sin `include`/`exec:`/`lua:`/`ctl:ruleEngine=Off`
- **Headers de seguridad** — gestión por sitio con validación de nombre y valor
- **Políticas de tráfico** — rate limiting y connection limiting por sitio, con alerta en UI cuando se usa `X-Forwarded-For` como clave
- **TLS y Let's Encrypt** — aprovisionamiento automático de certificados vía certbot container
- **GeoIP y blocklist de países** — bloqueo a nivel nginx con base de datos MaxMind GeoLite2
- **Bot Protection** — challenge matemático server-side con token HMAC-SHA256; cookie `HttpOnly + Secure`; verificación vía endpoint Flask proxiado desde nginx
- **Config extra Nginx** — snippets server/location por sitio con validación y dry-run `nginx -t`
- **Módulo WardNode WF** — gestión de UFW sin SSH desde la consola mediante socket Unix + agente host; hardening SSH integrado en el flujo de generación de clave
- **Módulo WardNode CS** — instalación y gestión de CrowdSec (decisiones ban/unban) vía SSH
- **Módulo WardNode OBS** — stack de observabilidad: Grafana Alloy → Loki + Prometheus → Grafana; configs distribuidas mediante volúmenes nombrados desde la imagen de consola
- **Syslog (Fluent-bit)** — reenvío de logs nginx/modsecurity a servidor syslog externo; validación de host con allowlist regex + bloqueo loopback/link-local
- **Módulo Auditoría** — panel admin-only con KPIs, gráfico timeline 7d, donut por severidad, top actores, tabla paginada y exportación CSV; `AuditLog` model con savepoint para aislamiento de transacciones
- **RBAC** — roles `admin`, `operator`, `reader`; decorador `@roles_required`
- **CSRF global** — Flask-WTF con inyección automática de token via HTMX/Alpine.js
- **Rate limiting** — Flask-Limiter en rutas de login, setup, password reset y endpoints sensibles
- **Dashboard** — KPIs 24h, gráfico de ataques por hora, top categorías, mapa coroplético de origen geográfico (jsvectormap)
- **Docker Compose VPS** — stack de producción sin código fuente; healthchecks; volúmenes nombrados para configs OBS

### Seguridad
- Bot challenge: respuesta correcta nunca expuesta en JS; verificación HMAC server-side; cookie `HttpOnly + Secure + SameSite=Lax`; validación de `returnTo` contra open redirect
- `int()` en comprehensions de form IDs protegido con `try/except ValueError` (3 rutas)
- Campo `syslog_host` validado con regex allowlist antes de interpolarse en config Fluent-bit
- `datetime.utcnow()` reemplazado por `datetime.now(timezone.utc).replace(tzinfo=None)`
- Endpoint `syslog-test`: validación de formato de host + resolución DNS con bloqueo de loopback y link-local
- `forwarded_for` como clave de rate limiting: advertencia en UI con Alpine.js

---

*WardNode — gestión WAF para equipos que operan su propio stack de seguridad.*
