# Arquitectura del proyecto

WardNode es una consola Flask para administrar un proxy inverso Nginx con ModSecurity y OWASP CRS. La consola es el plano de control: guarda configuracion en base de datos, genera archivos Nginx en disco y recarga el proxy. El trafico de aplicaciones nunca pasa por Flask, salvo endpoints auxiliares como la verificacion del desafio anti-bot.

## Componentes

- `console`: aplicacion Flask/Gunicorn. Expone la UI, autentica usuarios, guarda configuracion y genera archivos en `generated/nginx/`.
- `proxy`: contenedor `owasp/modsecurity-crs:nginx` customizado con `ngx_http_geoip2_module`. Lee los archivos generados desde `/etc/nginx/generated`.
- `db`: PostgreSQL para usuarios, sitios, politicas, headers, reglas, auditoria y configuracion global.
- `wardnode-wf-agent`: daemon systemd en el host. Expone un socket Unix para operaciones de firewall/CrowdSec.
- `observability`: perfil opcional con Grafana Alloy, Loki, Prometheus y Grafana.

## Blueprints

- `auth`: login, setup inicial, usuarios, recuperacion de password y MFA TOTP.
- `main`: redireccion raiz y endpoints simples de estado.
- `proxy`: gestion de sitios, WAF, TLS, headers, reglas, GeoIP, bot protection, syslog y render de configs.
- `modules`: modulos opcionales WF, CS, OBS y reinicio de servicios.
- `audit`: consulta y exportacion de auditoria.

## Flujo De Configuracion Del Proxy

1. Un usuario `admin` u `operator` modifica un sitio o politica desde la UI.
2. La ruta Flask valida input y persiste cambios con SQLAlchemy.
3. `_apply_nginx()` llama `render_nginx_configs()` y luego `reload_nginx()`.
4. Se escriben archivos como `00-zones.conf`, `00-geoip.conf`, `10-blocklist.map` y `site-{id}-{domain}.conf`.
5. El proxy recarga Nginx y aplica la nueva configuracion.

El modelo central es `Site`. De el dependen `TrafficPolicy`, `SecurityHeader`, `CustomModSecurityRule`, `NginxExtraConfig`, `BotProtectionConfig`, `SiteRuleSetting` y `AttackEvent`.

## WF Y CS

WardNode WF y WardNode CS interactuan con el host mediante el agente `host-agent/wardnode-wf-agent.py`.

```
Flask console -> /app/sockets/wardnode-wf.sock -> /run/wardnode/wardnode-wf.sock -> wardnode-wf-agent.py
```

El protocolo usa un prefijo de longitud de 4 bytes big-endian seguido de JSON. Flask valida los parametros antes de enviar el comando y el agente los vuelve a validar antes de ejecutar cualquier accion. El agente usa `subprocess.run()` con lista de argumentos, nunca `shell=True`.

WF permite consultar estado, inicializar UFW, permitir/bloquear puertos o IPs, eliminar reglas y cambiar soporte IPv6 de UFW.

CS reutiliza el mismo socket/agente para consultar CrowdSec, listar decisiones, ban/unban y arrancar/detener/reiniciar `crowdsec` y `crowdsec-firewall-bouncer`. CS requiere WF habilitado porque el bouncer actua sobre UFW.

## OBS

WardNode OBS no usa el socket WF. La consola usa Docker SDK y Docker CLI contra `/var/run/docker.sock` para gestionar contenedores del perfil `obs`:

- `wardnode-loki`
- `wardnode-grafana`
- `wardnode-alloy`
- `wardnode-prometheus`

Si los contenedores ya existen, se arrancan con Docker SDK. Si no existen, se ejecuta `docker compose -f docker-compose.vps.yml --profile obs up -d --no-build` desde el directorio indicado por `WARDNODE_PROJECT_DIR`.

Alloy recolecta logs de Nginx, ModSecurity y CrowdSec hacia Loki. Tambien expone metricas del host mediante `prometheus.exporter.unix` y las envia a Prometheus con `remote_write`. Grafana se sirve bajo `/obs/` a traves del proxy; la consola inyecta `obs.conf` en el contenedor proxy y recarga Nginx.

## Seguridad

- CSRF global en formularios y HTMX mutante; `/proxy/bot-verify` esta exento porque usa token HMAC propio.
- RBAC con roles `admin`, `operator` y `reader`.
- Secretos en `AppConfig` se cifran con `WARDNODE_SECRET_KEY` cuando corresponde.
- Reglas ModSecurity personalizadas, headers y snippets Nginx tienen validadores dedicados.
- El socket WF esta restringido por permisos de filesystem y grupo `wardnode`.
- Montar `/var/run/docker.sock` da a la consola control efectivo del Docker host; por eso OBS y reinicios de contenedores son funciones solo para `admin`.

## Deuda Conocida

- `proxy/routes.py` y `modules/routes.py` concentran bastante logica de aplicacion y side effects.
- `_apply_nginx()` silencia errores para facilitar desarrollo local; en produccion conviene hacer visible el fallo de render/reload.
- `AttackEvent` existe en base de datos, pero la ingesta real de eventos ModSecurity hacia esa tabla no esta implementada en el flujo principal.
- Faltan tests de integracion para WF, CS y OBS.
