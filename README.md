# WardNode

Base para una consola defensiva que administra un proxy inverso Nginx con ModSecurity y OWASP CRS:

- Flask app factory y blueprints modulares
- SQLAlchemy + Postgres para sitios, dominios, categorias y eventos
- Flask-Migrate / Alembic
- Jinja2, HTMX, Bootstrap y Alpine.js
- Proxy Docker basado en `owasp/modsecurity-crs:nginx`
- Configuracion generada para dominios, upstreams, certificados y categorias OWASP
- pytest

## Uso local

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
flask db init
flask db migrate -m "initial"
flask db upgrade
flask run
```

## Docker

```powershell
Copy-Item .env.example .env
docker compose up --build
```

La consola queda disponible en `http://localhost:5000`.
El proxy publica `http://localhost` y `https://localhost`.

## Flujo base

1. Entrar a la consola.
2. Crear el admin inicial en `/auth/setup`.
3. Iniciar sesion.
4. Registrar un sitio con dominio y upstream interno.
5. Habilitar o deshabilitar categorias OWASP por sitio.
6. Configurar certificados personalizados o marcar Let's Encrypt.
7. Generar configuracion Nginx.
8. Recargar el contenedor `proxy` cuando se quiera aplicar la nueva configuracion.

## Roles

- `admin`: administra usuarios y ejecuta todas las acciones del proxy.
- `operator`: ejecuta acciones del proxy, pero no puede crear usuarios.
- `reader`: solo puede ver paneles y detalles.

## Politicas de trafico por dominio

Cada sitio registrado tiene su propia politica `traffic_policy`. No se aplica una configuracion global unica: cada dominio puede activar o desactivar `limit_req`, definir requests por segundo, burst, `nodelay`, activar `limit_conn`, definir conexiones maximas y escoger la clave de aplicacion.

La generacion de Nginx crea:

- `generated/nginx/00-zones.conf`: zonas `limit_req_zone` y `limit_conn_zone` por sitio.
- `generated/nginx/site-*.conf`: `limit_req` y `limit_conn` aplicados dentro del `location /` del dominio correspondiente.

## Cabeceras de seguridad por dominio

Cada sitio tiene cabeceras de seguridad propias. La UI muestra las cabeceras default como filas editables, no como texto crudo. Cada fila valida nombre y valor antes de guardar; si alguna fila contiene error, no se persiste ningun cambio.

Defaults creados por sitio:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security` deshabilitada por defecto hasta configurar TLS
- `Content-Security-Policy` deshabilitada por defecto para evitar romper aplicaciones protegidas sin revision

## OWASP CRS y reglas personalizadas

Las categorias CRS incluyen familias principales y subcategorias operables por tag, por ejemplo protocolo, method enforcement, protocol attack, multipart, DoS, reputacion IP, SQLi, XSS, LFI, RFI, RCE, PHP, Java, Node.js, session fixation y paranoia levels 1-4. La activacion/desactivacion se traduce a `SecRuleRemoveByTag` en la configuracion generada.

Cada sitio tambien puede definir reglas ModSecurity personalizadas. La app valida estructura antes de guardar:

- Solo `SecRule` y `SecAction`.
- IDs obligatorios en el rango reservado `1000000-1999999`.
- Sin IDs duplicados en el bloque.
- Sin `include`, `exec:`, `lua:` ni `ctl:ruleEngine=Off`.
- Sin comillas simples, porque la regla se emite dentro del bloque inline de Nginx `modsecurity_rules`.

Ejemplo:

```apache
SecRule REQUEST_HEADERS:User-Agent "@contains badbot" "id:1000001,phase:1,deny,status:403,msg:\"Bad bot\""
```

## Nginx extra por dominio

Cada sitio puede tener configuracion extra en dos contextos separados:

- Directivas `server`, por ejemplo `client_max_body_size 20m;`.
- Directivas `location /`, por ejemplo WebSocket o buffering:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_buffering off;
```

Antes de guardar, la app valida las lineas y, cuando el binario `nginx` esta disponible, ejecuta una validacion equivalente a `nginx -t` sobre una configuracion temporal. Si hay error, no se guarda.

## Recuperacion de contrasena

La recuperacion se habilita solo despues de que exista un admin. Los tokens se guardan hasheados, expiran y son de un solo uso. La aplicacion no registra tokens ni secretos. Para desarrollo local puede activarse `PASSWORD_RESET_SHOW_TOKEN=true`; en produccion debe integrarse un proveedor de correo y mantenerlo en `false`.

## Let's Encrypt

El compose incluye un servicio `certbot` bajo profile. Ejemplo:

```powershell
docker compose --profile certbot run --rm certbot certonly --webroot -w /var/www/certbot -d app.example.com --email admin@example.com --agree-tos --no-eff-email
```

Luego marca Let's Encrypt en el sitio, genera Nginx y recarga el proxy.

## Notas

La base deja preparado el almacenamiento y la generacion de configuracion. La emision automatica de certificados Let's Encrypt y la ingesta real del audit log JSON de ModSecurity quedan como modulos ampliables.

## Tests

```powershell
pytest
```

## Seguridad

La linea base de seguridad esta documentada en `SECURITY.md` y aplicada en la app con CSRF global, token para HTMX mutante, headers de seguridad, cookies configurables para produccion y rate limits en endpoints mutantes.
