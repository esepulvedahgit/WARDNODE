# Security Baseline

Este proyecto se desarrolla con una linea base inspirada en OWASP ASVS, OWASP Cheat Sheet Series, Flask Security Considerations, OWASP API Security Top 10, NIST SSDF y CISA Secure by Design.

## Controles obligatorios

- Todo formulario `POST`, `PUT`, `PATCH` o `DELETE` debe usar CSRF. Para HTMX mutante, enviar `X-CSRFToken`.
- En produccion, activar cookies `Secure`, `HttpOnly` y `SameSite`.
- Aplicar rate limit en login, registro, MFA, reset password y endpoints mutantes sensibles.
- Toda accion sobre recursos debe verificar autorizacion por recurso antes de mutar estado.
- No registrar secretos, tokens, certificados privados, llaves, passwords ni datos sensibles.
- No usar SQL crudo sin parametros. Preferir SQLAlchemy ORM/query builder.
- No exponer stack traces en produccion. Usar handlers genericos y logs internos.

## Estado actual

- CSRF esta habilitado globalmente con `Flask-WTF`.
- HTMX agrega `X-CSRFToken` para metodos mutantes desde `app/static/js/app.js`.
- Cookies tienen `HttpOnly` y `SameSite=Lax`; `Secure` se controla con `SESSION_COOKIE_SECURE=true`.
- `Flask-Limiter` esta configurado y aplicado a los endpoints mutantes existentes.
- Login, setup inicial, recuperacion de contrasena y creacion de usuarios tienen rate limit.
- RBAC esta aplicado con roles `admin`, `operator` y `reader`.
- Los tokens de recuperacion se guardan hasheados, expiran y son de un solo uso.
- `limit_req` y `limit_conn` se generan como politica por dominio, no como default global.
- Las cabeceras de seguridad se gestionan por dominio y por fila, con validacion antes de guardar.
- Las reglas ModSecurity personalizadas se validan antes de guardar y usan un rango de IDs reservado para reglas locales.
- La configuracion extra de Nginx se valida antes de persistir y no permite directivas de alto riesgo como `include`, `root`, `alias` o `ssl_certificate_key`.
- Las paginas de error usan respuesta generica para `500`.
- Las rutas actuales no usan SQL crudo.
- El Audit Log registra todas las acciones del operador (cambios de configuracion, inicios de sesion, errores). Escritura via `log_audit()` en `app/audit/helpers.py` con `SAVEPOINT` de SQLAlchemy para no contaminar la transaccion del llamador. Nunca registra secretos, tokens ni datos sensibles. Accesible solo para `admin` en `/audit/`.
- Los secretos almacenados en base de datos (credenciales MaxMind, SMTP, secreto TOTP) se cifran con Fernet usando `WARDNODE_SECRET_KEY`. Se descifran en memoria unicamente cuando se usan.
- TOTP 2FA disponible por usuario. El secreto pendiente de confirmacion se guarda en sesion (`_totp_pending`), nunca en base de datos hasta confirmar con un codigo valido.

## Pendiente

- Integrar proveedor de correo para recuperacion de contrasena en produccion.
