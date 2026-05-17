# Security Baseline

## Fuentes

- OWASP ASVS
- OWASP Cheat Sheet Series
- Flask Security Considerations
- OWASP API Security Top 10
- NIST SSDF
- CISA Secure by Design

## Controles mínimos

- CSRF en formularios y HTMX mutante.
- Cookies Secure, HttpOnly y SameSite en producción.
- Rate limit en login, registro, MFA y reset password.
- Autorización por recurso.
- No registrar secretos ni datos sensibles.
- No usar SQL crudo sin parámetros.
- No exponer stack traces en producción.