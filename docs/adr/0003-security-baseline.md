# ADR-0003: Baseline de seguridad de la aplicación

## Estado

Aceptado.

## Fecha

2026-05-03

## Contexto

La aplicación maneja sesiones de usuario, datos potencialmente sensibles y acciones
mutantes sobre recursos. Sin una línea base de seguridad acordada, los controles se
aplican de forma inconsistente y las brechas aparecen en los bordes entre componentes.

Las fuentes de criterio son: OWASP ASVS, OWASP Cheat Sheet Series, Flask Security
Considerations, OWASP API Security Top 10, NIST SSDF, CISA Secure by Design,
CWE Top 25 y CISA KEV.

## Decisión

Se adopta el siguiente baseline de seguridad como conjunto mínimo no negociable.
Cualquier excepción requiere un ADR específico con justificación y mitigación.

### Secretos y configuración

- Sin secretos hardcodeados en código ni en repositorio.
- Variables sensibles exclusivamente en `.env` (no versionado) o sistema de secretos.
- `DEBUG=False` en producción; errores genéricos al usuario.

### Autenticación y sesiones

- Cookies de sesión con flags `Secure`, `HttpOnly` y `SameSite=Lax` como mínimo.
- Rate limiting aplicado a: login, registro, MFA, recuperación de contraseña y
  cualquier endpoint con costo computacional elevado.
- No registrar passwords, tokens, cookies, claves ni códigos MFA en logs.

### Autorización

- Validación de autorización por recurso, no solo por rol.
- No confiar en datos del cliente: campos ocultos, claims de URL, parámetros
  manipulables o cabeceras controlables por el usuario.

### CSRF

- Toda acción mutante (POST, PUT, PATCH, DELETE) que use sesión/cookies debe
  incluir protección CSRF.
- Endpoints de API que usen tokens Bearer están exentos si no aceptan cookies de sesión.

### Base de datos

- Sin SQL crudo salvo necesidad justificada y siempre con parámetros (nunca
  interpolación de strings).
- SQLAlchemy como ORM principal; queries crudas documentadas y revisadas.

### Logging y trazabilidad

- Registrar eventos de seguridad relevantes: intentos de login fallidos, cambios
  de credenciales, accesos denegados.
- No incluir datos sensibles en ningún nivel de log.

### Dependencias

- No agregar dependencias sin justificación explícita.
- Mantener dependencias actualizadas; revisar advisories antes de subir versiones
  en producción.

## Consecuencias

### Positivas

- Superficie de ataque reducida por defecto en toda la aplicación.
- Controles consistentes: no dependen del criterio individual de cada PR.
- Cumplimiento base con OWASP ASVS nivel 1 para la mayoría de los controles.
- Facilita auditorías: el baseline está documentado y es verificable.

### Negativas / Trade-offs

- Rate limiting y validación CSRF añaden complejidad de configuración inicial.
- Requiere disciplina en code review para detectar desviaciones.
- Algunos controles (ej. autorización por recurso) requieren más código que
  una verificación simple de rol.

### Riesgos

- Desactivación silenciosa de controles: si un control se desactiva para "simplificar"
  sin documentación, el baseline deja de ser confiable.
  Mitigación: regla explícita en `.claude/rules/50-security.md`; advertencia obligatoria
  si se propone eliminar un control sin alternativa.
- Falsa sensación de seguridad: este baseline cubre los controles transversales, pero
  no reemplaza el análisis de amenazas por funcionalidad.

## Condiciones de reevaluación

Se revisará si:

- La aplicación incorpora autenticación federada (OAuth2/OIDC), que requiere controles
  adicionales no cubiertos por este ADR.
- Se introducen endpoints públicos de API con modelo de autenticación diferente
  (tokens Bearer, API keys), que requieren su propio ADR de seguridad de API.
- Una auditoría externa identifica controles faltantes en el baseline.
