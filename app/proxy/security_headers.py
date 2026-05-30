import re

from app.extensions import db
from app.models import SecurityHeader, Site


# CSP completa para la consola: permite los 4 CDNs externos que usa wardnode
# (Bootstrap/Icons/HTMX desde cdn.jsdelivr.net, Alpine.js desde unpkg.com,
# Google Fonts desde fonts.googleapis.com + fonts.gstatic.com).
# 'unsafe-eval' es requerido por Alpine.js 3.x CDN build (usa new Function()
# para evaluar expresiones como x-model). Sin él, Alpine.js falla silenciosamente
# cuando CSP está activa, dejando los checkboxes en estado nativo (desmarcados).
CONSOLE_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)

# CSP genérica para sites protegidos (conservadora pero funcional)
SITE_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "frame-ancestors 'none'"
)

# Valores de CSP que se consideran "stale" para el site de consola:
# fueron creados antes de CONSOLE_CSP y deben actualizarse automáticamente.
# Solo aplica a registros con is_default=True (no customizados por el admin).
_STALE_CONSOLE_CSP_VALUES = {
    "default-src 'self'",   # valor original antes de todo cambio
    SITE_CSP,               # SITE_CSP genérico que no sirve para la consola
}

DEFAULT_SECURITY_HEADERS = [
    {
        "name": "X-Content-Type-Options",
        "value": "nosniff",
        "enabled": True,
        "always": True,
    },
    {
        "name": "X-Frame-Options",
        "value": "DENY",
        "enabled": True,
        "always": True,
    },
    {
        "name": "Referrer-Policy",
        "value": "strict-origin-when-cross-origin",
        "enabled": True,
        "always": True,
    },
    {
        "name": "Permissions-Policy",
        "value": "camera=(), microphone=(), geolocation=()",
        "enabled": True,
        "always": True,
    },
    {
        # Deprecated en Chrome/Firefox modernos; útil para IE/Edge legacy
        # y para superar escaneos de seguridad. La protección real XSS
        # viene del CSP configurado correctamente.
        "name": "X-XSS-Protection",
        "value": "1; mode=block",
        "enabled": True,
        "always": True,
    },
    {
        # HSTS ya NO se gestiona aquí — se controla via site.hsts_mode
        # (selector en el panel TLS). Este registro queda deshabilitado
        # como referencia; _render_security_headers() lo omite si
        # hsts_mode != 'off'.
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000; includeSubDomains",
        "enabled": False,
        "always": True,
    },
    {
        # Deshabilitado por defecto; el valor se ajusta según el tipo de
        # site al crear el registro (consola recibe CONSOLE_CSP).
        "name": "Content-Security-Policy",
        "value": SITE_CSP,
        "enabled": False,
        "always": True,
    },
]

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
INVALID_VALUE_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def ensure_site_security_headers(site: Site) -> list[SecurityHeader]:
    existing = {header.name.lower(): header for header in site.security_headers}
    needs_commit = False

    for position, item in enumerate(DEFAULT_SECURITY_HEADERS, start=1):
        if item["name"].lower() not in existing:
            # La consola recibe un CSP que incluye sus CDNs externos y unsafe-eval
            if item["name"] == "Content-Security-Policy" and site.is_console:
                value = CONSOLE_CSP
            else:
                value = item["value"]
            db.session.add(
                SecurityHeader(
                    site=site,
                    name=item["name"],
                    value=value,
                    enabled=item["enabled"],
                    always=item["always"],
                    position=position,
                    is_default=True,
                )
            )
            needs_commit = True

    # Actualizar registros CSP stale para el site de consola.
    # Ocurre cuando el registro fue creado antes de introducir CONSOLE_CSP
    # (p.ej. con el valor original "default-src 'self'"). Solo se actualiza
    # si is_default=True para no pisar valores customizados por el admin.
    if site.is_console and "content-security-policy" in existing:
        csp_header = existing["content-security-policy"]
        if csp_header.is_default and csp_header.value in _STALE_CONSOLE_CSP_VALUES:
            csp_header.value = CONSOLE_CSP
            needs_commit = True

    if needs_commit:
        db.session.commit()
    return site.security_headers


def validate_security_header(name: str, value: str) -> list[str]:
    errors = []
    if not name:
        errors.append("El nombre del header es obligatorio.")
    elif not HEADER_NAME_RE.match(name):
        errors.append(f"Header invalido: {name}.")

    if not value:
        errors.append(f"El valor de {name or 'header'} es obligatorio.")
    elif INVALID_VALUE_RE.search(value):
        errors.append(f"El valor de {name} contiene caracteres no permitidos.")

    if len(name) > 120:
        errors.append("El nombre del header excede 120 caracteres.")
    if len(value) > 1000:
        errors.append(f"El valor de {name} excede 1000 caracteres.")

    return errors
