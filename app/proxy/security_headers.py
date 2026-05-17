import re

from app.extensions import db
from app.models import SecurityHeader, Site


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
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000; includeSubDomains",
        "enabled": False,
        "always": True,
    },
    {
        "name": "Content-Security-Policy",
        "value": "default-src 'self'",
        "enabled": False,
        "always": True,
    },
]

HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
INVALID_VALUE_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def ensure_site_security_headers(site: Site) -> list[SecurityHeader]:
    existing = {header.name.lower(): header for header in site.security_headers}
    for position, item in enumerate(DEFAULT_SECURITY_HEADERS, start=1):
        if item["name"].lower() not in existing:
            db.session.add(
                SecurityHeader(
                    site=site,
                    name=item["name"],
                    value=item["value"],
                    enabled=item["enabled"],
                    always=item["always"],
                    position=position,
                    is_default=True,
                )
            )
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

