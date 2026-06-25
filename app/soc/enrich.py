"""Enriquecimiento de incidentes SOC: AbuseIPDB (con cache local) y MITRE ATT&CK.

El enriquecimiento nunca bloquea la creación del incidente: cualquier fallo
de red, cuota o cifrado degrada con gracia (cache stale o None).
"""

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from app.encryption import EncryptionNotConfigured
from app.extensions import db
from app.models import AppConfig, ThreatIntelCache

log = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_MAX_ABUSE_RESPONSE_BYTES = 256 * 1024  # 256 KB — AbuseIPDB devuelve JSON compacto
DEFAULT_CACHE_TTL_HOURS = 24


def is_public_ip(ip: str) -> bool:
    """Verifica que ip es una dirección IP válida y enrutable públicamente.

    Descarta IPs privadas, loopback, link-local, multicast, reservadas y
    cadenas no parseables. Llamar antes de cualquier egress a AbuseIPDB o
    antes de aplicar un bloqueo automático SOAR, para evitar banear rangos
    internos o enviar basura atacante-controlada a un tercero.
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_reserved
        or obj.is_link_local
        or obj.is_multicast
        or obj.is_unspecified
    )


# Alias privado por compatibilidad con usos internos existentes
_is_public_ip = is_public_ip

# Mapeo estático categoría de AttackEvent (valores de _TAG_TO_CATEGORY en
# proxy/ingest.py) → técnicas MITRE ATT&CK.
CRS_CATEGORY_TO_MITRE: dict[str, list[dict]] = {
    "sql-injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "xss": [
        {"id": "T1189", "name": "Drive-by Compromise"},
        {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
    ],
    "rce": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "command-injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "lfi": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1083", "name": "File and Directory Discovery"},
    ],
    "rfi": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1083", "name": "File and Directory Discovery"},
    ],
    "scanner": [
        {"id": "T1595", "name": "Active Scanning"},
        {"id": "T1046", "name": "Network Service Discovery"},
    ],
    "brute-force": [
        {"id": "T1110", "name": "Brute Force"},
    ],
    "php-injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell"},
    ],
    "java-injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell"},
    ],
    "session-fixation": [
        {"id": "T1539", "name": "Steal Web Session Cookie"},
    ],
    "protocol-violation": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "protocol-anomaly": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
    ],
}

_MITRE_FALLBACK = [{"id": "T1190", "name": "Exploit Public-Facing Application"}]


def map_mitre(categories: list[str]) -> list[dict]:
    """Une las técnicas MITRE de todas las categorías, sin ids duplicados.

    El dict estático CRS_CATEGORY_TO_MITRE define el mapeo categoría→IDs;
    los nombres y tácticas se actualizan desde la base CTI local
    (mitre_attack_technique) cuando está sincronizada — fallback al nombre
    estático si la tabla está vacía.
    """
    from app.soc.mitre_cti import lookup_technique

    seen: set[str] = set()
    techniques: list[dict] = []
    for cat in categories:
        for tech in CRS_CATEGORY_TO_MITRE.get(cat, _MITRE_FALLBACK):
            if tech["id"] in seen:
                continue
            seen.add(tech["id"])
            row = lookup_technique(tech["id"])
            techniques.append({
                "id": tech["id"],
                "name": row["name"] if row else tech["name"],
                "tactic": row["tactic"] if row else "",
            })
    return techniques


def _cache_lookup(ip: str) -> tuple[dict | None, bool]:
    """Retorna (payload, fresca). payload=None si no hay fila."""
    row = ThreatIntelCache.query.filter_by(ip=ip).first()
    if row is None:
        return None, False
    try:
        ttl_hours = int(AppConfig.get("soc_abuse_cache_ttl_hours") or DEFAULT_CACHE_TTL_HOURS)
    except (TypeError, ValueError):
        ttl_hours = DEFAULT_CACHE_TTL_HOURS
    fetched = row.fetched_at
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    fresh = fetched >= datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    try:
        return json.loads(row.payload), fresh
    except (json.JSONDecodeError, TypeError):
        return None, False


def get_abuse_info(ip: str) -> dict | None:
    """Reputación AbuseIPDB de una IP, con cache local TTL. Nunca lanza.

    Solo consulta IPs públicamente enrutables (_is_public_ip). Las IPs privadas,
    loopback o no parseables devuelven None inmediatamente para no enviar datos
    atacante-controlados a un tercero ni consumir cuota innecesariamente.
    """
    # Guard: solo IPs públicas válidas van al egress (A-1).
    if not _is_public_ip(ip):
        return None

    cached, fresh = _cache_lookup(ip)
    if cached is not None and fresh:
        return cached

    try:
        api_key = AppConfig.get_secret("soc_abuseipdb_api_key")
    except EncryptionNotConfigured:
        api_key = None
    if not api_key:
        return cached  # stale o None — sin key no se consulta

    import httpx

    try:
        with httpx.stream(
            "GET",
            _ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as resp:
            resp.raise_for_status()
            total, chunks = 0, []
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > _MAX_ABUSE_RESPONSE_BYTES:
                    log.warning(
                        "soc/enrich: AbuseIPDB respuesta demasiado grande para %s", ip
                    )
                    return cached
                chunks.append(chunk)
        data = json.loads(b"".join(chunks)).get("data", {})
    except Exception as exc:
        log.warning("soc/enrich: AbuseIPDB falló para %s: %s", ip, type(exc).__name__)
        return cached

    subset = {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "countryCode": data.get("countryCode"),
        "usageType": data.get("usageType"),
        "isp": data.get("isp"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
    }

    row = ThreatIntelCache.query.filter_by(ip=ip).first()
    if row is None:
        row = ThreatIntelCache(ip=ip, payload="{}", fetched_at=datetime.now(timezone.utc))
        db.session.add(row)
    row.payload = json.dumps(subset)
    row.fetched_at = datetime.now(timezone.utc)
    db.session.commit()
    return subset
