from __future__ import annotations

import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)

_DEFAULT_PROXY_CONTAINER = "wardnode-proxy"

_SEVERITY_MAP = {
    # Texto (ModSecurity v2 / fixtures de tests)
    "EMERGENCY": "critical", "ALERT": "critical", "CRITICAL": "critical",
    "ERROR": "high", "WARNING": "medium",
    "NOTICE": "low", "INFO": "low", "DEBUG": "low",
    # Numérico syslog (libmodsecurity v3 con SecAuditLogFormat JSON)
    # 0=EMERGENCY, 1=ALERT, 2=CRITICAL → critical
    # 3=ERROR → high  |  4=WARNING → medium  |  5-7=NOTICE/INFO/DEBUG → low
    "0": "critical", "1": "critical", "2": "critical",
    "3": "high", "4": "medium",
    "5": "low", "6": "low", "7": "low",
}

_TAG_TO_CATEGORY = {
    # CRS 3.x  (split("/")[-1].upper() sobre "OWASP_CRS/WEB_ATTACK/SQL_INJECTION")
    "SQL_INJECTION":      "sql-injection",
    "XSS":                "xss",
    "RCE":                "rce",
    "LFI":                "lfi",
    "RFI":                "rfi",
    "SCANNER":            "scanner",
    "BRUTE_FORCE":        "brute-force",
    "COMMAND_INJECTION":  "command-injection",
    "PHP_INJECTION":      "php-injection",
    "JAVA_INJECTION":     "java-injection",
    "SESSION_FIXATION":   "session-fixation",
    "PROTOCOL_VIOLATION": "protocol-violation",
    "PROTOCOL_ANOMALY":   "protocol-anomaly",
    # CRS 4.x  (tag completo uppercased, ej. "attack-sqli" → "ATTACK-SQLI")
    "ATTACK-SQLI":              "sql-injection",
    "ATTACK-XSS":               "xss",
    "ATTACK-RCE":               "rce",
    "ATTACK-LFI":               "lfi",
    "ATTACK-RFI":               "rfi",
    "ATTACK-PROTOCOL":          "protocol-violation",
    "ATTACK-PROTOCOL-ANOMALY":  "protocol-anomaly",
    # CRS 4.x: nombres reales de OWASP CRS 4.x (los antiguos ATTACK-PHP-INJECTION,
    # ATTACK-JAVA-INJECTION, ATTACK-SCANNER, ATTACK-SESSION-FIXATION NO existen en
    # CRS 4.x — los tags reales son los siguientes).
    "ATTACK-INJECTION-PHP":     "php-injection",
    "ATTACK-INJECTION-JAVA":    "java-injection",
    "ATTACK-INJECTION-GENERIC": "injection-generic",
    "ATTACK-REPUTATION-SCANNER":   "scanner",
    "ATTACK-REPUTATION-CRAWLER":   "scanner",
    "ATTACK-REPUTATION-SCRIPTING": "scanner",
    "ATTACK-FIXATION":          "session-fixation",
    "ATTACK-DISCLOSURE":        "data-leakage",
    "ATTACK-DOS":               "dos",
    # Compatibilidad con nombres antiguos (por si alguna versión los emite)
    "ATTACK-SCANNER":           "scanner",
    "ATTACK-COMMAND-INJECTION": "command-injection",
    "ATTACK-PHP-INJECTION":     "php-injection",
    "ATTACK-JAVA-INJECTION":    "java-injection",
    "ATTACK-SESSION-FIXATION":  "session-fixation",
}

# Fallback determinista por prefijo de ID de regla CRS (independiente de la versión
# y del tag). Se usa cuando ningún tag matchea. Nota: 949 (anomaly score blocking)
# se deja sin mapear a propósito → queda "unknown" si es lo único que hay.
_RULE_ID_PREFIX_TO_CATEGORY = {
    "913": "scanner",
    "920": "protocol-violation",
    "921": "protocol-violation",
    "930": "lfi",
    "931": "rfi",
    "932": "rce",
    "933": "php-injection",
    "941": "xss",
    "942": "sql-injection",
    "943": "session-fixation",
    "944": "java-injection",
}


def _parse_category(tags: list) -> str:
    """Mapea una lista de tags a una categoría conocida, o 'unknown' si ninguno matchea.

    Se conserva para compatibilidad; la ruta principal es _categorize(), que además
    inspecciona todos los mensajes y aplica el fallback por ID de regla.
    """
    for tag in tags:
        segment = tag.split("/")[-1].upper()
        if segment in _TAG_TO_CATEGORY:
            return _TAG_TO_CATEGORY[segment]
    return "unknown"


def _category_from_rule_ids(rule_ids: list) -> str | None:
    """Deriva la categoría desde el prefijo de 3 dígitos de cualquier ID de regla CRS."""
    for rid in rule_ids:
        if rid and len(str(rid)) >= 3:
            cat = _RULE_ID_PREFIX_TO_CATEGORY.get(str(rid)[:3])
            if cat:
                return cat
    return None


def _categorize(messages: list) -> str:
    """Determina la categoría inspeccionando TODOS los mensajes de la transacción.

    Orden: 1) primer tag de ataque reconocido en cualquier mensaje;
           2) fallback por prefijo de ID de regla CRS; 3) 'unknown'.
    """
    rule_ids = []
    for msg in messages:
        details = msg.get("details", {}) if isinstance(msg, dict) else {}
        for tag in details.get("tags", []) or []:
            segment = tag.split("/")[-1].upper()
            if segment in _TAG_TO_CATEGORY:
                return _TAG_TO_CATEGORY[segment]
        rid = details.get("ruleId")
        if rid is not None:
            rule_ids.append(rid)
    return _category_from_rule_ids(rule_ids) or "unknown"


def _parse_line(line: str) -> dict | None:
    try:
        data = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    txn = data.get("transaction", {})
    if not txn:
        return None

    messages = txn.get("messages", [])
    if not messages:
        return None

    req = txn.get("request", {})
    resp = txn.get("response", {})
    msg0 = messages[0]
    details = msg0.get("details", {})

    status_code = resp.get("http_code", 403)
    action = "block" if status_code == 403 else "detect"

    # libmodsecurity v3 con SecAuditLogFormat JSON emite severity como número
    # syslog en string ("0".."7"); v2 lo emite como texto ("CRITICAL", etc.).
    # str() tolera int, strip()+upper() normaliza ambos formatos.
    raw_severity = str(details.get("severity", "")).strip().upper()
    severity = _SEVERITY_MAP.get(raw_severity, "medium")

    headers = req.get("headers", {})
    host = headers.get("Host") or headers.get("host") or "unknown"
    # strip port if present (e.g. "example.com:443")
    domain = host.split(":")[0].lower()

    rule_id = details.get("ruleId")
    rule_id = str(rule_id) if rule_id is not None else None

    return {
        "transaction_id": txn.get("id"),
        "domain":         domain,
        "source_ip":      req.get("remote_address") or txn.get("client_ip") or txn.get("clientIp") or "",
        "method":         req.get("method", "GET"),
        "path":           req.get("uri", "/"),
        "status_code":    status_code,
        "action":         action,
        "rule_id":        rule_id,
        "severity":       severity,
        "message":        msg0.get("message", ""),
        "category":       _categorize(messages),
    }


def _process_line(app, line: str) -> None:
    parsed = _parse_line(line)
    if not parsed:
        return

    with app.app_context():
        from sqlalchemy.exc import IntegrityError
        from app.extensions import db
        from app.models import AttackEvent, Site
        from app.proxy.geoip import get_country_code

        site = Site.query.filter_by(domain=parsed["domain"]).first()

        country_code = None
        if parsed["source_ip"]:
            try:
                country_code = get_country_code(parsed["source_ip"])
            except Exception:
                pass

        event = AttackEvent(
            site_id=site.id if site else None,
            domain=parsed["domain"],
            source_ip=parsed["source_ip"],
            country_code=country_code,
            method=parsed["method"],
            path=parsed["path"],
            status_code=parsed["status_code"],
            action=parsed["action"],
            rule_id=parsed["rule_id"],
            severity=parsed["severity"],
            message=parsed["message"],
            category=parsed["category"],
            transaction_id=parsed["transaction_id"],
        )
        db.session.add(event)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        except Exception:
            db.session.rollback()
            raise


def _docker_log_loop(app, container_name: str) -> None:
    import docker
    import docker.errors

    client = docker.from_env()

    while True:
        try:
            container = client.containers.get(container_name)
            # Stream from current time forward — don't replay historical logs
            since = int(time.time())
            log.info("ingest: streaming Docker logs from %s", container_name)
            for raw in container.logs(stream=True, follow=True, since=since):
                line = raw.decode("utf-8", errors="replace").strip()
                if not line.startswith("{"):
                    continue
                try:
                    _process_line(app, line)
                except Exception as exc:
                    log.warning("ingest: error processing line: %s", exc)

            # logs() generator exhausted means container stopped
            log.warning("ingest: log stream ended for %s, retrying in 10s", container_name)
            time.sleep(10)

        except docker.errors.NotFound:
            log.warning("ingest: container %s not found, retrying in 10s", container_name)
            time.sleep(10)
        except Exception as exc:
            log.error("ingest: unexpected error: %s", exc)
            time.sleep(5)


def start_ingest_thread(app) -> threading.Thread | None:
    container_name = os.environ.get("WARDNODE_PROXY_CONTAINER", _DEFAULT_PROXY_CONTAINER)

    try:
        import docker
        docker.from_env().ping()
    except Exception as exc:
        log.debug("ingest: Docker not available (%s), ingest thread not started", exc)
        return None

    t = threading.Thread(
        target=_docker_log_loop,
        args=(app, container_name),
        name="modsec-ingest",
        daemon=True,
    )
    t.start()
    log.info("ingest: started modsec-ingest thread (streaming %s Docker logs)", container_name)
    return t
