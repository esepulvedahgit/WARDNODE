from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_LOG_PATH = "/var/log/modsec/modsec_audit.log"

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR":    "critical",
    "WARNING":  "warning",
    "NOTICE":   "warning",
    "INFO":     "low",
    "DEBUG":    "low",
}

_TAG_TO_CATEGORY = {
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
}


def _parse_category(tags: list) -> str:
    for tag in tags:
        segment = tag.split("/")[-1].upper()
        if segment in _TAG_TO_CATEGORY:
            return _TAG_TO_CATEGORY[segment]
    return "unknown"


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
    tags = details.get("tags", [])

    status_code = resp.get("http_code", 403)
    action = "block" if status_code == 403 else "detect"

    raw_severity = details.get("severity", "WARNING").upper()
    severity = _SEVERITY_MAP.get(raw_severity, "warning")

    host = req.get("headers", {}).get("Host", "unknown")
    # strip port if present (e.g. "example.com:443")
    domain = host.split(":")[0].lower()

    rule_id = details.get("ruleId")
    rule_id = str(rule_id) if rule_id is not None else None

    return {
        "transaction_id": txn.get("id"),
        "domain":         domain,
        "source_ip":      req.get("remote_address", ""),
        "method":         req.get("method", "GET"),
        "path":           req.get("uri", "/"),
        "status_code":    status_code,
        "action":         action,
        "rule_id":        rule_id,
        "severity":       severity,
        "message":        msg0.get("message", ""),
        "category":       _parse_category(tags),
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


def _tail_loop(app, log_path: str) -> None:
    path = Path(log_path)
    file_obj = None
    last_inode = None

    while True:
        try:
            if not path.exists():
                time.sleep(5)
                continue

            stat = path.stat()
            current_inode = stat.st_ino

            if file_obj is None:
                file_obj = path.open("r", encoding="utf-8", errors="replace")
                file_obj.seek(0, 2)
                last_inode = current_inode
                log.info("ingest: tailing %s", log_path)
            elif current_inode != last_inode:
                file_obj.close()
                file_obj = path.open("r", encoding="utf-8", errors="replace")
                last_inode = current_inode
                log.info("ingest: log rotated, reopened %s", log_path)

            line = file_obj.readline()
            if line:
                try:
                    _process_line(app, line)
                except Exception as exc:
                    log.warning("ingest: error processing line: %s", exc)
            else:
                time.sleep(0.5)

        except Exception as exc:
            log.error("ingest: unexpected error in tail loop: %s", exc)
            if file_obj:
                try:
                    file_obj.close()
                except Exception:
                    pass
                file_obj = None
            time.sleep(5)


def start_ingest_thread(app) -> threading.Thread | None:
    log_path = os.environ.get("MODSEC_LOG_PATH", _DEFAULT_LOG_PATH)

    if not os.path.exists(log_path):
        log.debug("ingest: %s not found, ingest thread not started", log_path)
        return None

    t = threading.Thread(
        target=_tail_loop,
        args=(app, log_path),
        name="modsec-ingest",
        daemon=True,
    )
    t.start()
    log.info("ingest: started modsec-ingest thread (tailing %s)", log_path)
    return t
