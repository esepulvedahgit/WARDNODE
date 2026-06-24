"""Reenviador syslog nativo: lee de modsec_raw_log y audit_log → RFC5424.

Sin dependencias de Docker. El worker (syslog_worker.py) llama a las
funciones de este módulo desde su hilo daemon.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import AuditLog, ModSecRawLog  # noqa: F401

log = logging.getLogger(__name__)

# ── Tablas de mapeo RFC5424 ───────────────────────────────────────────────────

FACILITY_CODES: dict[str, int] = {
    "kern":    0,
    "user":    1,
    "mail":    2,
    "daemon":  3,
    "auth":    4,
    "syslog":  5,
    "lpr":     6,
    "news":    7,
    "uucp":    8,
    "cron":    9,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

# RFC5424 severidades (nombre WardNode → código numérico)
SEVERITY_CODES: dict[str, int] = {
    "emergency": 0,
    "alert":     1,
    "critical":  2,
    "error":     3,
    "high":      3,   # alias WardNode → error
    "warning":   4,
    "medium":    4,   # alias WardNode → warning
    "notice":    5,
    "info":      6,
    "low":       6,   # alias WardNode → info
    "debug":     7,
}

# Mapeo audit_log.severity → código syslog
_AUDIT_SEVERITY: dict[str, int] = {
    "critical": 2,
    "error":    3,
    "warning":  4,
    "info":     6,
}

# Mapeo attack_event.severity (del ingest) → código syslog
_WAF_SEVERITY: dict[str, int] = {
    "critical": 2,
    "high":     3,
    "medium":   4,
    "low":      6,
}


# ── Construcción de frames RFC5424 ────────────────────────────────────────────

_NILVALUE    = "-"
_VERSION     = "1"
_MAX_MSG_BYTES = 8192  # tope syslog compatible con UDP MTU; previene HOL blocking (SYS-04)


def build_rfc5424(
    facility: int,
    severity: int,
    timestamp: datetime,
    hostname: str,
    appname: str,
    procid: str,
    msgid: str,
    message: str,
) -> str:
    """Construye un mensaje RFC5424 listo para enviar (sin \\n).

    PRI = facility * 8 + severity
    TIMESTAMP = ISO8601 / RFC3339 con Z
    Structured-data siempre NILVALUE ('-') — el cuerpo va en el MSG.
    """
    pri = facility * 8 + severity
    ts  = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    # Sanitizar campos de cabecera: ninguno puede contener espacios
    host  = (hostname or _NILVALUE).replace(" ", "_")[:255]
    app   = (appname  or _NILVALUE).replace(" ", "_")[:48]
    proc  = (procid   or _NILVALUE).replace(" ", "_")[:128]
    mid   = (msgid    or _NILVALUE).replace(" ", "_")[:32]
    # Sanear CR/LF/NUL del cuerpo (CWE-117 log forging) y acotar tamaño (SYS-02/04)
    safe = message.translate({0x00: None, 0x0d: 0x20, 0x0a: 0x20})
    enc = safe.encode("utf-8")
    if len(enc) > _MAX_MSG_BYTES:
        safe = enc[:_MAX_MSG_BYTES].decode("utf-8", "ignore") + " [truncated]"
    return f"<{pri}>{_VERSION} {ts} {host} {app} {proc} {mid} {_NILVALUE} {safe}"


def severity_from_modsec(raw_dict: dict) -> int:
    """Extrae la severidad syslog del JSON crudo de ModSecurity."""
    try:
        msgs = raw_dict.get("transaction", {}).get("messages", [])
        if msgs:
            raw = str(msgs[0].get("details", {}).get("severity", "")).strip().upper()
            # El hilo ingest convierte esto con _SEVERITY_MAP (mismo mapeo)
            waf_sev = {
                "EMERGENCY": "critical", "ALERT": "critical", "CRITICAL": "critical",
                "ERROR": "high", "WARNING": "medium",
                "NOTICE": "low", "INFO": "low", "DEBUG": "low",
                "0": "critical", "1": "critical", "2": "critical",
                "3": "high", "4": "medium",
                "5": "low", "6": "low", "7": "low",
            }.get(raw, "medium")
            return _WAF_SEVERITY.get(waf_sev, 4)
    except Exception:
        pass
    return 4  # default: warning


def severity_from_audit(severity_str: str) -> int:
    """Convierte audit_log.severity → código numérico syslog."""
    return _AUDIT_SEVERITY.get((severity_str or "info").lower(), 6)


_SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
})


def _redact_headers(node: object) -> object:
    """Recorre recursivamente un dict/list y redacta headers HTTP sensibles."""
    if isinstance(node, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else _redact_headers(v))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_redact_headers(x) for x in node]
    return node


def format_modsec_message(raw_json: str) -> str:
    """Formatea el JSON crudo de modsec_raw_log como cuerpo del mensaje syslog.

    Redacta headers sensibles (Authorization, Cookie, etc.) antes de enviar
    al SIEM externo. El evento, IP, URI y regla siguen presentes.
    Si el JSON no parsea lo devuelve tal cual.
    """
    try:
        return json.dumps(
            _redact_headers(json.loads(raw_json)),
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except Exception:
        return raw_json


def format_audit_message(row: "AuditLog") -> str:
    """Serializa una fila de audit_log como JSON de una sola línea."""
    payload: dict = {
        "action":         row.action,
        "actor":          row.actor_email,
        "resource_type":  row.resource_type,
        "resource_name":  row.resource_name,
        "severity":       row.severity,
        "status":         row.status,
        "ip":             row.ip_address,
    }
    if row.detail:
        try:
            payload["detail"] = json.loads(row.detail)
        except Exception:
            payload["detail"] = row.detail
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


# ── Guard anti-SSRF ──────────────────────────────────────────────────────────

def is_safe_syslog_target(host: str) -> tuple[bool, str]:
    """True si el host resuelve a un destino permitido para reenvío syslog.

    Bloquea: loopback, link-local (incl. 169.254.x metadata), reservadas,
    no-especificadas y multicast.
    PERMITE rangos privados RFC1918 (10.x/172.16-31/192.168.x) para SIEM en LAN.
    """
    try:
        resolved = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False, f"No se pudo resolver el host: {host}"
    if not resolved:
        return False, "El host no resolvió a ninguna dirección"
    for *_, sockaddr in resolved:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if (addr.is_loopback or addr.is_link_local or addr.is_reserved
                or addr.is_unspecified or addr.is_multicast):
            return False, "Host no permitido (loopback/metadata/reservada/multicast)"
    return True, ""


# ── Socket sender ─────────────────────────────────────────────────────────────

_CONNECT_TIMEOUT = 5.0   # segundos para TCP connect
_SEND_TIMEOUT    = 3.0   # segundos para sendto/sendall


class SyslogSender:
    """Envía frames RFC5424 a un servidor syslog por UDP o TCP.

    TCP usa el framing de octet-counting (RFC6587 §3.4.1):
        "<n> <frame>"
    donde <n> es la longitud en bytes del frame UTF-8.

    Reconexión perezosa en TCP: si el socket está cerrado se abre de nuevo
    en el siguiente send(). Úsalo como context manager para cierre limpio.
    """

    def __init__(self, host: str, port: int, protocol: str = "udp") -> None:
        self.host     = host
        self.port     = port
        self.protocol = protocol.lower()
        self._sock: socket.socket | None = None

    # -- context manager --

    def __enter__(self) -> "SyslogSender":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # -- envío --

    def _ensure_tcp(self) -> None:
        if self._sock is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(_CONNECT_TIMEOUT)
        s.connect((self.host, self.port))
        s.settimeout(_SEND_TIMEOUT)
        self._sock = s

    def send(self, frame: str) -> None:
        """Envía un frame RFC5424 al servidor configurado.

        Lanza excepciones de red sin capturarlas — el worker decide si
        actualizar el cursor o registrar el error.
        """
        data = frame.encode("utf-8")
        if self.protocol == "tcp":
            # RFC6587 octet-counting: length SP frame
            framed = f"{len(data)} ".encode() + data
            self._ensure_tcp()
            try:
                self._sock.sendall(framed)
            except OSError:
                # Reconexión en el siguiente intento
                self.close()
                raise
        else:
            # UDP: una sola syscall sendto
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(_SEND_TIMEOUT)
            try:
                s.sendto(data, (self.host, self.port))
            finally:
                s.close()

    def send_test(self) -> float:
        """Envía un mensaje de prueba y devuelve la latencia en ms.

        Lanza excepción si falla. Llamado desde settings_syslog_test().
        """
        frame = build_rfc5424(
            facility   = FACILITY_CODES.get("local7", 23),
            severity   = 6,  # info
            timestamp  = datetime.now(timezone.utc),
            hostname   = "wardnode",
            appname    = "wardnode",
            procid     = _NILVALUE,
            msgid      = "TEST",
            message    = '{"msg":"WardNode connectivity test"}',
        )
        t0 = time.monotonic()
        self.send(frame)
        return round((time.monotonic() - t0) * 1000, 1)
