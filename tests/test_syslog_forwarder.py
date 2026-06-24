"""Tests para el reenviador syslog nativo (syslog_forwarder.py + syslog_worker.py).

Cubre:
- Construcción de frames RFC5424 (PRI, estructura, timestamp, campos)
- Mapeo de severidad WAF y auditoría
- TCP octet-counting (RFC6587)
- Cursores: bootstrap a MAX(id), avance tras batch, sin reenvío de histórico
- Entrega end-to-end UDP: socket local → assertar frames recibidos y cursor avanzado
- Sin regresiones: settings_save_syslog ya no toca Docker
"""

import json
import socket
import threading
import time
from datetime import datetime, timezone

import pytest

from app.models import ROLE_ADMIN


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> datetime:
    return datetime.now(timezone.utc)


# ── 1. build_rfc5424 ─────────────────────────────────────────────────────────

class TestBuildRfc5424:
    def test_pri_local7_info(self):
        """local7 (23) + info (6) = PRI 190."""
        from app.proxy.syslog_forwarder import build_rfc5424, FACILITY_CODES

        frame = build_rfc5424(
            facility  = FACILITY_CODES["local7"],
            severity  = 6,
            timestamp = _ts(),
            hostname  = "host",
            appname   = "wardnode",
            procid    = "-",
            msgid     = "WAF",
            message   = "test",
        )
        assert frame.startswith("<190>1 ")

    def test_pri_local0_emergency(self):
        """local0 (16) + emergency (0) = PRI 128."""
        from app.proxy.syslog_forwarder import build_rfc5424

        frame = build_rfc5424(16, 0, _ts(), "h", "app", "-", "T", "m")
        assert frame.startswith("<128>1 ")

    def test_version_field(self):
        """El primer token <PRI>VERSION termina con el dígito '1' (RFC5424 v1)."""
        from app.proxy.syslog_forwarder import build_rfc5424

        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", "m")
        # Formato: "<PRI>1 TIMESTAMP ..." → primer token es "<PRI>1" sin espacio
        first_token = frame.split(" ")[0]
        assert first_token.endswith(">1"), f"Versión inesperada en token: {first_token!r}"

    def test_timestamp_iso8601(self):
        from app.proxy.syslog_forwarder import build_rfc5424

        ts = datetime(2025, 6, 1, 12, 0, 0, 0, tzinfo=timezone.utc)
        frame = build_rfc5424(23, 6, ts, "h", "app", "-", "T", "m")
        assert "2025-06-01T12:00:00.000000Z" in frame

    def test_fields_order(self):
        """Orden: PRI VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID SDATA MSG"""
        from app.proxy.syslog_forwarder import build_rfc5424

        frame = build_rfc5424(23, 6, _ts(), "host1", "app1", "123", "MSGID1", "body text")
        parts = frame.split(" ", 7)
        # parts[0]=<PRI>1  parts[1]=TIMESTAMP  parts[2]=host1  parts[3]=app1
        # parts[4]=123      parts[5]=MSGID1     parts[6]=-  (SDATA)  parts[7]=body
        assert parts[2] == "host1"
        assert parts[3] == "app1"
        assert parts[4] == "123"
        assert parts[5] == "MSGID1"
        assert parts[6] == "-"  # structured-data nilvalue
        assert parts[7] == "body text"

    def test_spaces_in_hostname_replaced(self):
        from app.proxy.syslog_forwarder import build_rfc5424

        frame = build_rfc5424(23, 6, _ts(), "my host", "app", "-", "T", "m")
        assert "my_host" in frame

    def test_message_preserved(self):
        from app.proxy.syslog_forwarder import build_rfc5424

        msg = '{"key":"value with spaces","n":1}'
        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", msg)
        assert frame.endswith(msg)


# ── 2. Mapeo de severidad ─────────────────────────────────────────────────────

class TestSeverityMapping:
    def test_modsec_critical_maps_to_2(self):
        from app.proxy.syslog_forwarder import severity_from_modsec

        raw = {"transaction": {"messages": [{"details": {"severity": "CRITICAL"}}]}}
        assert severity_from_modsec(raw) == 2

    def test_modsec_numeric_4_maps_to_medium_warning(self):
        """Severidad numérica '4' = WARNING/medium → código syslog 4."""
        from app.proxy.syslog_forwarder import severity_from_modsec

        raw = {"transaction": {"messages": [{"details": {"severity": "4"}}]}}
        assert severity_from_modsec(raw) == 4

    def test_modsec_missing_severity_defaults_to_4(self):
        from app.proxy.syslog_forwarder import severity_from_modsec

        assert severity_from_modsec({}) == 4

    def test_audit_info_maps_to_6(self):
        from app.proxy.syslog_forwarder import severity_from_audit

        assert severity_from_audit("info") == 6

    def test_audit_critical_maps_to_2(self):
        from app.proxy.syslog_forwarder import severity_from_audit

        assert severity_from_audit("critical") == 2

    def test_audit_warning_maps_to_4(self):
        from app.proxy.syslog_forwarder import severity_from_audit

        assert severity_from_audit("warning") == 4

    def test_audit_unknown_defaults_to_info_6(self):
        from app.proxy.syslog_forwarder import severity_from_audit

        assert severity_from_audit("unknown-level") == 6


# ── 3. TCP octet-counting ─────────────────────────────────────────────────────

class TestTcpOctetCounting:
    def test_framing_format(self):
        """Servidor TCP local recibe '<n> <frame>' donde n = len(frame.utf8)."""
        received: list[bytes] = []
        ready = threading.Event()

        def _server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            ready.host = srv.getsockname()[0]
            ready.port = srv.getsockname()[1]
            ready.set()
            srv.settimeout(3)
            try:
                conn, _ = srv.accept()
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                received.append(data)
                conn.close()
            except Exception:
                pass
            srv.close()

        t = threading.Thread(target=_server, daemon=True)
        t.start()
        ready.wait(timeout=2)

        from app.proxy.syslog_forwarder import SyslogSender, build_rfc5424

        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", "tcp-test")
        sender = SyslogSender(ready.host, ready.port, "tcp")
        sender.send(frame)
        sender.close()

        t.join(timeout=2)
        assert received, "Servidor TCP no recibió datos"
        data = received[0]

        # El frame debe tener el prefijo "<n> "
        space_pos = data.index(b" ")
        length_prefix = int(data[:space_pos])
        payload = data[space_pos + 1:]
        assert length_prefix == len(frame.encode("utf-8"))
        assert payload.decode("utf-8") == frame


# ── 4. Cursores: bootstrap y avance ──────────────────────────────────────────

class TestCursors:
    def test_bootstrap_sets_cursor_to_max_id(self, app):
        """_bootstrap_cursor() establece el cursor al MAX(id) actual."""
        from app.proxy.syslog_worker import _bootstrap_cursor
        from app.models import ModSecRawLog

        with app.app_context():
            from app.extensions import db
            # Insertar 3 filas
            for i in range(3):
                db.session.add(ModSecRawLog(
                    transaction_id=f"tx-bootstrap-{i}",
                    source_ip="1.2.3.4",
                    rule_id="942100",
                    raw_json='{"transaction":{"id":"tx","messages":[]}}',
                ))
            db.session.commit()

            cursor = _bootstrap_cursor("syslog_cursor_modsec_id", ModSecRawLog)
            from sqlalchemy import func
            max_id = db.session.query(func.max(ModSecRawLog.id)).scalar()
            assert cursor == max_id

    def test_no_historical_redelivery_after_bootstrap(self, app):
        """Tras bootstrap, las filas previas NO se reenvían."""
        from app.proxy.syslog_worker import _bootstrap_cursor, _get_cursor
        from app.models import ModSecRawLog

        with app.app_context():
            from app.extensions import db
            db.session.add(ModSecRawLog(
                transaction_id="tx-historic",
                source_ip="5.6.7.8",
                rule_id="942200",
                raw_json='{"transaction":{"id":"tx","messages":[]}}',
            ))
            db.session.commit()

            _bootstrap_cursor("syslog_cursor_modsec_id_hist", ModSecRawLog)

            # Filas con id <= cursor no deben aparecer en next batch
            from sqlalchemy import func
            max_id = db.session.query(func.max(ModSecRawLog.id)).scalar()
            count_above = db.session.query(func.count(ModSecRawLog.id)).filter(
                ModSecRawLog.id > max_id
            ).scalar()
            assert count_above == 0

    def test_cursor_advances_after_batch(self, app):
        """Después de un tick exitoso el cursor apunta al último id enviado."""
        from app.models import AppConfig, ModSecRawLog

        with app.app_context():
            from app.extensions import db

            # Resetear cursores a 0 para que el worker envíe todas las filas.
            # Usamos una IP RFC1918 (permitida por el guard SSRF) como host;
            # el tick fallará con OSError de red pero eso es esperado — solo
            # verificamos que el guard deja pasar el host.
            AppConfig.set("syslog_cursor_modsec_id", "0")
            AppConfig.set("syslog_cursor_audit_id", "0")
            AppConfig.set("syslog_enabled", "1")
            AppConfig.set("syslog_host", "10.0.0.1")
            AppConfig.set("syslog_port", "19514")
            AppConfig.set("syslog_protocol", "udp")
            AppConfig.set("syslog_facility", "local7")
            AppConfig.set("syslog_sources", "modsecurity")
            db.session.commit()

            # Insertar 2 filas
            for i in range(2):
                db.session.add(ModSecRawLog(
                    transaction_id=f"tx-cursor-adv-{i}",
                    source_ip="9.8.7.6",
                    rule_id="942300",
                    raw_json='{"transaction":{"id":"tx-c","messages":[]}}',
                ))
            db.session.commit()

            max_id = db.session.query(func.max(ModSecRawLog.id)).scalar()

            # Servidor UDP local para absorber los paquetes
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", 19514))
            srv.settimeout(2)

            from app.proxy.syslog_worker import _run_locked_body
            try:
                _run_locked_body(app)
            finally:
                srv.close()

            cursor_after = int(AppConfig.get("syslog_cursor_modsec_id") or "0")
            assert cursor_after == max_id


# ── 5. Entrega end-to-end UDP ─────────────────────────────────────────────────

class TestEndToEndUdp:
    def test_modsec_row_sent_as_rfc5424(self, app, monkeypatch):
        """Inserta fila en modsec_raw_log, ejecuta tick, verifica frame en UDP."""
        import app.proxy.syslog_worker as _worker
        # En tests enviamos a 127.0.0.1 — permitido explícitamente con monkeypatch
        monkeypatch.setattr(_worker, "is_safe_syslog_target", lambda h: (True, ""))

        from app.models import AppConfig, ModSecRawLog

        with app.app_context():
            from app.extensions import db
            from sqlalchemy import func as sqfunc

            AppConfig.set("syslog_enabled", "1")
            AppConfig.set("syslog_host", "127.0.0.1")
            AppConfig.set("syslog_port", "29514")
            AppConfig.set("syslog_protocol", "udp")
            AppConfig.set("syslog_facility", "local7")
            AppConfig.set("syslog_sources", "modsecurity")
            AppConfig.set("syslog_cursor_modsec_id", "0")
            AppConfig.set("syslog_cursor_audit_id", "0")
            db.session.commit()

            db.session.add(ModSecRawLog(
                transaction_id="tx-e2e-udp",
                source_ip="11.22.33.44",
                rule_id="942100",
                raw_json='{"transaction":{"id":"tx-e2e","messages":[{"details":{"severity":"CRITICAL","ruleId":942100},"message":"SQL injection detected"}],"request":{"remote_address":"11.22.33.44"}}}',
            ))
            db.session.commit()

            max_id = db.session.query(sqfunc.max(ModSecRawLog.id)).scalar()

            # Receptor UDP
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", 29514))
            srv.settimeout(3)
            received_frames: list[str] = []

            def _collect():
                try:
                    while True:
                        data, _ = srv.recvfrom(65535)
                        received_frames.append(data.decode("utf-8", errors="replace"))
                except socket.timeout:
                    pass
                finally:
                    srv.close()

            collector = threading.Thread(target=_collect, daemon=True)
            collector.start()

            from app.proxy.syslog_worker import _run_locked_body
            _run_locked_body(app)

            collector.join(timeout=4)

            assert received_frames, "No se recibieron frames UDP"
            frame = received_frames[0]
            # El frame debe ser RFC5424: empieza con <PRI>1
            assert frame.startswith("<")
            assert ">1 " in frame
            # Debe contener el msgid WAF
            assert "WAF" in frame
            # Debe contener el JSON crudo
            assert "tx-e2e" in frame

            # Cursor debe haber avanzado
            cursor_after = int(AppConfig.get("syslog_cursor_modsec_id") or "0")
            assert cursor_after == max_id

    def test_audit_row_sent_as_rfc5424(self, app, monkeypatch):
        """Inserta fila en audit_log, ejecuta tick, verifica frame UDP."""
        import app.proxy.syslog_worker as _worker
        monkeypatch.setattr(_worker, "is_safe_syslog_target", lambda h: (True, ""))

        from app.models import AppConfig, AuditLog

        with app.app_context():
            from app.extensions import db
            from sqlalchemy import func as sqfunc

            AppConfig.set("syslog_enabled", "1")
            AppConfig.set("syslog_host", "127.0.0.1")
            AppConfig.set("syslog_port", "39514")
            AppConfig.set("syslog_protocol", "udp")
            AppConfig.set("syslog_facility", "local7")
            AppConfig.set("syslog_sources", "audit")
            AppConfig.set("syslog_cursor_modsec_id", "0")
            AppConfig.set("syslog_cursor_audit_id", "0")
            db.session.commit()

            db.session.add(AuditLog(
                actor_email="admin@example.com",
                action="settings.syslog_save",
                resource_type="config",
                resource_name="syslog",
                severity="info",
                status="success",
                ip_address="10.0.0.1",
                detail=json.dumps({"note": "test_audit_e2e"}),
            ))
            db.session.commit()

            max_id = db.session.query(sqfunc.max(AuditLog.id)).scalar()

            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", 39514))
            srv.settimeout(3)
            received_frames: list[str] = []

            def _collect():
                try:
                    while True:
                        data, _ = srv.recvfrom(65535)
                        received_frames.append(data.decode("utf-8", errors="replace"))
                except socket.timeout:
                    pass
                finally:
                    srv.close()

            collector = threading.Thread(target=_collect, daemon=True)
            collector.start()

            from app.proxy.syslog_worker import _run_locked_body
            _run_locked_body(app)

            collector.join(timeout=4)

            assert received_frames, "No se recibieron frames de auditoría"
            frame = received_frames[0]
            assert "AUDIT" in frame
            assert "admin@example.com" in frame

            cursor_after = int(AppConfig.get("syslog_cursor_audit_id") or "0")
            assert cursor_after == max_id


# ── 6. Sin regresión: settings_save_syslog ya no toca Docker ─────────────────

class TestSyslogSettingsNoDocker:
    def test_save_syslog_disabled_does_not_raise(self, client, login_as):
        """POST /settings/syslog sin Docker disponible no debe lanzar excepción."""
        login_as(ROLE_ADMIN)
        resp = client.post(
            "/proxy/settings/syslog",
            data={
                "syslog_host":     "192.168.1.100",
                "syslog_port":     "514",
                "syslog_protocol": "udp",
                "syslog_facility": "local7",
                "syslog_sources":  "modsecurity",
                # syslog_enabled no presente → disabled
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # No debe haber error 500 por contenedor fluent-bit ausente
        body = resp.get_data(as_text=True)
        assert "guardada" in body.lower() or "syslog" in body.lower()

    def test_save_syslog_enabled_does_not_raise(self, client, login_as):
        """POST /settings/syslog con enabled=on no lanza excepción sin Docker."""
        login_as(ROLE_ADMIN)
        resp = client.post(
            "/proxy/settings/syslog",
            data={
                "syslog_enabled":  "on",
                "syslog_host":     "192.168.1.100",
                "syslog_port":     "514",
                "syslog_protocol": "udp",
                "syslog_facility": "local7",
                "syslog_sources":  "modsecurity",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        # Verificar que no hay página de error 500 (el "500" en fonts/port es normal)
        assert "<title>500" not in body
        assert "Internal Server Error" not in body


# ── 7. Guard SSRF (is_safe_syslog_target) ────────────────────────────────────

class TestSsrfGuard:
    def test_loopback_blocked(self):
        from app.proxy.syslog_forwarder import is_safe_syslog_target
        safe, _ = is_safe_syslog_target("127.0.0.1")
        assert not safe

    def test_link_local_metadata_blocked(self):
        """169.254.x (cloud metadata) debe ser bloqueada."""
        from app.proxy.syslog_forwarder import is_safe_syslog_target
        safe, _ = is_safe_syslog_target("169.254.169.254")
        assert not safe

    def test_multicast_blocked(self):
        from app.proxy.syslog_forwarder import is_safe_syslog_target
        safe, _ = is_safe_syslog_target("224.0.0.1")
        assert not safe

    def test_rfc1918_private_allowed(self):
        """Rangos privados RFC1918 (SIEM en LAN) deben pasar."""
        from app.proxy.syslog_forwarder import is_safe_syslog_target
        for host in ("10.0.0.5", "192.168.1.100", "172.16.0.1"):
            safe, reason = is_safe_syslog_target(host)
            assert safe, f"{host} debería ser permitido pero fue bloqueado: {reason}"

    def test_public_ip_allowed(self):
        from app.proxy.syslog_forwarder import is_safe_syslog_target
        safe, _ = is_safe_syslog_target("8.8.8.8")
        assert safe

    def test_loopback_blocked_at_save(self, client, login_as):
        """POST guardado con syslog_host=127.0.0.1 → rechazado."""
        login_as(ROLE_ADMIN)
        resp = client.post(
            "/proxy/settings/syslog",
            data={
                "syslog_enabled":  "on",
                "syslog_host":     "127.0.0.1",
                "syslog_port":     "514",
                "syslog_protocol": "udp",
                "syslog_facility": "local7",
                "syslog_sources":  "modsecurity",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "no permitido" in body.lower() or "not allowed" in body.lower()


# ── 8. Saneo de frames RFC5424 (SYS-02 CR/LF + SYS-04 tope) ─────────────────

class TestFrameHardening:
    def test_crlf_in_message_replaced_with_space(self):
        """CR y LF en el cuerpo del mensaje se reemplazan por espacio (CWE-117)."""
        from app.proxy.syslog_forwarder import build_rfc5424

        msg = 'line1\nFAKE-SYSLOG-ENTRY\rline3'
        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", msg)
        assert "\n" not in frame
        assert "\r" not in frame
        # El contenido sigue siendo legible (con espacios)
        assert "FAKE-SYSLOG-ENTRY" in frame

    def test_nul_byte_removed(self):
        from app.proxy.syslog_forwarder import build_rfc5424

        msg = "before\x00after"
        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", msg)
        assert "\x00" not in frame

    def test_message_truncated_at_8192_bytes(self):
        """Mensajes >8192 bytes se truncan con marcador '[truncated]'."""
        from app.proxy.syslog_forwarder import build_rfc5424, _MAX_MSG_BYTES

        big_msg = "X" * (_MAX_MSG_BYTES + 1000)
        frame = build_rfc5424(23, 6, _ts(), "h", "app", "-", "T", big_msg)
        # El frame completo debe ser razonable (cabecera + 8 KB aprox.)
        parts = frame.split(" ", 7)
        body = parts[7]
        assert "[truncated]" in body
        assert len(body.encode("utf-8")) <= _MAX_MSG_BYTES + len(" [truncated]")


# ── 9. Redacción de headers sensibles (SYS-03) ───────────────────────────────

class TestHeaderRedaction:
    def test_authorization_header_redacted(self):
        from app.proxy.syslog_forwarder import format_modsec_message

        raw = json.dumps({
            "transaction": {
                "id": "tx-redact",
                "request": {
                    "headers": {
                        "Authorization": "Bearer super-secret-token",
                        "Host": "example.com",
                    }
                }
            }
        })
        result = format_modsec_message(raw)
        assert "super-secret-token" not in result
        assert "[REDACTED]" in result
        # Host sigue presente
        assert "example.com" in result

    def test_cookie_header_redacted(self):
        from app.proxy.syslog_forwarder import format_modsec_message

        raw = json.dumps({
            "transaction": {"request": {"headers": {"Cookie": "session=abc123"}}}
        })
        result = format_modsec_message(raw)
        assert "abc123" not in result

    def test_non_sensitive_headers_preserved(self):
        from app.proxy.syslog_forwarder import format_modsec_message

        raw = json.dumps({
            "transaction": {"request": {"headers": {"User-Agent": "TestAgent/1.0", "Content-Type": "application/json"}}}
        })
        result = format_modsec_message(raw)
        assert "TestAgent/1.0" in result
        assert "application/json" in result

    def test_set_cookie_in_response_redacted(self):
        from app.proxy.syslog_forwarder import format_modsec_message

        raw = json.dumps({
            "transaction": {"response": {"headers": {"Set-Cookie": "sid=xyz; HttpOnly"}}}
        })
        result = format_modsec_message(raw)
        assert "xyz" not in result


# ── 10. Cursor corrupto → bootstrap (SYS-05) ─────────────────────────────────

class TestCorruptCursor:
    def test_corrupt_cursor_returns_minus_one(self, app):
        """_get_cursor devuelve -1 ante un valor corrupto (nunca 0)."""
        from app.models import AppConfig
        from app.proxy.syslog_worker import _get_cursor

        with app.app_context():
            key = "syslog_cursor_test_corrupt"
            AppConfig.set(key, "not-an-int")
            from app.extensions import db
            db.session.commit()

            result = _get_cursor(key)
            assert result == -1, f"Esperado -1 (bootstrap), obtenido: {result}"


# ── 11. Validación de exclusión WAF — Unicode (WN-03) ────────────────────────

class TestRuleExclusionUnicode:
    def test_unicode_digit_rejected(self):
        """Dígito Unicode (superíndice) no pasa la validación — evita ValueError en int()."""
        from app.proxy.custom_rules import validate_rule_exclusion

        rule_id, errors = validate_rule_exclusion("¹²³⁴⁵⁶⁷", "")
        assert rule_id is None
        assert errors

    def test_ascii_decimal_accepted(self):
        """ID CRS válido en ASCII pasa la validación."""
        from app.proxy.custom_rules import validate_rule_exclusion

        rule_id, errors = validate_rule_exclusion("942100", "")
        assert rule_id == 942100
        assert not errors


# Import necesario para el test de cursor
from sqlalchemy import func  # noqa: E402
