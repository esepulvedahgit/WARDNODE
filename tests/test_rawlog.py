"""Tests para la feature "Pestaña Log — visor audit log crudo ModSecurity".

Cubre:
  - Modelo ModSecRawLog (campos, dedup)
  - _store_raw_log en ingest.py
  - _logs_search_filter (escape de metacaracteres ILIKE)
  - is_prune_due (función pura)
  - prune_and_archive (salvaguarda de contraseña, borrado)
  - RBAC y anti-traversal en rutas
  - logs_list: respuesta completa vs. parcial HTMX
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
    ModSecRawLog,
)


# ---------------------------------------------------------------------------
# Grupo 1: Modelo y dedup
# ---------------------------------------------------------------------------


def test_modsec_raw_log_model_fields(app):
    """ModSecRawLog se puede crear e insertar con todos los campos."""
    with app.app_context():
        entry = ModSecRawLog(
            transaction_id="txn-001",
            source_ip="10.0.0.1",
            rule_id="941100",
            raw_json='{"transaction": {"id": "txn-001"}}',
        )
        db.session.add(entry)
        db.session.commit()

        saved = ModSecRawLog.query.filter_by(transaction_id="txn-001").first()
        assert saved is not None
        assert saved.source_ip == "10.0.0.1"
        assert saved.rule_id == "941100"
        assert saved.created_at is not None


def test_modsec_raw_log_dedup_by_transaction_id(app):
    """Insertar dos entradas con el mismo transaction_id → solo una queda."""
    from sqlalchemy.exc import IntegrityError

    with app.app_context():
        entry1 = ModSecRawLog(
            transaction_id="dup-txn",
            raw_json='{"first": true}',
        )
        db.session.add(entry1)
        db.session.commit()

        entry2 = ModSecRawLog(
            transaction_id="dup-txn",
            raw_json='{"second": true}',
        )
        db.session.add(entry2)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()

        count = ModSecRawLog.query.filter_by(transaction_id="dup-txn").count()
        assert count == 1


# ---------------------------------------------------------------------------
# Grupo 2: _store_raw_log en ingest.py
# ---------------------------------------------------------------------------


def test_store_raw_log_persists(app):
    """_store_raw_log persiste una línea JSON cruda."""
    from app.proxy.ingest import _store_raw_log

    raw = {
        "transaction": {"id": "abc123", "client_ip": "1.2.3.4"},
        "messages": [{"details": {"ruleId": "941100"}}],
    }
    _store_raw_log(app, raw)

    with app.app_context():
        saved = ModSecRawLog.query.filter_by(transaction_id="abc123").first()
        assert saved is not None
        assert saved.source_ip == "1.2.3.4"
        assert saved.rule_id == "941100"


def test_store_raw_log_dedup_silent(app):
    """_store_raw_log no lanza excepción en duplicate transaction_id."""
    from app.proxy.ingest import _store_raw_log

    raw = {"transaction": {"id": "dup-id"}}
    _store_raw_log(app, raw)
    _store_raw_log(app, raw)  # debe silenciarse, no lanzar

    with app.app_context():
        count = ModSecRawLog.query.filter_by(transaction_id="dup-id").count()
        assert count == 1


# ---------------------------------------------------------------------------
# Grupo 3: Búsqueda ILIKE con metacaracteres
# ---------------------------------------------------------------------------


def test_logs_search_filter_escapes_percent(app):
    """Búsqueda con % no dispara SQL injection ni error."""
    from app.proxy.routes import _logs_search_filter

    with app.app_context():
        entry = ModSecRawLog(raw_json='{"ip": "1.2.3.4", "path": "/test%20"}')
        db.session.add(entry)
        db.session.commit()

        result = _logs_search_filter(ModSecRawLog.query, "test%20").all()
        assert len(result) == 1


def test_logs_search_filter_escapes_underscore(app):
    """Búsqueda con _ no actúa como wildcard."""
    from app.proxy.routes import _logs_search_filter

    with app.app_context():
        entry = ModSecRawLog(raw_json='{"path": "/_wn_challenge"}')
        db.session.add(entry)
        db.session.commit()

        # Buscar con _ literal — debe encontrar
        assert _logs_search_filter(ModSecRawLog.query, "_wn_challenge").count() == 1

        # Si _ fuera wildcard, "/XwnXchallenge" aparecería también; comprobamos que no.
        entry2 = ModSecRawLog(raw_json='{"path": "/XwnXchallenge"}')
        db.session.add(entry2)
        db.session.commit()

        results = _logs_search_filter(ModSecRawLog.query, "_wn_challenge").all()
        assert all("_wn_challenge" in r.raw_json for r in results)


# ---------------------------------------------------------------------------
# Grupo 4: is_prune_due (función pura)
# ---------------------------------------------------------------------------


def test_is_prune_due_never_run():
    """Si last_run_at es None, el prune siempre está due si hour >= prune_hour."""
    from app.proxy.rawlog_worker import is_prune_due

    now = datetime(2025, 1, 15, 4, 0)  # 04:00
    assert is_prune_due(now, prune_hour=3, last_run_at=None) is True


def test_is_prune_due_already_ran_today():
    """Si ya corrió hoy, no está due."""
    from app.proxy.rawlog_worker import is_prune_due

    now = datetime(2025, 1, 15, 4, 0)
    last = datetime(2025, 1, 15, 3, 5)  # mismo día
    assert is_prune_due(now, prune_hour=3, last_run_at=last) is False


def test_is_prune_due_yesterday():
    """Si corrió ayer, está due."""
    from app.proxy.rawlog_worker import is_prune_due

    now = datetime(2025, 1, 15, 4, 0)
    last = datetime(2025, 1, 14, 3, 5)
    assert is_prune_due(now, prune_hour=3, last_run_at=last) is True


def test_is_prune_due_before_hour():
    """Si aún no es la hora configurada, no está due."""
    from app.proxy.rawlog_worker import is_prune_due

    now = datetime(2025, 1, 15, 2, 0)  # 02:00, antes de las 3
    assert is_prune_due(now, prune_hour=3, last_run_at=None) is False


# ---------------------------------------------------------------------------
# Grupo 5: prune_and_archive — salvaguarda y prune
# ---------------------------------------------------------------------------


def test_prune_and_archive_no_backup_deletes(app, tmp_path, monkeypatch):
    """Con backup_before_prune=0, borra filas antiguas sin crear zip."""
    from app.proxy import rawlog_service
    from app.models import AppConfig

    monkeypatch.setattr(rawlog_service, "rawlog_archive_dir", lambda: tmp_path)

    with app.app_context():
        AppConfig.set("modsec_rawlog_retention_days", "1")
        # No configurar backup_before_prune (por defecto no está activo)

        old = ModSecRawLog(raw_json='{"old": true}')
        db.session.add(old)
        db.session.commit()

        # Forzar created_at a hace 2 días
        db.session.execute(
            db.text("UPDATE modsec_raw_log SET created_at = :d WHERE id = :id"),
            {"d": datetime.utcnow() - timedelta(days=2), "id": old.id},
        )
        db.session.commit()

        result = rawlog_service.prune_and_archive(datetime.utcnow())

    assert result["deleted_rows"] >= 1
    assert result["archive_file"] is None
    assert list(tmp_path.glob("*.zip")) == []


def test_prune_and_archive_skips_without_password(app, tmp_path, monkeypatch):
    """Con backup habilitado pero sin contraseña, NO borra nada."""
    from app.proxy import rawlog_service
    from app.models import AppConfig

    monkeypatch.setattr(rawlog_service, "rawlog_archive_dir", lambda: tmp_path)

    with app.app_context():
        AppConfig.set("modsec_rawlog_backup_before_prune", "1")
        AppConfig.set("modsec_rawlog_retention_days", "1")
        # No configurar modsec_rawlog_zip_password

        old = ModSecRawLog(raw_json='{"old": true}')
        db.session.add(old)
        db.session.commit()

        db.session.execute(
            db.text("UPDATE modsec_raw_log SET created_at = :d WHERE id = :id"),
            {"d": datetime.utcnow() - timedelta(days=2), "id": old.id},
        )
        db.session.commit()

        result = rawlog_service.prune_and_archive(datetime.utcnow())

    assert result["skipped_reason"] == "backup_enabled_but_no_password"

    # La fila no debe haberse borrado
    with app.app_context():
        assert ModSecRawLog.query.count() >= 1


# ---------------------------------------------------------------------------
# Grupo 6: RBAC y anti-traversal (rutas)
# ---------------------------------------------------------------------------


def test_logs_list_requires_login(client):
    """Sin login → redirect a /auth/login."""
    resp = client.get("/proxy/logs")
    assert resp.status_code in (302, 401)
    assert "login" in resp.headers.get("Location", "")


def test_logs_list_reader_forbidden(client, login_as):
    """ROLE_READER no puede ver el log crudo (contiene payloads/credenciales íntegros)."""
    login_as(role=ROLE_READER)
    resp = client.get("/proxy/logs")
    assert resp.status_code == 403


def test_logs_list_operator_can_access(client, login_as):
    """ROLE_OPERATOR puede ver el log crudo."""
    login_as(role=ROLE_OPERATOR)
    resp = client.get("/proxy/logs")
    assert resp.status_code == 200


def test_archive_download_admin_only(client, login_as):
    """ROLE_OPERATOR no puede descargar archives."""
    login_as(role=ROLE_OPERATOR)
    resp = client.get("/proxy/logs/archives/download/wardnode-modsec-log-20250101-000000.zip")
    assert resp.status_code == 403


def test_archive_download_bad_name(client, login_as):
    """Nombre con traversal → rechazado antes de tocar el filesystem."""
    login_as(role=ROLE_ADMIN)
    resp = client.get("/proxy/logs/archives/download/../etc/passwd")
    # Flask no permite .. en rutas de URL — puede devolver 404 directamente
    assert resp.status_code != 200


def test_archive_download_regex_invalid(client, login_as):
    """Nombre que no pasa el regex → no devuelve 200."""
    login_as(role=ROLE_ADMIN)
    resp = client.get("/proxy/logs/archives/download/invalid-name.zip")
    assert resp.status_code != 200


# ---------------------------------------------------------------------------
# Grupo 7: logs_list HTMX parcial vs. completo
# ---------------------------------------------------------------------------


def test_logs_list_full_page(client, login_as):
    """Sin HX-Request → HTML completo (contiene 'Log ModSecurity')."""
    login_as(role=ROLE_ADMIN)
    resp = client.get("/proxy/logs")
    assert resp.status_code == 200
    assert b"Log ModSecurity" in resp.data


def test_logs_list_htmx_partial(client, login_as):
    """Con HX-Request → parcial (no contiene </html>)."""
    login_as(role=ROLE_ADMIN)
    resp = client.get("/proxy/logs", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert b"</html>" not in resp.data


# ---------------------------------------------------------------------------
# Grupo 8: Tope de longitud de búsqueda (H2) y truncación de 64 KB (H4)
# ---------------------------------------------------------------------------


def test_logs_search_term_truncated_to_128(client, login_as):
    """Término de búsqueda >128 chars se recorta: la ruta responde 200 sin error."""
    login_as(role=ROLE_ADMIN)
    long_q = "A" * 300
    resp = client.get(f"/proxy/logs?q={long_q}")
    assert resp.status_code == 200


def test_store_raw_log_truncation_respects_64kb(app):
    """raw_json almacenado nunca supera _RAW_JSON_MAX_BYTES (64 KB) tras truncar."""
    from app.proxy.ingest import _RAW_JSON_MAX_BYTES, _store_raw_log

    with app.app_context():
        big_body = "X" * 200_000
        raw_dict = {
            "transaction": {
                "id": "txn-trunc-test",
                "client_ip": "1.2.3.4",
                "request": {"body": big_body},
            },
            "messages": [{"details": {"ruleId": "941100"}}],
        }
        _store_raw_log(app, raw_dict)

        saved = ModSecRawLog.query.filter_by(transaction_id="txn-trunc-test").first()
        assert saved is not None
        assert len(saved.raw_json.encode("utf-8")) <= _RAW_JSON_MAX_BYTES
        import json as _json
        parsed = _json.loads(saved.raw_json)
        assert parsed.get("_truncated") is True
