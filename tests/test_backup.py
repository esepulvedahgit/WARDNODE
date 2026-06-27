"""Tests del módulo de backup/restore.

Cubren la lógica pura (retención, manifest, validación del zip, scheduler),
el cifrado AES del zip, las rutas con RBAC/re-auth y el colector de DB con
Docker SDK mockeado. pg_restore real queda como prueba manual.
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pyotp
import pytest
import pyzipper

from app.backup.service import (
    MANIFEST_FORMAT_VERSION,
    BackupError,
    RestoreValidationError,
    list_backups,
    prune_backups,
    resolve_backup_path,
    validate_backup_zip,
)
from app.backup.worker import is_backup_due
from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER, AppConfig, User

PASSWORD = "zip-password-123"


def _fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


@pytest.fixture()
def backup_env(tmp_path, monkeypatch):
    """Redirige BACKUP_DIR a tmp_path."""
    monkeypatch.setenv("WARDNODE_BACKUP_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture()
def fernet_env(monkeypatch):
    """Clave Fernet efímera para tests que cifran secretos."""
    monkeypatch.setenv("WARDNODE_SECRET_KEY", _fernet_key())


def _make_zip(directory: Path, name="wardnode-backup-20260611-010000.zip",
              manifest_extra=None, files=None, password=PASSWORD,
              skip_checksum_of=None, corrupt_checksum_of=None):
    """Construye un zip de backup válido (o adulterado) para tests."""
    files = files if files is not None else {"db/wardnode.pgdump": b"FAKE-PGDUMP"}
    checksums = {}
    for arcname, payload in files.items():
        if arcname == skip_checksum_of:
            continue
        digest = hashlib.sha256(payload).hexdigest()
        if arcname == corrupt_checksum_of:
            digest = "0" * 64
        checksums[arcname] = digest

    manifest = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "app": "wardnode",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reason": "test",
        "db_engine": "postgresql",
        "alembic_head": None,
        "pg_server_version": None,
        "components": {"db": "included"},
        "checksums": checksums,
    }
    manifest.update(manifest_extra or {})

    path = directory / name
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        for arcname, payload in files.items():
            zf.writestr(arcname, payload)
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("README-RESTORE.md", "restore docs")
    return path


# ── Retención y nombres ───────────────────────────────────────────────

class TestPruneAndNames:

    def test_prune_keeps_newest(self, app, backup_env):
        for i in range(5):
            (backup_env / f"wardnode-backup-2026061{i}-000000.zip").write_bytes(b"x")
        removed = prune_backups(2)
        assert len(removed) == 3
        remaining = [b["name"] for b in list_backups()]
        assert remaining == [
            "wardnode-backup-20260614-000000.zip",
            "wardnode-backup-20260613-000000.zip",
        ]

    def test_prune_ignores_fresh_part_files(self, app, backup_env):
        part = backup_env / "wardnode-backup-20260611-000000.zip.part"
        part.write_bytes(b"x")
        prune_backups(1)
        assert part.exists()  # .part fresco no se toca

    def test_prune_removes_stale_part_files(self, app, backup_env):
        import os
        part = backup_env / "wardnode-backup-20260601-000000.zip.part"
        part.write_bytes(b"x")
        old = time.time() - 25 * 3600
        os.utime(part, (old, old))
        prune_backups(5)
        assert not part.exists()

    @pytest.mark.parametrize("bad_name", [
        "../etc/passwd",
        "wardnode-backup-20260611-000000.zip/../../x",
        "/etc/passwd",
        "otra-cosa.zip",
        "wardnode-backup-2026-malformed.zip",
    ])
    def test_resolve_rejects_bad_names(self, app, backup_env, bad_name):
        with pytest.raises(BackupError):
            resolve_backup_path(bad_name)

    def test_resolve_accepts_valid_name(self, app, backup_env):
        name = "wardnode-backup-20260611-010101.zip"
        (backup_env / name).write_bytes(b"x")
        assert resolve_backup_path(name).name == name


# ── Validación del zip ────────────────────────────────────────────────

class TestValidateZip:

    def test_valid_zip_passes(self, app, backup_env):
        path = _make_zip(backup_env)
        result = validate_backup_zip(path, PASSWORD)
        assert result["manifest"]["app"] == "wardnode"
        assert result["needs_upgrade"] is False

    def test_wrong_password_rejected(self, app, backup_env):
        path = _make_zip(backup_env)
        with pytest.raises(RestoreValidationError):
            validate_backup_zip(path, "incorrecta-totalmente")

    def test_zip_without_password_cannot_open(self, app, backup_env):
        path = _make_zip(backup_env)
        with pyzipper.AESZipFile(path) as zf:
            with pytest.raises(RuntimeError):
                zf.read("manifest.json")

    def test_corrupt_checksum_rejected(self, app, backup_env):
        path = _make_zip(backup_env, corrupt_checksum_of="db/wardnode.pgdump")
        with pytest.raises(RestoreValidationError, match="checksum"):
            validate_backup_zip(path, PASSWORD)

    def test_traversal_entry_rejected(self, app, backup_env):
        path = _make_zip(backup_env, files={
            "db/wardnode.pgdump": b"x",
            "db/../../../etc/evil": b"evil",
        })
        with pytest.raises(RestoreValidationError, match="no permitida"):
            validate_backup_zip(path, PASSWORD)

    def test_unknown_entry_rejected(self, app, backup_env):
        path = _make_zip(backup_env, files={
            "db/wardnode.pgdump": b"x",
            "sneaky/file.bin": b"x",
        })
        with pytest.raises(RestoreValidationError, match="no permitida"):
            validate_backup_zip(path, PASSWORD)

    def test_unsupported_format_version_rejected(self, app, backup_env):
        path = _make_zip(backup_env, manifest_extra={"format_version": 99})
        with pytest.raises(RestoreValidationError, match="formato"):
            validate_backup_zip(path, PASSWORD)

    def test_foreign_manifest_rejected(self, app, backup_env):
        path = _make_zip(backup_env, manifest_extra={"app": "otra-app"})
        with pytest.raises(RestoreValidationError, match="WardNode"):
            validate_backup_zip(path, PASSWORD)

    def test_unknown_alembic_head_blocks(self, app, backup_env):
        # Revisión inexistente → backup de una versión más nueva → bloqueo.
        path = _make_zip(backup_env, manifest_extra={"alembic_head": "ffffffffffff"})
        with pytest.raises(RestoreValidationError, match="más nueva"):
            validate_backup_zip(path, PASSWORD)

    def test_old_alembic_head_sets_needs_upgrade(self, app, backup_env):
        from app.backup.service import _code_revisions
        _head, known = _code_revisions()
        old_rev = sorted(known)[0]  # la migración más antigua conocida
        path = _make_zip(backup_env, manifest_extra={"alembic_head": old_rev})
        result = validate_backup_zip(path, PASSWORD)
        assert result["needs_upgrade"] is True

    def test_missing_manifest_rejected(self, app, backup_env):
        path = backup_env / "wardnode-backup-20260611-020000.zip"
        with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(PASSWORD.encode())
            zf.writestr("db/wardnode.pgdump", b"x")
        with pytest.raises(RestoreValidationError, match="manifest"):
            validate_backup_zip(path, PASSWORD)


# ── Scheduler (función pura) ──────────────────────────────────────────

class TestIsBackupDue:

    def _dt(self, day, hour):
        return datetime(2026, 6, day, hour, 30, tzinfo=timezone.utc)

    def test_not_due_before_hour(self):
        assert is_backup_due(self._dt(11, 2), 3, None) is False

    def test_due_after_hour_never_run(self):
        assert is_backup_due(self._dt(11, 3), 3, None) is True

    def test_not_due_if_already_ran_today(self):
        last = self._dt(11, 3)
        assert is_backup_due(self._dt(11, 9), 3, last) is False

    def test_due_next_day(self):
        last = self._dt(10, 3)
        assert is_backup_due(self._dt(11, 3), 3, last) is True

    def test_due_after_restart_past_hour(self):
        # El proceso estuvo caído a las 03:00; arranca a las 17:00 → ejecuta.
        last = self._dt(10, 3)
        assert is_backup_due(self._dt(11, 17), 3, last) is True


# ── create_backup con colectores mockeados ────────────────────────────

class TestCreateBackup:

    @pytest.fixture()
    def configured(self, app, backup_env, fernet_env, monkeypatch):
        from app.extensions import db
        from app.encryption import encrypt_secret

        AppConfig.set("backup_zip_password", encrypt_secret(PASSWORD), encrypted=True)
        db.session.commit()

        def fake_dump(workdir):
            out = workdir / "db"
            out.mkdir(parents=True, exist_ok=True)
            (out / "wardnode.pgdump").write_bytes(b"FAKE-DUMP")
            return {"engine": "postgresql", "file": "db/wardnode.pgdump"}

        monkeypatch.setattr("app.backup.service.dump_database", fake_dump)
        monkeypatch.setattr("app.backup.service.collect_tls",
                            lambda w: "skipped: test")
        monkeypatch.setattr("app.backup.service.collect_host_state",
                            lambda w: "skipped: test")
        return backup_env

    def test_create_produces_encrypted_zip(self, app, configured):
        from app.backup.service import create_backup

        result = create_backup(reason="test")
        assert result.path.exists()
        assert result.components["db"] == "included"
        # No abre sin contraseña...
        with pyzipper.AESZipFile(result.path) as zf:
            with pytest.raises(RuntimeError):
                zf.read("manifest.json")
        # ...y valida completo con ella.
        validated = validate_backup_zip(result.path, PASSWORD)
        assert validated["manifest"]["reason"] == "test"
        assert "db/wardnode.pgdump" in validated["manifest"]["checksums"]
        # Sin restos .part
        assert not list(configured.glob("*.part"))

    def test_create_without_password_fails(self, app, backup_env):
        with pytest.raises(BackupError, match="[Cc]ontraseña"):
            from app.backup.service import create_backup
            create_backup(reason="test")


# ── Colector de DB con Docker SDK mockeado ────────────────────────────

class _FakeContainer:
    def __init__(self, exit_code=0, stdout=b"PGDUMP-BYTES", stderr=b""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def exec_run(self, cmd, environment=None, demux=False):
        self.calls.append({"cmd": cmd, "environment": environment})
        return self.exit_code, (self.stdout, self.stderr)


class TestDumpDatabase:

    @pytest.fixture()
    def fake_docker(self, monkeypatch):
        container = _FakeContainer()

        class FakeClient:
            class containers:
                @staticmethod
                def get(name):
                    return container

        import docker
        monkeypatch.setattr(docker, "from_env", lambda: FakeClient())
        return container

    def test_pg_dump_invocation(self, app, tmp_path, fake_docker, monkeypatch):
        from app.backup.collectors import dump_database

        monkeypatch.setitem(
            app.config, "SQLALCHEMY_DATABASE_URI",
            "postgresql://app:s3cret@db:5432/appdb",
        )
        meta = dump_database(tmp_path)

        assert meta["engine"] == "postgresql"
        assert (tmp_path / "db" / "wardnode.pgdump").read_bytes() == b"PGDUMP-BYTES"
        call = fake_docker.calls[0]
        # La contraseña va por env, jamás por argv.
        assert "s3cret" not in " ".join(call["cmd"])
        assert call["environment"] == {"PGPASSWORD": "s3cret"}
        assert call["cmd"][:2] == ["pg_dump", "-Fc"]

    def test_pg_dump_failure_raises(self, app, tmp_path, fake_docker, monkeypatch):
        from app.backup.collectors import CollectorError, dump_database

        fake_docker.exit_code = 1
        fake_docker.stderr = b"connection refused"
        monkeypatch.setitem(
            app.config, "SQLALCHEMY_DATABASE_URI",
            "postgresql://app:s3cret@db:5432/appdb",
        )
        with pytest.raises(CollectorError, match="pg_dump"):
            dump_database(tmp_path)


# ── Rutas: RBAC, re-auth, salvaguardas ────────────────────────────────

class TestRoutes:

    def test_index_requires_admin(self, client, login_as):
        login_as(ROLE_OPERATOR)
        assert client.get("/backup/").status_code == 403

    def test_index_renders_for_admin(self, app, client, login_as, backup_env):
        login_as(ROLE_ADMIN)
        resp = client.get("/backup/")
        assert resp.status_code == 200
        assert "Backups" in resp.get_data(as_text=True)

    def test_run_requires_admin(self, client, login_as):
        login_as(ROLE_OPERATOR)
        assert client.post("/backup/run").status_code == 403

    def test_download_rejects_traversal(self, client, login_as, backup_env):
        login_as(ROLE_ADMIN)
        resp = client.get("/backup/download/..%2F..%2Fetc%2Fpasswd",
                          follow_redirects=True)
        assert resp.status_code in (200, 404)
        # Nunca un fichero servido; o 404 del router o flash de error
        assert b"PGDUMP" not in resp.data

    def test_config_saves_scheduler(self, app, client, login_as, backup_env):
        login_as(ROLE_ADMIN)
        resp = client.post("/backup/config", data={
            "section": "scheduler", "enabled": "on", "hour": "5",
            "retention": "10", "include_tls": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert AppConfig.get("backup_enabled") == "1"
        assert AppConfig.get("backup_hour") == "5"
        assert AppConfig.get("backup_retention") == "10"
        assert AppConfig.get("backup_include_host") == "0"  # checkbox apagado

    def test_config_password_too_short_rejected(self, app, client, login_as, backup_env):
        login_as(ROLE_ADMIN)
        resp = client.post("/backup/config", data={
            "section": "password", "zip_password": "corta",
        }, follow_redirects=True)
        assert "12 caracteres" in resp.get_data(as_text=True)
        assert AppConfig.get("backup_zip_password") is None

    def test_config_password_mask_roundtrip_not_saved(self, app, client, login_as,
                                                      backup_env, fernet_env):
        from app.extensions import db
        from app.encryption import encrypt_secret

        login_as(ROLE_ADMIN)
        AppConfig.set("backup_zip_password", encrypt_secret(PASSWORD), encrypted=True)
        db.session.commit()
        original = AppConfig.get("backup_zip_password")

        # Reenviar la máscara que muestra la UI no debe sobreescribir el secreto
        masked = "*" * (len(PASSWORD) - 4) + PASSWORD[-4:]
        client.post("/backup/config", data={
            "section": "password", "zip_password": masked,
        }, follow_redirects=True)
        assert AppConfig.get("backup_zip_password") == original

    def test_restore_requires_reauth(self, app, client, login_as, backup_env):
        login_as(ROLE_ADMIN)
        path = _make_zip(backup_env)
        with path.open("rb") as f:
            resp = client.post("/backup/restore", data={
                "current_password": "INCORRECTA",
                "confirm_text": "RESTAURAR",
                "zip_password": PASSWORD,
                "backup_file": (f, path.name),
            }, content_type="multipart/form-data", follow_redirects=True)
        assert "Verificación de identidad fallida" in resp.get_data(as_text=True)

    def test_restore_requires_confirm_text(self, app, client, login_as, backup_env):
        login_as(ROLE_ADMIN, password="AdminPass123!@")
        path = _make_zip(backup_env)
        with path.open("rb") as f:
            resp = client.post("/backup/restore", data={
                "current_password": "AdminPass123!@",
                "confirm_text": "restaurar",  # minúsculas: inválido
                "zip_password": PASSWORD,
                "backup_file": (f, path.name),
            }, content_type="multipart/form-data", follow_redirects=True)
        assert "RESTAURAR" in resp.get_data(as_text=True)

    def test_restore_requires_totp_when_enabled(self, app, client, login_as,
                                                backup_env, fernet_env):
        from app.extensions import db
        from app.encryption import encrypt_secret

        user = login_as(ROLE_ADMIN, password="AdminPass123!@")
        secret = pyotp.random_base32()
        user.totp_secret = encrypt_secret(secret)
        user.totp_enabled = True
        db.session.commit()

        path = _make_zip(backup_env)
        # Sin código TOTP → re-auth falla
        with path.open("rb") as f:
            resp = client.post("/backup/restore", data={
                "current_password": "AdminPass123!@",
                "confirm_text": "RESTAURAR",
                "zip_password": PASSWORD,
                "backup_file": (f, path.name),
            }, content_type="multipart/form-data", follow_redirects=True)
        assert "Verificación de identidad fallida" in resp.get_data(as_text=True)

    def test_restore_rejects_tampered_zip(self, app, client, login_as,
                                          backup_env, monkeypatch):
        login_as(ROLE_ADMIN, password="AdminPass123!@")
        path = _make_zip(backup_env, corrupt_checksum_of="db/wardnode.pgdump")
        with path.open("rb") as f:
            resp = client.post("/backup/restore", data={
                "current_password": "AdminPass123!@",
                "confirm_text": "RESTAURAR",
                "zip_password": PASSWORD,
                "backup_file": (f, path.name),
            }, content_type="multipart/form-data", follow_redirects=True)
        assert "no pasó la validación" in resp.get_data(as_text=True)


# ── Email con adjuntos ────────────────────────────────────────────────

class TestEmailAttachments:

    @pytest.fixture()
    def smtp_spy(self, app, monkeypatch):
        from app.extensions import db

        AppConfig.set("smtp_host", "smtp.test")
        AppConfig.set("smtp_from", "wardnode@test")
        db.session.commit()

        sent = {}

        class FakeSMTP:
            def __init__(self, host, port):
                sent["host"] = host

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def login(self, u, p):
                pass

            def sendmail(self, from_, to, msg):
                sent["from"] = from_
                sent["to"] = to
                sent["msg"] = msg

        import smtplib
        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        return sent

    def test_send_email_with_attachment(self, app, smtp_spy):
        from app.email import send_email

        send_email(["ops@test"], "Asunto", "Cuerpo",
                   attachments=[("backup.zip", b"ZIPDATA", "application/zip")])
        assert smtp_spy["to"] == ["ops@test"]
        assert 'filename="backup.zip"' in smtp_spy["msg"]
        assert "application/zip" in smtp_spy["msg"]

    def test_existing_wrappers_still_work(self, app, smtp_spy):
        from app.email import send_soc_alert_email

        send_soc_alert_email(["soc@test"], "Alerta", "Cuerpo plano")
        assert smtp_spy["to"] == ["soc@test"]
        assert "Alerta" in smtp_spy["msg"]

    def test_subject_crlf_stripped(self, app, smtp_spy):
        from app.email import send_email

        send_email(["x@test"], "linea1\r\nBcc: evil@test", "Cuerpo")
        # El CRLF se reemplaza por espacios: jamás una cabecera Bcc inyectada.
        assert not any(line.startswith("Bcc:")
                       for line in smtp_spy["msg"].splitlines())


# ── Docs Backup ─────────────────────────────────────────────────────────────

def test_backup_docs_renders(client, login_as):
    login_as()
    r = client.get("/backup/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Índice" in body
    for anchor in ("vision-general", "contenido", "secreto", "restauracion-ui", "referencia"):
        assert f'id="{anchor}"' in body
        assert f'href="#{anchor}"' in body


def test_backup_docs_denied_operator(client, login_as):
    login_as(role=ROLE_OPERATOR)
    r = client.get("/backup/docs")
    assert r.status_code in (302, 403)


def test_backup_docs_button_on_panel(client, login_as):
    login_as()
    body = client.get("/backup/").get_data(as_text=True)
    assert "/backup/docs" in body


def test_backup_docs_denied_reader(client, login_as):
    login_as(role=ROLE_READER)
    r = client.get("/backup/docs")
    assert r.status_code in (302, 403)
