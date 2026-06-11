"""Lógica core del módulo de backup/restore.

Backup = zip AES-256 (pyzipper) con dump de la DB, certs TLS, estado WF del
host, manifest.json con checksums y README de restauración. La contraseña
del zip vive cifrada (Fernet) en AppConfig; el zip JAMÁS incluye
WARDNODE_SECRET_KEY ni ficheros .env.
"""

import hashlib
import io
import json
import logging
import os
import re
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pyzipper
from flask import current_app
from sqlalchemy import text

from app.audit.helpers import log_audit
from app.backup.collectors import (
    CollectorError,
    _db_container_name,
    collect_host_state,
    collect_tls,
    dump_database,
)
from app.extensions import db
from app.models import AppConfig

log = logging.getLogger(__name__)

MANIFEST_FORMAT_VERSION = 1

# Nombre estricto: también valida entradas de download/delete (anti traversal).
BACKUP_NAME_RE = re.compile(r"^wardnode-backup-\d{8}-\d{6}\.zip$")

# Whitelist de rutas permitidas dentro del zip.
_ALLOWED_PREFIXES = ("db/", "tls/", "host/")
_ALLOWED_FILES = ("manifest.json", "README-RESTORE.md")

MAX_ZIP_BYTES = 2 * 1024**3          # hard-cap del zip (2 GB)
MAX_UNCOMPRESSED_BYTES = 4 * 1024**3  # anti zip-bomb (total descomprimido)
MAX_COMPRESSION_RATIO = 200           # anti zip-bomb (por entrada)
_PART_ORPHAN_SECONDS = 24 * 3600

# Serializa backups dentro del mismo proceso (manual vs programado).
_create_lock = threading.Lock()

_README_RESTORE = """\
# Restauración de WardNode desde este backup

## REQUISITO CRÍTICO

Este backup NO incluye la variable de entorno `WARDNODE_SECRET_KEY`.
SIN ESA CLAVE, LOS SECRETOS CIFRADOS DEL DUMP (SMTP, MaxMind, claves SSH,
tokens LLM/Telegram, secretos TOTP) SON IRRECUPERABLES. Consérvala aparte
(gestor de contraseñas). Si la perdiste, tras restaurar ejecuta
`flask reset-encrypted-secrets` y reconfigura los secretos a mano.

## Pasos (servidor nuevo o existente)

1. Clona/copia el proyecto WardNode y restaura `.env` / `.env.prod`
   (incluyendo `WARDNODE_SECRET_KEY` y credenciales de PostgreSQL).
2. Levanta la base de datos: `docker compose up -d db`
3. Restaura: `flask backup-restore <este-zip>` (pedirá la contraseña del zip).
   El comando valida el manifest, ejecuta pg_restore, aplica migraciones
   pendientes y regenera los configs de Nginx.
4. Reinicia los contenedores: `docker compose restart console proxy`
5. (Opcional) Certificados TLS: extrae `tls/letsencrypt.tar.gz` dentro del
   volumen `letsencrypt` si quieres evitar la re-emisión automática.
6. (Opcional) Firewall WF: revisa `host/ufw-rules.txt` y re-aplica las reglas
   desde la UI del módulo WF; copia `host/protected_ports.json` a
   `/opt/wardnode/` antes de arrancar el agente para restaurar los puertos
   protegidos.
"""


class BackupError(Exception):
    """Error de backup con mensaje seguro para UI/email/audit."""


class RestoreValidationError(BackupError):
    """El zip subido no pasó la validación; no se tocó nada."""


@dataclass
class BackupResult:
    path: Path
    size_bytes: int
    manifest: dict
    components: dict[str, str] = field(default_factory=dict)


# ── Helpers de disco ──────────────────────────────────────────────────


def backup_dir() -> Path:
    d = Path(os.environ.get("WARDNODE_BACKUP_DIR", "/app/data/backups"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_backup_path(name: str) -> Path:
    """Valida el nombre contra la regex estricta y devuelve la ruta."""
    if not BACKUP_NAME_RE.match(name):
        raise BackupError("nombre de backup inválido")
    path = backup_dir() / name
    if not path.is_file():
        raise BackupError("el backup no existe")
    return path


def list_backups() -> list[dict]:
    out = []
    for p in backup_dir().glob("wardnode-backup-*.zip"):
        if not BACKUP_NAME_RE.match(p.name):
            continue
        st = p.stat()
        out.append({
            "name": p.name,
            "size_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
        })
    return sorted(out, key=lambda b: b["name"], reverse=True)


def prune_backups(retention: int) -> list[str]:
    """Conserva los `retention` backups más recientes; limpia .part huérfanos."""
    retention = max(1, retention)
    removed = []
    backups = list_backups()
    for entry in backups[retention:]:
        try:
            (backup_dir() / entry["name"]).unlink()
            removed.append(entry["name"])
        except OSError:
            pass
    now = time.time()
    for part in backup_dir().glob("*.part"):
        try:
            if now - part.stat().st_mtime > _PART_ORPHAN_SECONDS:
                part.unlink()
        except OSError:
            pass
    return removed


# ── Manifest helpers ──────────────────────────────────────────────────


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _current_alembic_head() -> str | None:
    try:
        return db.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()
    except Exception:
        return None


def _pg_server_version() -> str | None:
    try:
        if db.engine.dialect.name == "postgresql":
            return str(db.session.execute(text("SHOW server_version")).scalar())
    except Exception:
        pass
    return None


def _code_revisions() -> tuple[str | None, set[str]]:
    """(head local, set de revisiones conocidas) del directorio de migraciones."""
    try:
        from alembic.script import ScriptDirectory

        directory = current_app.extensions["migrate"].directory
        script = ScriptDirectory(str(directory))
        head = script.get_current_head()
        known = {rev.revision for rev in script.walk_revisions()}
        return head, known
    except Exception:
        return None, set()


# ── Crear backup ──────────────────────────────────────────────────────


def create_backup(*, reason: str = "manual") -> BackupResult:
    """Genera el zip cifrado completo. Lanza BackupError en fallo."""
    with _create_lock:
        return _create_backup_locked(reason)


def _create_backup_locked(reason: str) -> BackupResult:
    from app.encryption import EncryptionNotConfigured

    try:
        password = AppConfig.get_secret("backup_zip_password") or ""
    except EncryptionNotConfigured:
        password = ""
    if not password:
        _audit_failure(reason, "contraseña de backup no configurada")
        raise BackupError(
            "Contraseña del zip no configurada. Defínela en Backups → Contraseña del zip."
        )

    ts = datetime.now(timezone.utc)
    name = f"wardnode-backup-{ts.strftime('%Y%m%d-%H%M%S')}.zip"
    final_path = backup_dir() / name
    part_path = backup_dir() / (name + ".part")
    components: dict[str, str] = {}

    with tempfile.TemporaryDirectory(dir=backup_dir()) as tmp:
        workdir = Path(tmp)

        try:
            db_meta = dump_database(workdir)
            components["db"] = "included"
        except CollectorError as exc:
            _audit_failure(reason, str(exc))
            raise BackupError(f"Fallo el volcado de la base de datos: {exc}") from exc

        if (AppConfig.get("backup_include_tls") or "1") == "1":
            components["tls"] = collect_tls(workdir)
        else:
            components["tls"] = "skipped: deshabilitado en configuración"

        if (AppConfig.get("backup_include_host") or "1") == "1":
            components["host"] = collect_host_state(workdir)
        else:
            components["host"] = "skipped: deshabilitado en configuración"

        # Cinturón y tirantes: el workdir jamás debe contener .env ni la clave.
        for forbidden in workdir.rglob(".env*"):
            forbidden.unlink()

        files = sorted(
            p for p in workdir.rglob("*") if p.is_file()
        )
        manifest = {
            "format_version": MANIFEST_FORMAT_VERSION,
            "app": "wardnode",
            "created_at": ts.isoformat(),
            "reason": reason,
            "db_engine": db_meta["engine"],
            "alembic_head": _current_alembic_head(),
            "pg_server_version": _pg_server_version(),
            "components": components,
            "checksums": {
                str(p.relative_to(workdir)): _sha256_file(p) for p in files
            },
        }
        (workdir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (workdir / "README-RESTORE.md").write_text(_README_RESTORE, encoding="utf-8")

        try:
            with pyzipper.AESZipFile(
                part_path, "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(password.encode())
                for p in sorted(workdir.rglob("*")):
                    if p.is_file():
                        zf.write(p, arcname=str(p.relative_to(workdir)))
            os.replace(part_path, final_path)
        except Exception as exc:
            part_path.unlink(missing_ok=True)
            _audit_failure(reason, f"empaquetado fallido: {type(exc).__name__}")
            raise BackupError("No se pudo escribir el zip del backup.") from exc

    try:
        retention = int(AppConfig.get("backup_retention") or 7)
    except (TypeError, ValueError):
        retention = 7
    removed = prune_backups(retention)

    size = final_path.stat().st_size
    log_audit(
        "backup.create", resource_type="backup", resource_name=name,
        detail={"size_bytes": size, "reason": reason,
                "components": components, "pruned": removed},
    )
    return BackupResult(path=final_path, size_bytes=size,
                        manifest=manifest, components=components)


def _audit_failure(reason: str, message: str) -> None:
    log_audit(
        "backup.create", resource_type="backup", severity="error",
        status="failure", detail={"reason": reason, "error": message[:500]},
    )


# ── Validación del zip (restore) ──────────────────────────────────────


def _entry_allowed(arcname: str) -> bool:
    if arcname in _ALLOWED_FILES:
        return True
    return any(
        arcname.startswith(prefix) and ".." not in arcname and not arcname.startswith("/")
        for prefix in _ALLOWED_PREFIXES
    )


def validate_backup_zip(zip_path: Path, password: str) -> dict:
    """Valida el zip SIN tocar nada. Devuelve el manifest + flags."""
    try:
        size = zip_path.stat().st_size
    except OSError as exc:
        raise RestoreValidationError("no se pudo leer el fichero") from exc
    if size > MAX_ZIP_BYTES:
        raise RestoreValidationError("el zip excede el tamaño máximo permitido (2 GB)")

    try:
        zf = pyzipper.AESZipFile(zip_path)
        zf.setpassword(password.encode())
        infos = zf.infolist()
    except Exception as exc:
        raise RestoreValidationError("zip corrupto o ilegible") from exc

    with zf:
        total_uncompressed = 0
        for info in infos:
            arcname = info.filename
            if arcname.endswith("/"):
                continue
            if not _entry_allowed(arcname):
                raise RestoreValidationError(f"entrada no permitida en el zip: {arcname[:80]}")
            total_uncompressed += info.file_size
            compressed = max(1, info.compress_size)
            if info.file_size / compressed > MAX_COMPRESSION_RATIO:
                raise RestoreValidationError("ratio de compresión sospechoso (posible zip bomb)")
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise RestoreValidationError("contenido descomprimido excede el límite (4 GB)")

        try:
            manifest_raw = zf.read("manifest.json")
        except KeyError as exc:
            raise RestoreValidationError("el zip no contiene manifest.json") from exc
        except RuntimeError as exc:
            # pyzipper lanza RuntimeError con contraseña incorrecta
            raise RestoreValidationError("contraseña incorrecta o zip corrupto") from exc

        try:
            manifest = json.loads(manifest_raw)
        except ValueError as exc:
            raise RestoreValidationError("manifest.json malformado") from exc

        if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
            raise RestoreValidationError(
                f"versión de formato no soportada: {manifest.get('format_version')!r}"
            )
        if manifest.get("app") != "wardnode":
            raise RestoreValidationError("el manifest no corresponde a un backup de WardNode")

        checksums = manifest.get("checksums") or {}
        for arcname, expected in checksums.items():
            if not _entry_allowed(arcname):
                raise RestoreValidationError(f"checksum de entrada no permitida: {arcname[:80]}")
            h = hashlib.sha256()
            try:
                with zf.open(arcname) as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
            except KeyError as exc:
                raise RestoreValidationError(f"falta la entrada {arcname[:80]}") from exc
            except RuntimeError as exc:
                raise RestoreValidationError("contraseña incorrecta o zip corrupto") from exc
            if h.hexdigest() != expected:
                raise RestoreValidationError(f"checksum inválido: {arcname[:80]}")

    flags = {"needs_upgrade": False, "pg_version_warning": None}
    dump_head = manifest.get("alembic_head")
    code_head, known = _code_revisions()
    if dump_head and known:
        if dump_head not in known:
            raise RestoreValidationError(
                "el backup proviene de una versión de WardNode más nueva que este "
                "código (migración desconocida). Actualiza WardNode primero."
            )
        if dump_head != code_head:
            flags["needs_upgrade"] = True

    dump_pg = manifest.get("pg_server_version") or ""
    local_pg = _pg_server_version() or ""
    try:
        if dump_pg and local_pg and int(dump_pg.split(".")[0]) > int(local_pg.split(".")[0]):
            flags["pg_version_warning"] = (
                f"el dump proviene de PostgreSQL {dump_pg} y el servidor local es "
                f"{local_pg}; pg_restore podría fallar"
            )
    except ValueError:
        pass

    return {"manifest": manifest, **flags}


# ── Restore ───────────────────────────────────────────────────────────


def restore_backup(zip_path: Path, password: str, *, skip_db: bool = False) -> dict:
    """Restaura la DB desde el zip. DESTRUCTIVO. Lanza BackupError en fallo."""
    result = validate_backup_zip(zip_path, password)
    manifest = result["manifest"]

    with tempfile.TemporaryDirectory(dir=backup_dir()) as tmp:
        workdir = Path(tmp)
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.setpassword(password.encode())
            for arcname in (manifest.get("checksums") or {}):
                dest = workdir / arcname  # arcname ya validado (whitelist, sin ..)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(arcname))

        if not skip_db:
            engine_name = db.engine.dialect.name
            dump_engine = manifest.get("db_engine")
            if engine_name == "postgresql":
                if dump_engine != "postgresql":
                    raise RestoreValidationError(
                        "el backup contiene una DB SQLite; no es restaurable en PostgreSQL"
                    )
                _restore_postgres(workdir / "db" / "wardnode.pgdump")
            else:
                if dump_engine != "sqlite":
                    raise RestoreValidationError(
                        "el backup contiene un dump PostgreSQL; no es restaurable en SQLite"
                    )
                _restore_sqlite(workdir / "db" / "wardnode.sqlite")

    upgraded = False
    if result["needs_upgrade"]:
        try:
            from flask_migrate import upgrade

            upgrade()
            upgraded = True
        except Exception as exc:
            log.error("backup: fallo aplicando migraciones post-restore: %s", exc)
            raise BackupError(
                "Restore aplicado pero las migraciones pendientes fallaron; "
                "ejecuta `flask db upgrade` manualmente."
            ) from exc

    configs_ok = True
    try:
        from app.proxy.services import render_nginx_configs

        render_nginx_configs()
    except Exception as exc:
        configs_ok = False
        log.warning("backup: no se regeneraron configs nginx post-restore: %s", exc)

    # Auditar DESPUÉS del restore para que el evento persista en la DB restaurada.
    log_audit(
        "backup.restore", resource_type="backup", resource_name=zip_path.name,
        severity="critical",
        detail={"created_at": manifest.get("created_at"),
                "alembic_head": manifest.get("alembic_head"),
                "migrations_applied": upgraded,
                "nginx_configs_regenerated": configs_ok},
    )
    return {"manifest": manifest, "migrations_applied": upgraded,
            "nginx_configs_regenerated": configs_ok}


def _restore_postgres(dump_path: Path) -> None:
    if not dump_path.is_file():
        raise RestoreValidationError("el zip no contiene db/wardnode.pgdump")

    uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    parts = urlsplit(uri)
    user = parts.username or "app"
    password = parts.password or ""
    dbname = (parts.path or "/app").lstrip("/")
    if not re.match(r"^[A-Za-z0-9_-]+$", dbname):
        raise BackupError("nombre de base de datos inválido en DATABASE_URL")

    import docker

    try:
        client = docker.from_env()
        container = client.containers.get(_db_container_name())
    except Exception as exc:
        raise BackupError(
            f"no se pudo acceder al contenedor de la DB ({type(exc).__name__})"
        ) from exc

    # Cerrar el pool propio y matar las conexiones de todos los workers; el
    # terminate corre desde la DB de mantenimiento `postgres`, no la objetivo.
    db.session.remove()
    db.engine.dispose()
    container.exec_run(
        ["psql", "-U", user, "-d", "postgres", "-c",
         f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
         f"WHERE datname = '{dbname}' AND pid <> pg_backend_pid()"],
        environment={"PGPASSWORD": password},
    )

    # Copiar el dump al contenedor (put_archive exige un tar).
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(dump_path, arcname="wardnode.pgdump")
    buf.seek(0)
    container.put_archive("/tmp", buf.read())

    try:
        exit_code, output = container.exec_run(
            ["pg_restore", "--clean", "--if-exists", "--no-owner",
             "-U", user, "-d", dbname, "/tmp/wardnode.pgdump"],
            environment={"PGPASSWORD": password},
            demux=True,
        )
        _stdout, stderr = output if isinstance(output, tuple) else (output, b"")
        if exit_code != 0:
            err = (stderr or b"").decode(errors="replace")[:2000]
            raise BackupError(f"pg_restore falló (exit {exit_code}): {err}")
    finally:
        container.exec_run(["rm", "-f", "/tmp/wardnode.pgdump"])


def _restore_sqlite(sqlite_path: Path) -> None:
    if not sqlite_path.is_file():
        raise RestoreValidationError("el zip no contiene db/wardnode.sqlite")
    uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    raw_path = uri.split("sqlite:///", 1)[-1]
    if raw_path in ("", ":memory:"):
        raise BackupError("la base SQLite en memoria no es restaurable")
    dest = Path(raw_path)
    if not dest.is_absolute():
        dest = Path(current_app.instance_path) / dest.name
    db.session.remove()
    db.engine.dispose()
    import shutil

    shutil.copy2(sqlite_path, dest)
