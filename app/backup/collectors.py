"""Colectores de componentes del backup.

Cada colector escribe sus archivos dentro del workdir y devuelve una nota
de estado para el manifest: "included" o "skipped: <motivo>". Solo el
colector de DB aborta el backup en fallo; TLS y host degradan con gracia.
"""

import gzip
import json
import logging
import os
import shutil
import tarfile
from pathlib import Path
from urllib.parse import urlsplit

from flask import current_app

log = logging.getLogger(__name__)

_STDERR_TRUNCATE = 2000


class CollectorError(Exception):
    """Fallo de un colector crítico (DB). Mensaje seguro, sin credenciales."""


def _db_container_name() -> str:
    return os.environ.get("WARDNODE_DB_CONTAINER", "wardnode-db")


def _proxy_container_name() -> str:
    return os.environ.get("WARDNODE_PROXY_CONTAINER", "wardnode-proxy")


def dump_database(workdir: Path) -> dict:
    """Vuelca la base de datos a workdir/db/.

    PostgreSQL → pg_dump -Fc vía Docker SDK (el contenedor console no trae
    pg_dump). SQLite (dev) → copia del fichero. Devuelve metadata para el
    manifest. Lanza CollectorError en fallo (componente crítico).
    """
    uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    out_dir = workdir / "db"
    out_dir.mkdir(parents=True, exist_ok=True)

    if uri.startswith("sqlite"):
        # sqlite:///ruta/relativa o sqlite:////ruta/absoluta
        raw_path = uri.split("sqlite:///", 1)[-1]
        if raw_path in ("", ":memory:"):
            raise CollectorError("la base SQLite en memoria no es respaldable")
        src = Path(raw_path)
        if not src.is_absolute():
            src = Path(current_app.instance_path) / src.name
        if not src.exists():
            raise CollectorError(f"fichero SQLite no encontrado: {src.name}")
        shutil.copy2(src, out_dir / "wardnode.sqlite")
        return {"engine": "sqlite", "file": "db/wardnode.sqlite"}

    parts = urlsplit(uri)
    user = parts.username or "app"
    password = parts.password or ""
    dbname = (parts.path or "/app").lstrip("/")

    import docker

    try:
        client = docker.from_env()
        container = client.containers.get(_db_container_name())
    except Exception as exc:
        raise CollectorError(
            f"no se pudo acceder al contenedor de la DB ({type(exc).__name__})"
        ) from exc

    # La contraseña viaja SOLO por env del exec, nunca por argv (visible en ps).
    exit_code, output = container.exec_run(
        ["pg_dump", "-Fc", "-U", user, "-d", dbname],
        environment={"PGPASSWORD": password},
        demux=True,
    )
    stdout, stderr = output if isinstance(output, tuple) else (output, b"")
    if exit_code != 0:
        err = (stderr or b"").decode(errors="replace")[:_STDERR_TRUNCATE]
        raise CollectorError(f"pg_dump falló (exit {exit_code}): {err}")
    if not stdout:
        raise CollectorError("pg_dump no produjo salida")

    (out_dir / "wardnode.pgdump").write_bytes(stdout)
    return {"engine": "postgresql", "file": "db/wardnode.pgdump"}


def collect_tls(workdir: Path) -> str:
    """Empaqueta /etc/letsencrypt como tls/letsencrypt.tar.gz.

    Primero intenta el mount read-only local; si no existe, fallback vía
    Docker SDK leyendo del contenedor proxy. Nunca aborta el backup.
    """
    out_dir = workdir / "tls"
    le_path = Path("/etc/letsencrypt")

    try:
        if le_path.is_dir() and any(le_path.iterdir()):
            out_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(out_dir / "letsencrypt.tar.gz", "w:gz") as tf:
                tf.add(le_path, arcname="letsencrypt")
            return "included"
    except PermissionError:
        log.warning("backup: sin permiso de lectura sobre /etc/letsencrypt local")
    except Exception as exc:
        log.warning("backup: fallo leyendo /etc/letsencrypt local: %s", type(exc).__name__)

    # Fallback: extraer del contenedor proxy (instalaciones sin el mount ro).
    try:
        import docker

        client = docker.from_env()
        container = client.containers.get(_proxy_container_name())
        stream, _stat = container.get_archive("/etc/letsencrypt")
        out_dir.mkdir(parents=True, exist_ok=True)
        with gzip.open(out_dir / "letsencrypt.tar.gz", "wb") as gz:
            for chunk in stream:
                gz.write(chunk)
        return "included"
    except Exception as exc:
        return f"skipped: letsencrypt no accesible ({type(exc).__name__})"


def collect_host_state(workdir: Path) -> str:
    """Exporta el estado WF del host (reglas UFW + puertos protegidos).

    Requiere el módulo WF activo y el agente respondiendo. Nunca aborta.
    """
    from app.models import AppConfig

    if AppConfig.get("module_wf_enabled") != "1":
        return "skipped: módulo WF inactivo"

    from app.modules.socket_client import send_command

    out_dir = workdir / "host"
    wrote_something = False

    try:
        resp = send_command("status")
        if resp.get("ok"):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "ufw-rules.txt").write_text(
                resp.get("output") or json.dumps(resp, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            wrote_something = True
        else:
            log.warning("backup: agente WF respondió error en status: %s", resp.get("error"))
    except Exception as exc:
        log.warning("backup: agente WF no accesible: %s", type(exc).__name__)

    protected = Path("/opt/wardnode/.protected_ports.json")
    try:
        if protected.exists():
            out_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(protected, out_dir / "protected_ports.json")
            wrote_something = True
    except Exception as exc:
        log.warning("backup: no se pudo copiar protected_ports.json: %s", type(exc).__name__)

    return "included" if wrote_something else "skipped: agente WF no accesible"
